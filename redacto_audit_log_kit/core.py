import datetime
import os
from abc import ABC, abstractmethod

import requests

from redacto_audit_log_kit.constants import PUSH_TIMEOUT_SECONDS, QUERY_TIMEOUT_SECONDS
from redacto_audit_log_kit.events import define_event, signing_key_from_env
from redacto_audit_log_kit.exceptions import (
    AuditKitConfigurationError,
    AuditKitConnectionError,
    AuditKitError,
    AuditKitEventProcessingError,
    AuditKitExternalServiceError,
    AuditKitInvalidDataError,
)
from redacto_audit_log_kit.helpers import logql_string, unescape_value
from redacto_audit_log_kit.schema import (
    ATTRIBUTE_PREFIX,
    DEFAULT_LIMIT,
    LABEL_FIELDS,
    NON_LOGQL_QUERY_PARAMS,
    OPTIONAL_LABEL_FIELDS,
    PIPELINE_FILTER_FIELDS,
    AuditEvent,
    AuditPage,
    AuditRecord,
    SearchQuery,
)


class AuditAdapter(ABC):
    name: str

    @abstractmethod
    def define_event(self, audit_log_entry: AuditEvent) -> dict:
        raise NotImplementedError

    @abstractmethod
    def report_event(self, defined_event_dict: dict) -> dict:
        raise NotImplementedError

    @abstractmethod
    def log(self, audit_log_entry: AuditEvent) -> dict:
        raise NotImplementedError

    @abstractmethod
    def generate_search_query(self, search_query: SearchQuery) -> dict:
        raise NotImplementedError

    @abstractmethod
    def get_events(self, search_query: SearchQuery) -> dict:
        raise NotImplementedError

    @abstractmethod
    def get_page(self, search_query: SearchQuery) -> AuditPage:
        raise NotImplementedError


class LokiProtocolAdapter(AuditAdapter):
    """
    Speaks Loki's push and query_range API, which both Loki and audit-server serve.
    Subclasses declare only what differs between the stores.
    """

    name = None
    base_url_env = None
    store = None
    permanent_statuses = frozenset({400, 401, 403, 413, 415})
    error_hints = {}

    label_fields = LABEL_FIELDS
    optional_label_fields = OPTIONAL_LABEL_FIELDS
    pipeline_filter_fields = PIPELINE_FILTER_FIELDS
    non_logql_query_params = NON_LOGQL_QUERY_PARAMS

    def __init__(self):
        if not (self.name and self.base_url_env and self.store):
            raise TypeError(f"{type(self).__name__} must set name, base_url_env and store")
        self.signing_key = signing_key_from_env()

    def base_url(self) -> str:
        base_url = os.getenv(self.base_url_env)
        if not base_url:
            raise AuditKitConfigurationError(f"{self.base_url_env} is not set.")
        return base_url.rstrip("/")

    def metadata_is_escaped(self, timestamp_ns: int) -> bool:
        return False

    def _raise_for_status(self, response, ok_statuses):
        if response.status_code in ok_statuses:
            return
        message = f"{self.store} returned: {response.text}"
        hint = self.error_hints.get(response.status_code)
        if hint:
            message += f" ({hint})"
        raise AuditKitExternalServiceError(
            response.status_code,
            message,
            permanent=response.status_code in self.permanent_statuses,
        )

    def define_event(self, audit_log_entry: AuditEvent):
        return define_event(audit_log_entry, self.signing_key)

    def report_event(self, defined_event_dict: dict):
        """
        Sends an event built by define_event to the store.
        Raises AuditKitConfigurationError, AuditKitConnectionError, AuditKitExternalServiceError, or AuditKitEventProcessingError.
        """
        try:
            push_events_endpoint = self.base_url() + "/loki/api/v1/push"

            headers = {
                "Content-Type": "application/json",
            }

            ts = str(defined_event_dict["timestamp"])
            msg = defined_event_dict["body"]
            labels = defined_event_dict.get("labels", {})
            structured_meta_data = {
                k: str(v)
                for k, v in defined_event_dict.get("structured_metadata", {}).items()
            }
            streams = [{"stream": labels, "values": [[ts, msg, structured_meta_data]]}]
            payload = {"streams": streams}
            response = requests.post(
                push_events_endpoint,
                json=payload,
                headers=headers,
                timeout=PUSH_TIMEOUT_SECONDS,
            )
            self._raise_for_status(response, (200, 204))

            return {
                "status": "success",
                "status_code": response.status_code,
                "message": "Event reported successfully",
            }

        except AuditKitError:
            raise
        except requests.exceptions.RequestException as e:
            raise AuditKitConnectionError(f"report_event network error: {e}")
        except (KeyError, ValueError, TypeError) as e:
            raise AuditKitInvalidDataError(f"report_event failed: {e}")
        except Exception as e:
            raise AuditKitEventProcessingError(f"report_event unexpected error: {e}")

    def log(self, audit_log_entry: AuditEvent):
        """
        Convenience method that combines define_event() and report_event().
        Raises AuditKitEventProcessingError on error.
        """
        try:
            defined_event_dict = self.define_event(audit_log_entry)
            return self.report_event(defined_event_dict)
        except AuditKitError:
            raise
        except Exception as e:
            raise AuditKitEventProcessingError(f"log unexpected error: {e}")

    def _generate_logql_query(self, search_query: SearchQuery):
        query_dict = search_query.model_dump(exclude_none=True)
        label_filters = []
        pipeline_filters = []

        for field in self.label_fields | self.optional_label_fields:
            if field in query_dict:
                value = query_dict.pop(field)
                label_filters.append(f"{field}={logql_string(value)}")

        if label_filters:
            label_selector = "{" + ", ".join(label_filters) + "}"
        else:
            label_selector = "{}"

        for field in self.pipeline_filter_fields:
            if field in query_dict:
                value = query_dict[field]
                pipeline_filters.append(f"{field}={logql_string(value)}")

        if pipeline_filters:
            pipeline = " | " + " | ".join(pipeline_filters)
        else:
            pipeline = ""

        return label_selector + pipeline

    def generate_search_query(
        self,
        search_query: SearchQuery,
    ):
        """
        Constructs query_range parameters as a dict from SearchQuery fields.
        Validates/converts time fields to nanoseconds.
        Raises AuditKitEventProcessingError on error.
        """
        try:
            params = {}
            params["query"] = self._generate_logql_query(search_query)

            for field in self.non_logql_query_params:
                value = getattr(search_query, field, None)
                if value is not None:
                    if field in ("start", "end"):
                        if isinstance(value, datetime.datetime):
                            params[field] = int(value.timestamp() * 1_000_000_000)
                        elif isinstance(value, (int, float)):
                            if value > 1e12:
                                params[field] = int(value)
                            else:
                                params[field] = int(float(value) * 1_000_000_000)
                        else:
                            raise AuditKitInvalidDataError(
                                f"{field} has unsupported type: {type(value)}"
                            )
                    else:
                        params[field] = value

            return params

        except AuditKitError:
            raise
        except Exception as e:
            raise AuditKitEventProcessingError(
                f"generate_search_query unexpected error: {e}"
            )

    def get_events(
        self,
        # TODO: RADHIKA here we need to take in the page size too
        search_query: SearchQuery,
    ):
        """
        Queries the store's /loki/api/v1/query_range endpoint with generated params.
        Returns the JSON response or raises an error.
        """
        try:
            params = self.generate_search_query(search_query)
            get_events_endpoint = self.base_url() + "/loki/api/v1/query_range"

            headers = {
                "Accept": "application/json",
            }
            response = requests.get(
                get_events_endpoint,
                headers=headers,
                params=params,
                timeout=QUERY_TIMEOUT_SECONDS,
            )
            self._raise_for_status(response, (200,))
            return response.json()

        except AuditKitError:
            raise
        except requests.exceptions.RequestException as e:
            raise AuditKitConnectionError(f"get_events network error: {e}")
        except Exception as e:
            raise AuditKitEventProcessingError(f"get_events unexpected error: {e}")

    def get_page(self, search_query: SearchQuery) -> AuditPage:
        """
        Returns up to search_query.limit events, newest first. Pass next_page_token
        back as page_token for the next page; it is opaque, never parse it.
        """
        limit = search_query.limit or DEFAULT_LIMIT
        update = {"limit": limit + 1}
        if search_query.page_token is not None:
            try:
                update["end"] = int(search_query.page_token)
            except ValueError:
                raise AuditKitInvalidDataError("page_token was not issued by get_page")
        response = self.get_events(search_query.model_copy(update=update))

        records = []
        label_keys = self.label_fields | self.optional_label_fields
        for stream in response.get("data", {}).get("result", []):
            raw = stream.get("stream", {})
            unescaped = {k: v if k in label_keys else unescape_value(v) for k, v in raw.items()}
            for value in stream.get("values", []):
                timestamp = int(value[0])
                fields = unescaped if self.metadata_is_escaped(timestamp) else raw
                records.append(
                    AuditRecord(
                        timestamp=timestamp,
                        message=value[1],
                        metadata={
                            k: v for k, v in fields.items() if not k.startswith(ATTRIBUTE_PREFIX)
                        },
                        attributes={
                            k[len(ATTRIBUTE_PREFIX) :]: v
                            for k, v in fields.items()
                            if k.startswith(ATTRIBUTE_PREFIX)
                        },
                    )
                )
        records.sort(
            key=lambda r: (r.timestamp, r.metadata.get("event_signature", r.message)),
            reverse=True,
        )

        next_page_token = str(records[limit - 1].timestamp) if len(records) > limit else None
        return AuditPage(events=records[:limit], next_page_token=next_page_token)
