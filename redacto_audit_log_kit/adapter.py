# TODO: check the float check for unix epoch timestamp inputs
# TODO: can we run a loki instance to run test cases?

import os
from pprint import pprint
from typing import Optional
from urllib.parse import urlsplit

# from loguru import logger
import requests
import time
import datetime
import json

from abc import ABC, abstractmethod
from django.conf import settings

from redacto_audit_log_kit.schema import (
    ATTRIBUTE_PREFIX,
    DEFAULT_LIMIT,
    AuditPage,
    AuditRecord,
    SearchQuery,
    AuditEvent,
)
from redacto_audit_log_kit.signing import compute_event_signature
from redacto_audit_log_kit.exceptions import (
    AuditKitError,
    AuditKitConfigurationError,
    AuditKitConnectionError,
    AuditKitExternalServiceError,
    AuditKitInvalidDataError,
    AuditKitEventProcessingError,
)

# Matches the Go ledger's Loki client and audit-server's write timeout; a hung backend
# otherwise holds the Dramatiq worker until its time limit kills it.
PUSH_TIMEOUT_SECONDS = 10
# Loki's HTTP server cuts a response at its default 30s write timeout, so a long-range
# query_range can take that long and waiting longer gains nothing.
QUERY_TIMEOUT_SECONDS = 30

LOKI_BASE_URL_ENV = "LOKI_BASE_URL"
AUDIT_SERVER_BASE_URL_ENV = "AUDIT_SERVER_BASE_URL"
LOKI_METADATA_ESCAPED_BEFORE_NS_ENV = "LOKI_METADATA_ESCAPED_BEFORE_NS"

LABEL_FIELDS = frozenset(
    {
        "organization_uuid",
        "workspace_uuid",
        "vrm_vendor_id",
        "service_name",
        "kb_id",
    }
)

OPTIONAL_LABEL_FIELDS = frozenset(
    {
        "log_category",
    }
)

PIPELINE_FILTER_FIELDS = frozenset(
    {
        "source_ip",
        "resource_type",
        "description",
        "action",
        "crud",
        "actor_name",
        "actor_uuid",
        "resource_name",
        "resource_uuid",
        "event_id",
        "actor_type",
    }
)

NON_LOGQL_QUERY_PARAMS = frozenset(
    {
        "limit",
        "start",
        "end",
        "since",
        "interval",
        "direction",
    }
)


def _logql_string(value) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def signing_key_from_env() -> str:
    signing_key = os.environ.get("AUDIT_LOG_SIGNING_KEY")
    if not signing_key:
        raise AuditKitConfigurationError(
            "AUDIT_LOG_SIGNING_KEY environment variable is required"
        )
    return signing_key


def define_event(audit_log_entry: AuditEvent, signing_key: str) -> dict:
    """
    Builds the signed event every store is sent, so all of them get the same
    timestamp and signature.
    """
    try:
        if hasattr(audit_log_entry, "created"):
            created = audit_log_entry.created
            if isinstance(created, datetime.datetime):
                unix_epoch_ns = int(created.timestamp() * 1_000_000_000)
            elif isinstance(created, (int, float)):
                if created > 1e12:  # assume already in ns
                    unix_epoch_ns = int(created)
                else:  # assume seconds
                    unix_epoch_ns = int(float(created) * 1_000_000_000)
            else:
                unix_epoch_ns = int(time.time_ns())
        else:
            unix_epoch_ns = int(time.time_ns())

        structured_metadata = {}
        labels = {}
        for field, value in audit_log_entry.model_dump().items():
            if field in LABEL_FIELDS:
                labels[field] = value
            elif field in OPTIONAL_LABEL_FIELDS:
                if value is not None:
                    labels[field] = value
            elif field == "attributes":
                for key, attribute_value in (value or {}).items():
                    structured_metadata[ATTRIBUTE_PREFIX + key] = attribute_value
            # event_signature is excluded because it's computed internally by the
            # adapter and not part of the AuditEvent schema - callers never provide it
            elif field not in {"description", "created", "event_signature"}:
                if value is not None:
                    structured_metadata[field] = value

        event_dict = {
            "timestamp": unix_epoch_ns,
            "body": audit_log_entry.description,
            "labels": labels,
            "structured_metadata": structured_metadata,
        }

        event_dict["structured_metadata"]["event_signature"] = compute_event_signature(
            event_dict, signing_key
        )

        return event_dict

    except AuditKitError:
        raise
    except (AttributeError, ValueError, TypeError) as e:
        raise AuditKitInvalidDataError(f"define_event unexpected error: {e}")
    except Exception as e:
        raise AuditKitEventProcessingError(f"define_event unexpected error: {e}")


def _unescape(value):
    if not isinstance(value, str) or "\\" not in value:
        return value
    try:
        return json.loads(f'"{value}"')
    except ValueError:
        return value


class AuditAdapter(ABC):
    @abstractmethod
    def report_event(self, event):
        raise NotImplementedError

    @abstractmethod
    def define_event(self, event):
        raise NotImplementedError

    @abstractmethod
    def get_events(self, last, before):
        raise NotImplementedError

    @abstractmethod
    def log(self, message):
        raise NotImplementedError

    @abstractmethod
    def generate_search_query(self, criteria):
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

    def _generate_query(self, search_query: SearchQuery):
        query_dict = search_query.model_dump(exclude_none=True)
        label_filters = []
        pipeline_filters = []

        for field in self.label_fields | self.optional_label_fields:
            if field in query_dict:
                value = query_dict.pop(field)
                label_filters.append(f"{field}={_logql_string(value)}")

        if label_filters:
            label_selector = "{" + ", ".join(label_filters) + "}"
        else:
            label_selector = "{}"

        for field in self.pipeline_filter_fields:
            if field in query_dict:
                value = query_dict[field]
                pipeline_filters.append(f"{field}={_logql_string(value)}")

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
            params["query"] = self._generate_query(search_query)

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
            unescaped = {k: v if k in label_keys else _unescape(v) for k, v in raw.items()}
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
        records.sort(key=lambda r: r.timestamp, reverse=True)

        next_page_token = str(records[limit - 1].timestamp) if len(records) > limit else None
        return AuditPage(events=records[:limit], next_page_token=next_page_token)


class GrafanaLokiAdapter(LokiProtocolAdapter):
    name = "loki"
    base_url_env = LOKI_BASE_URL_ENV
    store = "Loki"

    def metadata_is_escaped(self, timestamp_ns: int) -> bool:
        cutover = os.getenv(LOKI_METADATA_ESCAPED_BEFORE_NS_ENV)
        return not cutover or timestamp_ns < int(cutover)

    def _generate_logql_query(self, search_query: SearchQuery):
        return self._generate_query(search_query)


class AuditServerAdapter(LokiProtocolAdapter):
    """
    audit-server serves Loki's API under its /audit base path. AUDIT_SERVER_BASE_URL
    carries the service's client credentials as userinfo, e.g.
    http://<client-id>:<client-secret>@audit-server:8080/audit; requests sends them
    as HTTP Basic auth.
    """

    name = "audit_server"
    base_url_env = AUDIT_SERVER_BASE_URL_ENV
    store = "audit-server"
    error_hints = {
        401: f"the credentials in {AUDIT_SERVER_BASE_URL_ENV} were rejected",
        403: "this client may not use this service_name; add it to its AUDIT_CLIENTS entry",
    }

    def __init__(self):
        super().__init__()
        url = urlsplit(self.base_url())
        if not (url.username and url.password):
            raise AuditKitConfigurationError(
                f"{AUDIT_SERVER_BASE_URL_ENV} must carry the client credentials, "
                "http://<client-id>:<client-secret>@<host>/audit"
            )


# SIGNOZ_INGESTION_KEY = settings.SIGNOZ_INGESTION_KEY
# SIGNOZ_BASE_URL = settings.SIGNOZ_BASE_URL


# class SignozAdapter(ExternalLibAdapter):
#     # def __init__(self):
#     #     external_lib_instance = SignozAdapter()
#     #     super().__init__(external_lib_instance)

#     def report_event(self, audit_log_entry: list[AuditLogEntry]):
#         # region = os.getenv('SIGNOZ_REGION', 'in')
#         ingestion_key = os.getenv('SIGNOZ_INGESTION_KEY', 'EYT0xgxj1ltwaEsJxOCD74MbSJa3kWhgbfJNlDOASn8=')
#         base_url = "http://127.0.0.1:8082/"
#         url = f"{base_url}"

#         headers = {
#             "Content-Type": "application/json",
#             "signoz-ingestion-key": ingestion_key
#         }
#         payload = [dict(entry) for entry in audit_log_entry]
#         try:
#             response = requests.post(
#                 url,
#                 json=payload,
#                 headers=headers,
#                 )
#             if response.status_code not in [200, 201]:
#                 logger.error(f"Retraced error: {response.status_code}, {response.text}")
#                 raise Exception(
#                     f"Retraced returned {response.status_code}: {response.text}"
#                 )
#             return response
#         except requests.exceptions.RequestException as e:
#             logger.exception("Network error while sending audit event")
#             raise Exception(f"Failed to send event to SigNoz: {e}")


#     def generate_search_query(
#         self,
#         start,
#         end,
#         filters=None,
#         order_keys=[("timestamp", "desc"), ("id", "desc")],
#         offset=0,
#         limit=100,
#     ):

#         filter_expr = ""
#         if filters:
#             filter_expr = " AND ".join(
#                 f"{k} = '{v}'" for k, v in filters.items()
#             )
#         # Build order clause
#         order = []
#         for key_name, direction in order_keys:
#             order.append({
#                 "key": {"name": key_name},
#                 "direction": direction
#             })
#         # Construct query dict
#         query = {
#             "start": start,
#             "end": end,
#             "requestType": "raw",
#             "compositeQuery": {
#                 "queries": [
#                     {
#                         "type": "builder_query",
#                         "spec": {
#                             "name": "A",
#                             "signal": "logs",
#                             "filter": {"expression": filter_expr},
#                             "order": order,
#                             "offset": offset,
#                             "limit": limit,
#                         }
#                     }
#                 ]
#             }
#         }
#         return query


# #TODO: remove this function after testing
# def call_log():
#     example = AuditLogEntry(
#         timestamp=int(time.time_ns()),               # ns, current time
#         trace_id="000000000000000018c51935df0b93b9",
#         span_id="18c51935df0b93b9",
#         trace_flags=1,
#         severity_text="info",
#         severity_number=9,
#         attributes={"method": "GET", "path": "/api/users"},
#         resources={"service.name": "vendor-server", "deployment.environment": "local"},
#         body="This is a log line rd2"
#     )
#     input = [example]
#     obj = SignozAdapter()
#     return obj.log(input)
