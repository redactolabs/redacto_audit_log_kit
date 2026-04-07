# TODO: check the float check for unix epoch timestamp inputs
# TODO: can we run a loki instance to run test cases?

import os
from pprint import pprint
from typing import Optional

# from loguru import logger
import requests
import time
import datetime
import json

from abc import ABC, abstractmethod
from django.conf import settings

from redacto_audit_log_kit.schema import SearchQuery, AuditEvent
from redacto_audit_log_kit.signing import compute_event_signature
from redacto_audit_log_kit.exceptions import (
    AuditKitConfigurationError,
    AuditKitConnectionError,
    AuditKitExternalServiceError,
    AuditKitInvalidDataError,
    AuditKitEventProcessingError,
)


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


class GrafanaLokiAdapter(AuditAdapter):
    label_fields = {
        "organization_uuid",
        "workspace_uuid",
        "vrm_vendor_id",
        "service_name",
        "kb_id",
    }

    pipeline_filter_fields = {
        "source_ip",
        "resource_type",
        "description",
        "action",
        "crud",
        "actor_name",
        "actor_uuid",
        "resource_name",
        "resource_uuid",
    }

    non_logql_query_params = {
        "limit",
        "start",
        "end",
        "since",
        "interval",
        "direction",
    }

    def __init__(self):
        self.signing_key = os.environ.get("AUDIT_LOG_SIGNING_KEY")
        if not self.signing_key:
            raise AuditKitConfigurationError(
                "AUDIT_LOG_SIGNING_KEY environment variable is required"
            )

    def define_event(self, audit_log_entry: AuditEvent):

        try:
            # compute timestamp in ns
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

            # extract structured_metadata (all non-label, non-created, non-description fields)
            structured_metadata = {}
            labels = {}
            for field, value in audit_log_entry.model_dump().items():
                if field in self.label_fields:
                    labels[field] = value
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

            event_dict["structured_metadata"]["event_signature"] = (
                compute_event_signature(event_dict, self.signing_key)
            )

            return event_dict

        except (
            AuditKitConfigurationError,
            AuditKitConnectionError,
            AuditKitExternalServiceError,
            AuditKitInvalidDataError,
            AuditKitEventProcessingError,
        ):
            raise  # Re-raise custom exceptions as-is
        except (AttributeError, ValueError, TypeError) as e:
            raise AuditKitInvalidDataError(f"define_event unexpected error: {e}")
        except Exception as e:
            raise AuditKitEventProcessingError(f"define_event unexpected error: {e}")

    def report_event(self, defined_event_dict: dict):
        """
        Accepts an AuditEvent, extracts timestamp and description, and sends to Loki.
        Raises AuditKitConfigurationError, AuditKitConnectionError, AuditKitExternalServiceError, or AuditKitEventProcessingError.
        """
        try:
            # loki_base_url = os.getenv('LOKI_BASE_URL', 'http://localhost:3100')
            # loki_base_url = os.getenv('LOKI_BASE_URL', 'http://host.docker.internal:3100')
            loki_base_url = os.getenv("LOKI_BASE_URL")
            if not loki_base_url:
                raise AuditKitConfigurationError("LOKI_BASE_URL is not set.")
            push_events_endpoint = loki_base_url + "/loki/api/v1/push"

            headers = {
                "Content-Type": "application/json",
            }

            ts = str(defined_event_dict["timestamp"])
            msg = defined_event_dict["body"]
            structured_meta_data = defined_event_dict.get("structured_metadata", {})
            labels = defined_event_dict.get("labels", {})
            structured_meta_data = {
                k: str(v)
                for k, v in defined_event_dict.get("structured_metadata", {}).items()
            }
            streams = [{"stream": labels, "values": [[ts, msg, structured_meta_data]]}]
            payload = {"streams": streams}
            # pprint(payload)
            response = requests.post(
                push_events_endpoint, json=payload, headers=headers
            )
            if response.status_code not in [200, 204]:
                # logger.error(f"Loki error: {response.status_code}, {response.text}")
                raise AuditKitExternalServiceError(
                    response.status_code, f"Loki returned: {response.text}"
                )

            return {
                "status": "success",
                "status_code": response.status_code,
                "message": "Event reported successfully",
            }

        except (
            AuditKitConfigurationError,
            AuditKitConnectionError,
            AuditKitExternalServiceError,
            AuditKitInvalidDataError,
            AuditKitEventProcessingError,
        ):
            raise  # Re-raise custom exceptions as-is
        except requests.exceptions.RequestException as e:
            raise AuditKitConnectionError(f"report_event network error: {e}")
        except (KeyError, ValueError, TypeError) as e:
            raise AuditKitInvalidDataError(f"report_event failed: {e}")
        except Exception as e:
            raise AuditKitEventProcessingError(f"report_event unexpected error: {e}")

    def log(self, audit_log_entry: AuditEvent):
        """
        Processes an audit log entry and sends it to Loki.
        This is a convenience method that combines define_event() and report_event().
        Raises AuditKitEventProcessingError on error.
        """
        try:
            defined_event_dict = self.define_event(audit_log_entry)
            return self.report_event(defined_event_dict)
        except (
            AuditKitConfigurationError,
            AuditKitConnectionError,
            AuditKitExternalServiceError,
            AuditKitInvalidDataError,
            AuditKitEventProcessingError,
        ):
            raise  # Re-raise custom exceptions as-is
        except Exception as e:
            # logger.exception(f"Failed to log audit event: {e}")
            raise AuditKitEventProcessingError(f"log unexpected error: {e}")

    def _generate_logql_query(self, search_query: SearchQuery):
        # Convert input to dictionary, ignoring None values
        query_dict = search_query.model_dump(exclude_none=True)
        label_filters = []
        pipeline_filters = []

        # Build label selector from label_fields
        for field in self.label_fields:
            if field in query_dict:
                value = query_dict.pop(field)
                label_filters.append(f'{field}="{value}"')

        # Create label selector string
        if label_filters:
            label_selector = "{" + ", ".join(label_filters) + "}"
        else:
            label_selector = "{}"

        # Build pipeline filters from pipeline_filter_fields
        for field in self.pipeline_filter_fields:
            if field in query_dict:
                value = query_dict[field]
                pipeline_filters.append(f'{field}="{value}"')

        # Construct pipeline string
        if pipeline_filters:
            pipeline = " | " + " | ".join(pipeline_filters)
        else:
            pipeline = ""

        # Combine for final LogQL query
        logql_query = label_selector + pipeline
        return logql_query

    def generate_search_query(
        self,
        search_query: SearchQuery,
    ):
        """
        Efficiently constructs Loki query_range parameters as a dict from SearchQuery fields.
        Validates/converts time fields to Loki-compatible formats.
        Returns: dict of query params for Loki API.
        Raises AuditKitEventProcessingError on error.
        """
        try:
            params = {}
            # Always use generated LogQL query
            params["query"] = self._generate_logql_query(search_query)

            for field in self.non_logql_query_params:
                value = getattr(search_query, field, None)
                if value is not None:
                    # Special handling for time fields
                    if field in ("start", "end"):
                        if isinstance(value, datetime.datetime):
                            params[field] = int(value.timestamp() * 1_000_000_000)
                        elif isinstance(value, (int, float)):
                            # If already in ns (13+ digits), use as is, else convert from seconds
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
            #  # If caller didn't set start/end, default to a sane window
            # if 'start' not in params or 'end' not in params:
            #     now = datetime.datetime.now(datetime.timezone.utc)
            #     start_dt = now - datetime.timedelta(hours=2)
            #     params.setdefault('end',   int(now.timestamp()      * 1_000_000_000))
            #     params.setdefault('start', int(start_dt.timestamp() * 1_000_000_000))

            return params

        except (
            AuditKitConfigurationError,
            AuditKitConnectionError,
            AuditKitExternalServiceError,
            AuditKitInvalidDataError,
            AuditKitEventProcessingError,
        ):
            raise  # Re-raise custom exceptions as-is
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
        Queries Loki's /loki/api/v1/query_range endpoint with generated params.
        Returns the JSON response or raises an error.
        """
        try:
            params = self.generate_search_query(search_query)

            # loki_base_url = os.getenv('LOKI_BASE_URL', 'http://host.docker.internal:3100')
            loki_base_url = os.getenv("LOKI_BASE_URL")
            if not loki_base_url:
                raise AuditKitConfigurationError("LOKI_BASE_URL is not set.")
            get_events_endpoint = loki_base_url + "/loki/api/v1/query_range"

            print(f"{get_events_endpoint=} | {params=}")

            headers = {
                "Accept": "application/json",
            }
            response = requests.get(get_events_endpoint, headers=headers, params=params)
            if response.status_code != 200:
                raise AuditKitExternalServiceError(
                    response.status_code, f"Loki returned: {response.text}"
                )
            return response.json()

        except (
            AuditKitConfigurationError,
            AuditKitConnectionError,
            AuditKitExternalServiceError,
            AuditKitInvalidDataError,
            AuditKitEventProcessingError,
        ):
            raise  # Re-raise custom exceptions as-is
        except requests.exceptions.RequestException as e:
            raise AuditKitConnectionError(f"get_events network error: {e}")
        except Exception as e:
            raise AuditKitEventProcessingError(f"get_events unexpected error: {e}")


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
