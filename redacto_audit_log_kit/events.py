import datetime
import os
import time

from redacto_audit_log_kit.constants import AUDIT_LOG_SIGNING_KEY_ENV
from redacto_audit_log_kit.exceptions import (
    AuditKitConfigurationError,
    AuditKitError,
    AuditKitEventProcessingError,
    AuditKitInvalidDataError,
)
from redacto_audit_log_kit.schema import (
    ATTRIBUTE_PREFIX,
    LABEL_FIELDS,
    OPTIONAL_LABEL_FIELDS,
    AuditEvent,
)
from redacto_audit_log_kit.signing import compute_event_signature


def signing_key_from_env() -> str:
    signing_key = os.environ.get(AUDIT_LOG_SIGNING_KEY_ENV)
    if not signing_key:
        raise AuditKitConfigurationError(
            f"{AUDIT_LOG_SIGNING_KEY_ENV} environment variable is required"
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
