# Structured audit event schema for logging
import os
import re
import time
import uuid
from datetime import datetime

# Model for audit log entry
from typing import Dict, Any, Literal, Optional
from pydantic import BaseModel, Field, field_validator

# Validation constants for Loki query parameters
MAX_LIMIT = 1000
MIN_LIMIT = 1
MAX_TIMESTAMP_NS = 2**63 - 1  # int64 max ns, ~2262-04-11 UTC
MIN_TIMESTAMP_NS = 0

LogCategory = Literal["consent_lifecycle", "system_processing", "grievance_rights"]
ActorType = Literal[
    "human_user", "end_user", "service_account", "scheduled_job", "system"
]

ATTRIBUTE_PREFIX = "attr_"
MAX_ATTRIBUTES = 100
MAX_ATTRIBUTE_KEY_LENGTH = 64
ATTRIBUTE_KEY_PATTERN = re.compile(r"[a-z][a-z0-9_]*")
EVENT_ID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def validate_event_id(value: Optional[str]) -> Optional[str]:
    if value is not None and not EVENT_ID_PATTERN.fullmatch(value):
        raise ValueError("event_id must be a lowercase canonical UUID string")
    return value


def new_event_id() -> str:
    unix_ms = time.time_ns() // 1_000_000
    random_bits = int.from_bytes(os.urandom(10), "big")
    rand_a = (random_bits >> 68) & 0xFFF
    rand_b = random_bits & ((1 << 62) - 1)
    value = (
        (unix_ms & ((1 << 48) - 1)) << 80
        | 0x7 << 76
        | rand_a << 64
        | 0b10 << 62
        | rand_b
    )
    return str(uuid.UUID(int=value))


class AuditEvent(BaseModel):
    organization_uuid: Optional[str] = None
    workspace_uuid: Optional[str] = None
    vrm_vendor_id: Optional[str] = None
    service_name: Optional[str] = None
    kb_id: Optional[str] = None
    action: Optional[str] = None
    crud: Optional[str] = None
    source_ip: Optional[str] = None
    actor_name: Optional[str] = None
    actor_uuid: Optional[str] = None
    resource_name: Optional[str] = None
    resource_uuid: Optional[str] = None
    resource_type: Optional[str] = None
    description: Optional[str] = None
    created: Optional[int] = None  # Unix epoch ns
    # Optionally add more fields as needed
    log_category: Optional[LogCategory] = None
    event_id: Optional[str] = None
    actor_type: Optional[ActorType] = None
    attributes: Optional[Dict[str, str]] = None

    _validate_event_id = field_validator("event_id")(validate_event_id)

    @field_validator("attributes")
    @classmethod
    def validate_attributes(
        cls, value: Optional[Dict[str, str]]
    ) -> Optional[Dict[str, str]]:
        if value is None:
            return value
        if len(value) > MAX_ATTRIBUTES:
            raise ValueError(f"attributes accepts at most {MAX_ATTRIBUTES} keys")
        for key in value:
            too_long = len(key) > MAX_ATTRIBUTE_KEY_LENGTH
            if too_long or not ATTRIBUTE_KEY_PATTERN.fullmatch(key):
                raise ValueError(
                    f"attribute key {key!r} must match {ATTRIBUTE_KEY_PATTERN.pattern} "
                    f"and be at most {MAX_ATTRIBUTE_KEY_LENGTH} characters"
                )
        return value


class SearchQuery(BaseModel):
    organization_uuid: Optional[str] = None  # label
    workspace_uuid: Optional[str] = None
    vrm_vendor_id: Optional[str] = None  # label
    service_name: Optional[str] = None  # label
    kb_id: Optional[str] = None  # label
    action: Optional[str] = None  # label
    actor_uuid: Optional[str] = None
    actor_name: Optional[str] = None  # label
    resource_uuid: Optional[str] = None
    resource_name: Optional[str] = None  # label
    resource_type: Optional[str] = None
    crud: Optional[str] = None  # label
    source_ip: Optional[str] = None
    description: Optional[str] = None
    log_category: Optional[LogCategory] = None
    event_id: Optional[str] = None
    actor_type: Optional[ActorType] = None

    _validate_event_id = field_validator("event_id")(validate_event_id)

    # Loki query_range parameters with validation
    # query: Optional[str] = None
    limit: Optional[int] = Field(default=100, ge=MIN_LIMIT, le=MAX_LIMIT)
    start: Optional[int] = Field(default=None, ge=MIN_TIMESTAMP_NS, le=MAX_TIMESTAMP_NS)
    end: Optional[int] = Field(default=None, ge=MIN_TIMESTAMP_NS, le=MAX_TIMESTAMP_NS)
    since: Optional[str] = None
    interval: Optional[str] = None
    direction: Optional[str] = None

    #  group_name: Optional[str] = None # what is this?

    # <module>_<field> format for custom fields
    # vrm_vendor_id: Optional[str] = None # label
    # vrm_vendor_domain_name: Optional[str] = None # label


# class AuditLogEntry(BaseModel):
# 	timestamp: int  # uint64
# 	trace_id: str   # hex string
# 	span_id: str    # hex string
# 	trace_flags: int
# 	severity_text: str
# 	severity_number: int
# 	attributes: Optional[Dict[str, Any]]
# 	resources: Optional[Dict[str, Any]]
# 	body: str

# class AuditLogEntry(BaseModel):
#     action: str
#     group: Group
#     crud: str
#     created: datetime
#     source_ip: str
#     actor: Actor
#     target: Target
#     description: str

# class Group(SecureSchema):
#     id: str
#     name: str


# class Actor(SecureSchema):
#     id: str
#     name: str


# class Target(SecureSchema):
#     id: str
#     name: str
#     type: str
#     fields: dict[str, str]
