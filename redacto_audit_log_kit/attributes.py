import json
import re
from typing import Any, Dict, List, Mapping, Optional

from redacto_audit_log_kit.schema import (
    ATTRIBUTE_PREFIX,
    MAX_ATTRIBUTE_KEY_LENGTH,
    MAX_ATTRIBUTE_VALUE_BYTES,
    MAX_ATTRIBUTES,
    MAX_ATTRIBUTES_BYTES,
)

MAX_DROPPED_REPORT_BYTES = 1024
DROPPED_ATTRIBUTES_KEY = "dropped_attributes"
INVALID_KEY_CHARACTERS = re.compile(r"[^a-z0-9_]")


def attribute_key(key: Any) -> str:
    normalized = INVALID_KEY_CHARACTERS.sub("_", str(key).lower())
    if not normalized[:1].isalpha():
        normalized = f"k_{normalized}"
    return normalized[:MAX_ATTRIBUTE_KEY_LENGTH]


def attribute_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(
            value,
            default=str,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    return str(value)


def truncate_attribute_value(value: str) -> str:
    encoded = value.encode()
    if len(encoded) <= MAX_ATTRIBUTE_VALUE_BYTES:
        return value
    marker = f"...[truncated {len(encoded)} bytes]"
    cut = MAX_ATTRIBUTE_VALUE_BYTES - len(marker)
    return encoded[:cut].decode(errors="ignore") + marker


def dropped_report(dropped: List[str]) -> str:
    report = ",".join(dropped)
    room = MAX_DROPPED_REPORT_BYTES - len(ATTRIBUTE_PREFIX) - len(DROPPED_ATTRIBUTES_KEY)
    if len(report.encode()) <= room:
        return report
    return f"{len(dropped)} attributes"


def build_attributes(extra_fields: Optional[Mapping[Any, Any]]) -> Dict[str, str]:
    candidates: Dict[str, str] = {}
    for raw_key in sorted(extra_fields or {}, key=str):
        value = extra_fields[raw_key]
        if value is None:
            continue
        candidates[attribute_key(raw_key)] = truncate_attribute_value(
            attribute_value(value)
        )
    attributes: Dict[str, str] = {}
    dropped: List[str] = []
    used = 0
    for key in sorted(candidates):
        value = candidates[key]
        size = len(ATTRIBUTE_PREFIX) + len(key) + len(value.encode())
        if (
            used + size > MAX_ATTRIBUTES_BYTES - MAX_DROPPED_REPORT_BYTES
            or len(attributes) >= MAX_ATTRIBUTES - 1
        ):
            dropped.append(key)
            continue
        attributes[key] = value
        used += size
    if dropped:
        attributes[DROPPED_ATTRIBUTES_KEY] = dropped_report(dropped)
    return attributes
