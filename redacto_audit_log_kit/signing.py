"""Utilities for HMAC-SHA256 signing and verification of audit log events."""

import hashlib
import hmac
import json
from typing import Any, Dict


def _canonical_representation(event_dict: Dict[str, Any]) -> str:
    """Build a deterministic JSON string from the event dict, excluding event_signature."""
    canonical = {
        "timestamp": event_dict["timestamp"],
        "body": event_dict.get("body"),
        "labels": event_dict.get("labels", {}),
        "structured_metadata": {
            k: v
            for k, v in event_dict.get("structured_metadata", {}).items()
            if k != "event_signature"
        },
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"))


def compute_event_signature(event_dict: Dict[str, Any], signing_key: str) -> str:
    """Compute HMAC-SHA256 signature of an audit event.

    Args:
        event_dict: Dict with keys timestamp, body, labels, structured_metadata.
        signing_key: Secret key for HMAC.

    Returns:
        Hex-encoded HMAC-SHA256 signature (64 characters).
    """
    canonical_json = _canonical_representation(event_dict)
    return hmac.new(
        signing_key.encode("utf-8"),
        canonical_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_event_signature(
    event_dict: Dict[str, Any], expected_signature: str, signing_key: str
) -> bool:
    """Verify an event's HMAC signature.

    Args:
        event_dict: Dict with keys timestamp, body, labels, structured_metadata.
        expected_signature: The signature to verify against.
        signing_key: Secret key for HMAC.

    Returns:
        True if the signature is valid, False otherwise.
    """
    computed = compute_event_signature(event_dict, signing_key)
    return hmac.compare_digest(computed, expected_signature)
