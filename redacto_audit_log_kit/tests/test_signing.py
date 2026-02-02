import unittest

from redacto_audit_log_kit.signing import (
    compute_event_signature,
    verify_event_signature,
    _canonical_representation,
)


class TestSigning(unittest.TestCase):
    def setUp(self):
        self.key = "test-secret-key"
        self.event = {
            "timestamp": 1706000000000000000,
            "body": "Test audit log entry",
            "labels": {
                "organization_uuid": "org-123",
                "service_name": "test-service",
            },
            "structured_metadata": {
                "action": "create",
                "crud": "c",
                "source_ip": "127.0.0.1",
                "actor_name": "Test Actor",
            },
        }

    def test_deterministic(self):
        sig1 = compute_event_signature(self.event, self.key)
        sig2 = compute_event_signature(self.event, self.key)
        self.assertEqual(sig1, sig2)
        self.assertEqual(len(sig1), 64)

    def test_different_key_different_signature(self):
        sig1 = compute_event_signature(self.event, "key-a")
        sig2 = compute_event_signature(self.event, "key-b")
        self.assertNotEqual(sig1, sig2)

    def test_different_content_different_signature(self):
        sig1 = compute_event_signature(self.event, self.key)
        modified = {**self.event, "body": "Different message"}
        sig2 = compute_event_signature(modified, self.key)
        self.assertNotEqual(sig1, sig2)

    def test_event_signature_excluded_from_computation(self):
        event_with_sig = {
            **self.event,
            "structured_metadata": {
                **self.event["structured_metadata"],
                "event_signature": "dummy",
            },
        }
        sig1 = compute_event_signature(self.event, self.key)
        sig2 = compute_event_signature(event_with_sig, self.key)
        self.assertEqual(sig1, sig2)

    def test_field_order_independence(self):
        event_reordered = {
            "body": self.event["body"],
            "timestamp": self.event["timestamp"],
            "structured_metadata": dict(
                reversed(list(self.event["structured_metadata"].items()))
            ),
            "labels": dict(reversed(list(self.event["labels"].items()))),
        }
        sig1 = compute_event_signature(self.event, self.key)
        sig2 = compute_event_signature(event_reordered, self.key)
        self.assertEqual(sig1, sig2)

    def test_verify_valid(self):
        sig = compute_event_signature(self.event, self.key)
        is_valid, computed = verify_event_signature(self.event, sig, self.key)
        self.assertTrue(is_valid)
        self.assertEqual(sig, computed)

    def test_verify_invalid(self):
        is_valid, _ = verify_event_signature(self.event, "0" * 64, self.key)
        self.assertFalse(is_valid)

    def test_none_body(self):
        event = {
            "timestamp": 123,
            "body": None,
            "labels": {},
            "structured_metadata": {},
        }
        sig = compute_event_signature(event, self.key)
        self.assertEqual(len(sig), 64)

    def test_empty_metadata(self):
        event = {
            "timestamp": 123,
            "body": "test",
            "labels": {},
            "structured_metadata": {},
        }
        sig = compute_event_signature(event, self.key)
        self.assertEqual(len(sig), 64)


if __name__ == "__main__":
    unittest.main()
