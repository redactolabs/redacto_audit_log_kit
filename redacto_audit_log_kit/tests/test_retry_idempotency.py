import itertools
import os
import unittest
from unittest import mock

from redacto_audit_log_kit.adapter import GrafanaLokiAdapter
from redacto_audit_log_kit.schema import AuditEvent

_clock = itertools.count(1_794_000_000_000_000_000, 1_000_000)


def queued_payload(**fields):
    """What an async client puts on the queue: the event dumped before any send attempt."""
    return AuditEvent(organization_uuid="org-1", service_name="consent", description="x", **fields).model_dump(
        exclude_none=True
    )


class TestRetrySendsTheSameEvent(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"AUDIT_LOG_SIGNING_KEY": "test-secret-key"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.adapter = GrafanaLokiAdapter()

    def attempts(self, payload):
        with mock.patch("time.time_ns", side_effect=lambda: next(_clock)):
            return [self.adapter.define_event(AuditEvent(**payload)) for _ in range(2)]

    def test_an_event_without_created_keeps_its_timestamp_across_attempts(self):
        with mock.patch("time.time_ns", side_effect=lambda: next(_clock)):
            payload = queued_payload()
        first, retry = self.attempts(payload)

        self.assertEqual(first, retry)

    def test_an_explicit_none_created_is_stamped_once_too(self):
        with mock.patch("time.time_ns", side_effect=lambda: next(_clock)):
            payload = queued_payload(created=None)
        first, retry = self.attempts(payload)

        self.assertEqual(first, retry)

    def test_a_caller_supplied_created_is_kept(self):
        payload = queued_payload(created=1_700_000_000_000_000_000)
        first, _ = self.attempts(payload)

        self.assertEqual(first["timestamp"], 1_700_000_000_000_000_000)


if __name__ == "__main__":
    unittest.main()
