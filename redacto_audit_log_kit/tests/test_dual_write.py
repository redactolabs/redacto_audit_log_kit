import os
import unittest
from unittest import mock

import requests

from redacto_audit_log_kit.adapter import GrafanaLokiAdapter
from redacto_audit_log_kit.exceptions import (
    AuditKitConnectionError,
    AuditKitExternalServiceError,
)

LOKI_BASE_URL = "http://loki:3100"
AUDIT_SERVER_BASE_URL = "http://consent:s3cret-client-key@audit-server:8080/audit"


def defined_event():
    return {
        "timestamp": 1_794_000_000_000_000_000,
        "body": "product created",
        "labels": {"organization_uuid": "org-1", "service_name": "consent"},
        "structured_metadata": {"action": "product.created"},
    }


def response(status_code, text=""):
    return mock.Mock(status_code=status_code, text=text)


class TestDualWrite(unittest.TestCase):
    def adapter(self, audit_server_base_url=None):
        patcher = mock.patch.dict(
            os.environ,
            {"AUDIT_LOG_SIGNING_KEY": "test-secret-key", "LOKI_BASE_URL": LOKI_BASE_URL},
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("AUDIT_SERVER_BASE_URL", None)
        if audit_server_base_url:
            os.environ["AUDIT_SERVER_BASE_URL"] = audit_server_base_url
        return GrafanaLokiAdapter()

    def post_returning(self, *responses):
        patcher = mock.patch(
            "redacto_audit_log_kit.adapter.requests.post", side_effect=list(responses)
        )
        post = patcher.start()
        self.addCleanup(patcher.stop)
        return post

    def test_without_audit_server_only_loki_is_written(self):
        adapter = self.adapter()
        post = self.post_returning(response(204))

        adapter.report_event(defined_event())

        self.assertEqual(
            [c.args[0] for c in post.call_args_list],
            [LOKI_BASE_URL + "/loki/api/v1/push"],
        )

    def test_with_audit_server_both_receive_the_same_push(self):
        adapter = self.adapter(AUDIT_SERVER_BASE_URL)
        post = self.post_returning(response(204), response(204))

        adapter.report_event(defined_event())

        loki, audit = post.call_args_list
        self.assertEqual(loki.args[0], LOKI_BASE_URL + "/loki/api/v1/push")
        self.assertEqual(audit.args[0], AUDIT_SERVER_BASE_URL + "/loki/api/v1/push")
        self.assertEqual(audit.kwargs["json"], loki.kwargs["json"])
        self.assertEqual(audit.kwargs["timeout"], 10)

    def test_an_audit_server_rejection_raises_for_the_caller_to_retry(self):
        adapter = self.adapter(AUDIT_SERVER_BASE_URL)
        self.post_returning(response(204), response(503, "unavailable"))

        with self.assertRaises(AuditKitExternalServiceError):
            adapter.report_event(defined_event())

    def test_an_audit_server_timeout_raises_for_the_caller_to_retry(self):
        adapter = self.adapter(AUDIT_SERVER_BASE_URL)
        self.post_returning(response(204), requests.exceptions.ReadTimeout("read timed out"))

        with self.assertRaises(AuditKitConnectionError):
            adapter.report_event(defined_event())

    def test_a_loki_failure_raises_before_audit_server_is_written(self):
        adapter = self.adapter(AUDIT_SERVER_BASE_URL)
        post = self.post_returning(response(500, "loki down"), response(204))

        with self.assertRaises(AuditKitExternalServiceError):
            adapter.report_event(defined_event())

        self.assertEqual(post.call_count, 1)


if __name__ == "__main__":
    unittest.main()
