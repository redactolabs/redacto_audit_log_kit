import contextlib
import io
import os
import unittest
from unittest import mock

import requests

from redacto_audit_log_kit.adapter import GrafanaLokiAdapter
from redacto_audit_log_kit.exceptions import AuditKitConnectionError
from redacto_audit_log_kit.schema import SearchQuery

BASE_URL_WITH_CREDENTIALS = "http://consent:s3cret-client-key@audit-server:8080/audit"


def defined_event():
    return {
        "timestamp": 1_794_000_000_000_000_000,
        "body": "product created",
        "labels": {"organization_uuid": "org-1", "service_name": "consent"},
        "structured_metadata": {"action": "product.created"},
    }


def ok_response(status_code, body=None):
    response = mock.Mock(status_code=status_code)
    response.json.return_value = body or {}
    return response


class TestHttpTimeouts(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(
            os.environ,
            {
                "AUDIT_LOG_SIGNING_KEY": "test-secret-key",
                "LOKI_BASE_URL": BASE_URL_WITH_CREDENTIALS,
            },
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.adapter = GrafanaLokiAdapter()

    def test_push_sends_a_timeout(self):
        with mock.patch(
            "redacto_audit_log_kit.adapter.requests.post",
            return_value=ok_response(204),
        ) as post:
            self.adapter.report_event(defined_event())

        self.assertGreater(post.call_args.kwargs.get("timeout") or 0, 0)

    def test_push_timeout_raises_connection_error_for_the_caller_to_retry(self):
        with mock.patch(
            "redacto_audit_log_kit.adapter.requests.post",
            side_effect=requests.exceptions.ReadTimeout("read timed out"),
        ):
            with self.assertRaises(AuditKitConnectionError):
                self.adapter.report_event(defined_event())

    def test_query_sends_a_timeout(self):
        with mock.patch(
            "redacto_audit_log_kit.adapter.requests.get",
            return_value=ok_response(200, {"status": "success"}),
        ) as get:
            self.adapter.get_events(SearchQuery(organization_uuid="org-1"))

        self.assertGreater(get.call_args.kwargs.get("timeout") or 0, 0)

    def test_query_waits_longer_than_a_push(self):
        with mock.patch(
            "redacto_audit_log_kit.adapter.requests.post",
            return_value=ok_response(204),
        ) as post, mock.patch(
            "redacto_audit_log_kit.adapter.requests.get",
            return_value=ok_response(200, {"status": "success"}),
        ) as get:
            self.adapter.report_event(defined_event())
            self.adapter.get_events(SearchQuery(organization_uuid="org-1"))

        self.assertEqual(get.call_args.kwargs["timeout"], 30)
        self.assertEqual(post.call_args.kwargs["timeout"], 10)

    def test_query_does_not_print_the_base_url_credentials(self):
        stdout = io.StringIO()
        with mock.patch(
            "redacto_audit_log_kit.adapter.requests.get",
            return_value=ok_response(200, {"status": "success"}),
        ), contextlib.redirect_stdout(stdout):
            self.adapter.get_events(SearchQuery(organization_uuid="org-1"))

        self.assertNotIn("s3cret-client-key", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
