import os
import unittest
from unittest import mock

import requests

from redacto_audit_log_kit.adapter import (
    AuditServerAdapter,
    GrafanaLokiAdapter,
    adapters_from_env,
    reader_from_env,
)
from redacto_audit_log_kit.client import AuditClient
from redacto_audit_log_kit.exceptions import (
    AuditKitConfigurationError,
    AuditKitConnectionError,
    AuditKitExternalServiceError,
)
from redacto_audit_log_kit.schema import AuditEvent, SearchQuery

LOKI_BASE_URL = "http://loki:3100"
AUDIT_SERVER_BASE_URL = "http://consent:s3cret-client-key@audit-server:8080/audit"
LOKI_PUSH = LOKI_BASE_URL + "/loki/api/v1/push"
AUDIT_SERVER_PUSH = AUDIT_SERVER_BASE_URL + "/loki/api/v1/push"


def defined_event():
    return {
        "timestamp": 1_794_000_000_000_000_000,
        "body": "product created",
        "labels": {"organization_uuid": "org-1", "service_name": "consent"},
        "structured_metadata": {"action": "product.created"},
    }


def an_event():
    return AuditEvent(organization_uuid="org-1", service_name="consent", description="x")


def response(status_code, text="", body=None):
    r = mock.Mock(status_code=status_code, text=text)
    r.json.return_value = body or {"status": "success"}
    return r


class AdapterTestCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(
            os.environ,
            {
                "AUDIT_LOG_SIGNING_KEY": "test-secret-key",
                "LOKI_BASE_URL": LOKI_BASE_URL,
                "AUDIT_SERVER_BASE_URL": AUDIT_SERVER_BASE_URL,
            },
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("AUDIT_LOG_BACKEND", None)
        os.environ.pop("AUDIT_LOG_READ_FROM", None)

    def backend(self, value):
        if value is None:
            os.environ.pop("AUDIT_LOG_BACKEND", None)
        else:
            os.environ["AUDIT_LOG_BACKEND"] = value

    def read_from(self, value):
        if value is None:
            os.environ.pop("AUDIT_LOG_READ_FROM", None)
        else:
            os.environ["AUDIT_LOG_READ_FROM"] = value

    def patch(self, method, *responses):
        patcher = mock.patch(
            f"redacto_audit_log_kit.adapter.requests.{method}", side_effect=list(responses)
        )
        mocked = patcher.start()
        self.addCleanup(patcher.stop)
        return mocked


class TestGrafanaLokiAdapter(AdapterTestCase):
    def test_writes_loki_only_even_when_audit_server_is_configured(self):
        post = self.patch("post", response(204))

        GrafanaLokiAdapter().report_event(defined_event())

        self.assertEqual([c.args[0] for c in post.call_args_list], [LOKI_PUSH])


class TestAuditServerAdapter(AdapterTestCase):
    def test_pushes_to_audit_server(self):
        post = self.patch("post", response(204))

        AuditServerAdapter().report_event(defined_event())

        self.assertEqual(post.call_args.args[0], AUDIT_SERVER_PUSH)
        self.assertEqual(post.call_args.kwargs["timeout"], 10)

    def test_reads_from_audit_server(self):
        get = self.patch("get", response(200))

        AuditServerAdapter().get_events(SearchQuery(organization_uuid="org-1"))

        self.assertEqual(get.call_args.args[0], AUDIT_SERVER_BASE_URL + "/loki/api/v1/query_range")

    def test_a_rejection_names_audit_server(self):
        self.patch("post", response(403, "service not allowed"))

        with self.assertRaises(AuditKitExternalServiceError) as caught:
            AuditServerAdapter().report_event(defined_event())

        self.assertIn("audit-server returned", str(caught.exception))

    def test_requires_its_base_url(self):
        os.environ.pop("AUDIT_SERVER_BASE_URL")

        with self.assertRaises(AuditKitConfigurationError) as caught:
            AuditServerAdapter().report_event(defined_event())

        self.assertIn("AUDIT_SERVER_BASE_URL is not set", str(caught.exception))


class TestAdaptersFromEnv(AdapterTestCase):
    def test_each_backend_builds_its_adapters_in_write_order(self):
        cases = [
            (None, [GrafanaLokiAdapter]),
            ("loki", [GrafanaLokiAdapter]),
            ("dual", [GrafanaLokiAdapter, AuditServerAdapter]),
            (" Dual ", [GrafanaLokiAdapter, AuditServerAdapter]),
            ("audit_server", [AuditServerAdapter]),
        ]
        for value, want in cases:
            with self.subTest(AUDIT_LOG_BACKEND=value):
                self.backend(value)
                self.assertEqual([type(a) for a in adapters_from_env()], want)

    def test_an_unknown_backend_fails_at_startup(self):
        self.backend("both")

        with self.assertRaises(AuditKitConfigurationError):
            adapters_from_env()

    def test_an_audit_server_backend_without_its_url_fails_at_startup(self):
        os.environ.pop("AUDIT_SERVER_BASE_URL")
        for value in ("dual", "audit_server"):
            with self.subTest(AUDIT_LOG_BACKEND=value):
                self.backend(value)
                with self.assertRaises(AuditKitConfigurationError):
                    adapters_from_env()


class TestReaderFromEnv(AdapterTestCase):
    def test_reads_go_to_the_named_store_or_loki_while_it_is_written(self):
        cases = [
            ("dual", None, GrafanaLokiAdapter),
            ("dual", "loki", GrafanaLokiAdapter),
            ("dual", " Audit_Server ", AuditServerAdapter),
            ("audit_server", None, AuditServerAdapter),
            ("audit_server", "audit_server", AuditServerAdapter),
        ]
        for backend, read_from, want in cases:
            with self.subTest(AUDIT_LOG_BACKEND=backend, AUDIT_LOG_READ_FROM=read_from):
                self.backend(backend)
                self.read_from(read_from)
                self.assertIsInstance(reader_from_env(adapters_from_env()), want)

    def test_an_unknown_value_fails_at_startup(self):
        self.backend("dual")
        self.read_from("postgres")

        with self.assertRaises(AuditKitConfigurationError):
            reader_from_env(adapters_from_env())

    def test_reading_a_store_that_is_not_written_fails_at_startup(self):
        for backend, read_from in (("loki", "audit_server"), ("audit_server", "loki")):
            with self.subTest(AUDIT_LOG_BACKEND=backend, AUDIT_LOG_READ_FROM=read_from):
                self.backend(backend)
                self.read_from(read_from)
                with self.assertRaises(AuditKitConfigurationError):
                    AuditClient()


class TestDualWriteClient(AdapterTestCase):
    def setUp(self):
        super().setUp()
        self.backend("dual")

    def test_log_sends_the_same_event_to_loki_then_audit_server(self):
        post = self.patch("post", response(204), response(204))

        AuditClient().log(an_event())

        loki, audit = post.call_args_list
        self.assertEqual((loki.args[0], audit.args[0]), (LOKI_PUSH, AUDIT_SERVER_PUSH))
        self.assertEqual(audit.kwargs["json"], loki.kwargs["json"])

    def test_the_result_reports_every_store(self):
        self.patch("post", response(204), response(200))

        result = AuditClient().log(an_event())

        self.assertEqual(result["status"], "success")
        self.assertEqual(
            {name: r["status_code"] for name, r in result["stores"].items()},
            {"GrafanaLokiAdapter": 204, "AuditServerAdapter": 200},
        )

    def test_an_audit_server_rejection_raises_for_the_caller_to_retry(self):
        self.patch("post", response(204), response(503, "unavailable"))

        with self.assertRaises(AuditKitExternalServiceError):
            AuditClient().log(an_event())

    def test_an_audit_server_timeout_raises_for_the_caller_to_retry(self):
        self.patch("post", response(204), requests.exceptions.ReadTimeout("read timed out"))

        with self.assertRaises(AuditKitConnectionError):
            AuditClient().log(an_event())

    def test_a_loki_failure_still_writes_audit_server_and_raises(self):
        post = self.patch("post", response(500, "loki down"), response(204))

        with self.assertRaises(AuditKitExternalServiceError) as caught:
            AuditClient().log(an_event())

        self.assertEqual([c.args[0] for c in post.call_args_list], [LOKI_PUSH, AUDIT_SERVER_PUSH])
        self.assertIn("Loki returned", str(caught.exception))

    def test_when_both_fail_the_error_names_both(self):
        self.patch("post", response(500, "loki down"), response(503, "audit-server down"))

        with self.assertRaises(AuditKitExternalServiceError) as caught:
            AuditClient().log(an_event())

        self.assertIn("Loki returned", str(caught.exception))
        self.assertTrue(any("audit-server returned" in n for n in caught.exception.__notes__))

    def test_reads_go_to_loki(self):
        get = self.patch("get", response(200))

        AuditClient().get_events(SearchQuery(organization_uuid="org-1"))

        self.assertEqual(get.call_args.args[0], LOKI_BASE_URL + "/loki/api/v1/query_range")

    def test_with_audit_server_alone_reads_go_to_audit_server(self):
        self.backend("audit_server")
        get = self.patch("get", response(200))

        AuditClient().get_events(SearchQuery(organization_uuid="org-1"))

        self.assertEqual(get.call_args.args[0], AUDIT_SERVER_BASE_URL + "/loki/api/v1/query_range")

    def test_reads_can_move_to_audit_server_while_both_are_written(self):
        self.read_from("audit_server")
        post = self.patch("post", response(204), response(204))
        get = self.patch("get", response(200))
        client = AuditClient()

        client.log(an_event())
        client.get_events(SearchQuery(organization_uuid="org-1"))

        self.assertEqual([c.args[0] for c in post.call_args_list], [LOKI_PUSH, AUDIT_SERVER_PUSH])
        self.assertEqual(get.call_args.args[0], AUDIT_SERVER_BASE_URL + "/loki/api/v1/query_range")

    def test_an_explicit_adapter_reads_there_whatever_the_env_says(self):
        self.read_from("audit_server")
        get = self.patch("get", response(200))

        AuditClient(adapter=GrafanaLokiAdapter()).get_events(SearchQuery(organization_uuid="org-1"))

        self.assertEqual(get.call_args.args[0], LOKI_BASE_URL + "/loki/api/v1/query_range")

    def test_an_explicit_adapter_still_writes_only_there(self):
        post = self.patch("post", response(204))

        AuditClient(adapter=GrafanaLokiAdapter()).log(an_event())

        self.assertEqual([c.args[0] for c in post.call_args_list], [LOKI_PUSH])


if __name__ == "__main__":
    unittest.main()
