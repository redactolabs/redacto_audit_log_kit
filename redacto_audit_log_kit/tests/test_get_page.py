import os
import unittest
from unittest import mock

from redacto_audit_log_kit.adapter import AuditServerAdapter, GrafanaLokiAdapter
from redacto_audit_log_kit.client import AuditClient
from redacto_audit_log_kit.exceptions import AuditKitInvalidDataError
from redacto_audit_log_kit.schema import SearchQuery

ENV = {
    "AUDIT_LOG_SIGNING_KEY": "test-secret-key",
    "LOKI_BASE_URL": "http://loki:3100",
    "AUDIT_SERVER_BASE_URL": "http://consent:secret@audit-server:8080/audit",
}


def store_response(*streams):
    return {"status": "success", "data": {"resultType": "streams", "result": list(streams)}}


def stream(metadata, *timestamps):
    return {"stream": metadata, "values": [[str(ts), f"line {ts}"] for ts in timestamps]}


class GetPageTestCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, ENV)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("AUDIT_LOG_BACKEND", "AUDIT_LOG_READ_FROM", "LOKI_METADATA_ESCAPED_BEFORE_NS"):
            os.environ.pop(name, None)

    def page(self, adapter, body, **query):
        with mock.patch.object(adapter, "get_events", return_value=body) as get_events:
            page = adapter.get_page(SearchQuery(organization_uuid="org-1", **query))
        return page, get_events.call_args.args[0]


class TestGetPage(GetPageTestCase):
    def test_merges_streams_newest_first_and_hands_back_a_token_when_more_remain(self):
        body = store_response(
            stream({"service_name": "consent", "action": "a"}, 50, 10),
            stream({"service_name": "consent", "action": "b"}, 40, 30),
        )

        page, sent = self.page(GrafanaLokiAdapter(), body, limit=3)

        self.assertEqual(sent.limit, 4)
        self.assertEqual([e.timestamp for e in page.events], [50, 40, 30])
        self.assertEqual([e.metadata["action"] for e in page.events], ["a", "b", "b"])
        self.assertEqual(page.next_page_token, "30")

    def test_the_last_page_has_no_token(self):
        page, _ = self.page(GrafanaLokiAdapter(), store_response(stream({}, 20, 10)), limit=3)

        self.assertEqual(len(page.events), 2)
        self.assertIsNone(page.next_page_token)

    def test_the_token_asks_for_the_page_after_it(self):
        _, sent = self.page(GrafanaLokiAdapter(), store_response(), limit=3, page_token="30")

        self.assertEqual(sent.end, 30)

    def test_a_token_it_did_not_issue_is_rejected(self):
        with self.assertRaises(AuditKitInvalidDataError):
            self.page(GrafanaLokiAdapter(), store_response(), page_token="next")

    def test_splits_attributes_from_metadata(self):
        body = store_response(stream({"action": "a", "attr_reason": "manual"}, 10))

        page, _ = self.page(GrafanaLokiAdapter(), body)

        self.assertEqual(page.events[0].metadata, {"action": "a"})
        self.assertEqual(page.events[0].attributes, {"reason": "manual"})
        self.assertEqual(page.events[0].message, "line 10")


class TestMetadataDecoding(GetPageTestCase):
    escaped = {"organization_uuid": "o\\\\1", "resource_name": 'a \\"b\\"'}

    def test_loki_metadata_is_unescaped_except_labels(self):
        page, _ = self.page(GrafanaLokiAdapter(), store_response(stream(self.escaped, 10)))

        self.assertEqual(page.events[0].metadata, {"organization_uuid": "o\\\\1", "resource_name": 'a "b"'})

    def test_loki_events_from_after_the_cutover_are_left_as_stored(self):
        os.environ["LOKI_METADATA_ESCAPED_BEFORE_NS"] = "20"

        page, _ = self.page(GrafanaLokiAdapter(), store_response(stream(self.escaped, 30, 10)))

        self.assertEqual(page.events[0].metadata["resource_name"], 'a \\"b\\"')
        self.assertEqual(page.events[1].metadata["resource_name"], 'a "b"')

    def test_audit_server_metadata_is_left_as_stored(self):
        page, _ = self.page(AuditServerAdapter(), store_response(stream(self.escaped, 10)))

        self.assertEqual(page.events[0].metadata["resource_name"], 'a \\"b\\"')


class TestClientGetPage(GetPageTestCase):
    def test_pages_come_from_the_reader(self):
        os.environ["AUDIT_LOG_BACKEND"] = "dual"
        os.environ["AUDIT_LOG_READ_FROM"] = "audit_server"
        client = AuditClient()

        with mock.patch.object(client.reader, "get_events", return_value=store_response()) as get:
            client.get_page(SearchQuery(organization_uuid="org-1"))

        self.assertIsInstance(client.reader, AuditServerAdapter)
        get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
