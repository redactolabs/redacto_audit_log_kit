import datetime
import io
import unittest
from contextlib import redirect_stderr
from unittest import mock

from redacto_audit_log_kit.exceptions import AuditKitExternalServiceError
from redacto_audit_log_kit.reconcile import event_keys, main, reconcile
from redacto_audit_log_kit.schema import MAX_LIMIT

DAY_1 = 1_795_219_200_000_000_000  # 2026-11-21 00:00 UTC
DAY_NS = 86_400 * 1_000_000_000


class FakeStore:
    """Answers query_range like Loki and audit-server: [start, end), newest first, limit."""

    def __init__(self, events):
        self.events = events
        self.calls = 0

    def get_events(self, query):
        self.calls += 1
        hits = sorted(
            (e for e in self.events if query.start <= e[0] < query.end),
            key=lambda e: e[0],
            reverse=True,
        )[: query.limit]
        return {
            "status": "success",
            "data": {
                "result": [
                    {"stream": {"event_signature": sig, "action": "x"}, "values": [[str(ts), "line"]]}
                    for ts, sig in hits
                ]
            },
        }


def events(n, start=DAY_1, step=1_000):
    return [(start + i * step, f"sig-{start}-{i}") for i in range(n)]


class TestEventKeys(unittest.TestCase):
    def test_pages_past_the_limit_without_losing_an_event(self):
        stored = events(MAX_LIMIT * 2 + 7)
        store = FakeStore(stored)

        keys = event_keys(store, "org", "consent", DAY_1, DAY_1 + DAY_NS)

        self.assertEqual(set(keys), set(stored))
        self.assertGreater(store.calls, 2)

    def test_keeps_events_sharing_the_nanosecond_a_page_ends_on(self):
        stored = events(MAX_LIMIT - 1, start=DAY_1 + 10_000_000) + [
            (DAY_1 + 5, f"same-ns-{i}") for i in range(3)
        ]

        keys = event_keys(FakeStore(stored), "org", "consent", DAY_1, DAY_1 + DAY_NS)

        self.assertEqual(set(keys), set(stored))


class TestReconcile(unittest.TestCase):
    def test_reports_each_day_and_the_events_one_store_lacks(self):
        shared = events(3) + events(2, start=DAY_1 + DAY_NS)
        lost = (DAY_1 + DAY_NS + 50, "lost-in-audit-server")
        extra = (DAY_1 + 70, "only-audit-server")

        days = reconcile(
            FakeStore(shared + [lost]),
            FakeStore(shared + [extra]),
            "org",
            "consent",
            DAY_1,
            DAY_1 + 2 * DAY_NS,
        )

        self.assertEqual(
            days,
            {
                datetime.date(2026, 11, 21): {
                    "loki": 3,
                    "audit_server": 4,
                    "only_loki": [],
                    "only_audit_server": [(extra[0], "x")],
                },
                datetime.date(2026, 11, 22): {
                    "loki": 3,
                    "audit_server": 2,
                    "only_loki": [(lost[0], "x")],
                    "only_audit_server": [],
                },
            },
        )


class TestMain(unittest.TestCase):
    def test_a_store_it_cannot_read_exits_2_not_1(self):
        class Forbidden:
            def get_events(self, query):
                raise AuditKitExternalServiceError(403, "audit-server returned: forbidden")

        argv = ["--org", "org", "--service", "vrm", "--start", "2026-11-21", "--end", "2026-11-22"]
        with mock.patch("redacto_audit_log_kit.reconcile.GrafanaLokiAdapter", lambda: FakeStore([])), \
                mock.patch("redacto_audit_log_kit.reconcile.AuditServerAdapter", Forbidden), \
                redirect_stderr(io.StringIO()) as err:
            code = main(argv)

        self.assertEqual(code, 2)
        self.assertIn("nothing compared", err.getvalue())


if __name__ == "__main__":
    unittest.main()
