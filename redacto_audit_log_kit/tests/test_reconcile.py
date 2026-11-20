import datetime
import unittest

from redacto_audit_log_kit.reconcile import event_keys, reconcile
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


if __name__ == "__main__":
    unittest.main()
