"""
Compares what Loki and audit-server hold for one organization and service, day by
day, so Loki can be dropped only once audit-server is known to be complete.

Run it where the service runs, with that service's LOKI_BASE_URL and
AUDIT_SERVER_BASE_URL:

    python -m redacto_audit_log_kit.reconcile --org <uuid> --service consent \\
        --start 2026-11-21 --end 2026-11-28

Start from the day dual write was switched on: events from before then are only in
Loki. Exits 1 when any day differs, and prints up to --show of the missing events.
Exits 2 when a store can't be read (for example a 403 because this service's
audit-server client may not read --service), since nothing was compared.
"""

import argparse
import datetime
import sys
from collections import defaultdict

from redacto_audit_log_kit.adapter import AuditServerAdapter, GrafanaLokiAdapter
from redacto_audit_log_kit.exceptions import AuditKitError
from redacto_audit_log_kit.schema import MAX_LIMIT, SearchQuery

NS_PER_SECOND = 1_000_000_000


def event_keys(adapter, organization_uuid, service_name, start_ns, end_ns):
    """
    Returns every event in [start_ns, end_ns) as {(ts, event_signature or line): action}.
    Pages newest first; each page ends one nanosecond after the oldest event seen, so
    events sharing that nanosecond are not skipped, and the set drops the repeats.
    """
    keys = {}
    end = end_ns
    while end > start_ns:
        response = adapter.get_events(
            SearchQuery(
                organization_uuid=organization_uuid,
                service_name=service_name,
                start=start_ns,
                end=end,
                limit=MAX_LIMIT,
            )
        )
        page = {}
        for stream in response.get("data", {}).get("result", []):
            metadata = stream.get("stream", {})
            for ts, line in stream.get("values", []):
                key = (int(ts), metadata.get("event_signature") or line)
                page[key] = metadata.get("action", "")
        new = page.keys() - keys.keys()
        keys.update(page)
        if len(page) < MAX_LIMIT:
            break
        oldest = min(ts for ts, _ in page)
        end = oldest + 1 if new else oldest
    return keys


def day_of(ts_ns):
    return datetime.datetime.fromtimestamp(ts_ns / NS_PER_SECOND, datetime.timezone.utc).date()


def reconcile(loki, audit_server, organization_uuid, service_name, start_ns, end_ns):
    """
    Returns {day: {"loki": n, "audit_server": n, "only_loki": [(ts, action)],
    "only_audit_server": [(ts, action)]}} for every UTC day with an event in either store.
    """
    stores = {
        "loki": event_keys(loki, organization_uuid, service_name, start_ns, end_ns),
        "audit_server": event_keys(audit_server, organization_uuid, service_name, start_ns, end_ns),
    }
    days = defaultdict(
        lambda: {"loki": 0, "audit_server": 0, "only_loki": [], "only_audit_server": []}
    )
    for name, other in (("loki", "audit_server"), ("audit_server", "loki")):
        for key, action in stores[name].items():
            day = days[day_of(key[0])]
            day[name] += 1
            if key not in stores[other]:
                day[f"only_{name}"].append((key[0], action))
    return dict(sorted(days.items()))


def utc_midnight_ns(value):
    day = datetime.date.fromisoformat(value)
    midnight = datetime.datetime.combine(day, datetime.time(), datetime.timezone.utc)
    return int(midnight.timestamp()) * NS_PER_SECOND


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--org", required=True, help="organization_uuid")
    parser.add_argument("--service", required=True, help="service_name, e.g. consent, vrm")
    parser.add_argument("--start", required=True, help="first UTC day, YYYY-MM-DD")
    parser.add_argument("--end", required=True, help="UTC day after the last, YYYY-MM-DD")
    parser.add_argument("--show", type=int, default=20, help="missing events to print per day")
    args = parser.parse_args(argv)

    try:
        days = reconcile(
            GrafanaLokiAdapter(),
            AuditServerAdapter(),
            args.org,
            args.service,
            utc_midnight_ns(args.start),
            utc_midnight_ns(args.end),
        )
    except AuditKitError as e:
        print(f"could not read a store, nothing compared: {e}", file=sys.stderr)
        return 2
    differs = False
    print("day         loki  audit_server  only_loki  only_audit_server")
    for day, d in days.items():
        only_loki, only_as = d["only_loki"], d["only_audit_server"]
        print(
            f"{day}  {d['loki']:>5}  {d['audit_server']:>12}  {len(only_loki):>9}  {len(only_as):>17}"
        )
        for store, missing in (("only in Loki", only_loki), ("only in audit-server", only_as)):
            for ts, action in sorted(missing)[: args.show]:
                print(f"    {store}: ts={ts} action={action}")
        differs = differs or bool(only_loki or only_as)
    if not days:
        print("no events in either store")
    return 1 if differs else 0


if __name__ == "__main__":
    sys.exit(main())
