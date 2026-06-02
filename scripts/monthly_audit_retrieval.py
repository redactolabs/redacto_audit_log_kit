#!/usr/bin/env python3
"""
Monthly Audit Log Retrieval Script

Fetches audit logs for all configured organizations for the past month.
Saves results to CSV files.

=== HOW TO RUN ===

1. Port-forward Loki:
   kubectl port-forward svc/loki 3100:3100 -n monitoring &

2. Set environment variables:
   export LOKI_BASE_URL=http://localhost:3100
   export AUDIT_LOG_SIGNING_KEY=<your-signing-key>

3. Run:
   poetry run python scripts/monthly_audit_retrieval.py --product vrm

4. Optional flags:
   --dry-run      Preview without fetching
   --output-dir   Custom output directory (default: ./audit_logs_output)

5. Output:
   CSV files saved to: ./audit_logs_output/<service>/<timestamp>/<client>.csv
"""

import argparse
import csv
import os
import sys
from datetime import datetime, timezone

from dateutil.relativedelta import relativedelta

from redacto_audit_log_kit.adapter import GrafanaLokiAdapter
from redacto_audit_log_kit.schema import SearchQuery, MAX_LIMIT
from org_mappings import SERVICE_ORG_MAPPING, VALID_SERVICES


CSV_COLUMNS = [
    "timestamp",
    "action",
    "crud",
    "actor_name",
    "actor_uuid",
    "resource_name",
    "resource_uuid",
    "resource_type",
    "source_ip",
    "description",
]


def get_month_range():
    """Return (start, end) datetime for past month."""
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - relativedelta(months=1)
    return start_dt, end_dt


def fetch_all_events(adapter, org_uuid, service_name, start_dt, end_dt):
    """Fetch all events for an org, handling pagination if needed."""
    all_events = []
    current_end = end_dt

    while True:
        query = SearchQuery(
            organization_uuid=org_uuid,
            service_name=service_name,
            start=int(start_dt.timestamp()),
            end=int(current_end.timestamp()),
            limit=MAX_LIMIT,
            direction="backward",
        )

        response = adapter.get_events(query)
        results = response.get("data", {}).get("result", [])

        if not results:
            break

        oldest_ts = None
        batch_count = 0

        for stream in results:
            for value in stream.get("values", []):
                ts_ns = int(value[0])
                body = value[1] if len(value) > 1 else ""
                metadata = value[2] if len(value) > 2 else {}

                all_events.append({
                    "timestamp": datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat(),
                    "description": body,
                    **metadata,
                })

                batch_count += 1
                if oldest_ts is None or ts_ns < oldest_ts:
                    oldest_ts = ts_ns

        if batch_count < MAX_LIMIT:
            break

        current_end = datetime.fromtimestamp((oldest_ts - 1) / 1e9, tz=timezone.utc)

    return all_events


def save_to_csv(events, filepath):
    """Save events to CSV file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)


def main():
    parser = argparse.ArgumentParser(description="Fetch monthly audit logs")
    parser.add_argument("-p", "--product", required=True, choices=VALID_SERVICES,
                        help=f"Product: {', '.join(VALID_SERVICES)}")
    parser.add_argument("--dry-run", action="store_true", help="Preview without fetching")
    parser.add_argument("--output-dir", default="./audit_logs_output", help="Output directory")
    args = parser.parse_args()

    # Check environment
    if not os.environ.get("LOKI_BASE_URL") or not os.environ.get("AUDIT_LOG_SIGNING_KEY"):
        print("ERROR: Set LOKI_BASE_URL and AUDIT_LOG_SIGNING_KEY environment variables")
        sys.exit(1)

    service_name = args.product
    org_mapping = SERVICE_ORG_MAPPING[service_name]

    if not org_mapping:
        print(f"ERROR: No organizations configured for '{service_name}' in scripts/org_mappings.py")
        sys.exit(1)

    start_dt, end_dt = get_month_range()

    print(f"Service: {service_name}")
    print(f"Period: {start_dt.date()} to {end_dt.date()}")
    print(f"Organizations: {len(org_mapping)}")
    print()

    if args.dry_run:
        print("[DRY RUN]")
        for name, uuid in org_mapping.items():
            print(f"  {name}: {uuid}")
        return

    adapter = GrafanaLokiAdapter()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(args.output_dir, service_name, timestamp)

    failed = []

    for idx, (client_name, org_uuid) in enumerate(org_mapping.items(), 1):
        print(f"[{idx}/{len(org_mapping)}] {client_name}...", end=" ", flush=True)

        try:
            events = fetch_all_events(adapter, org_uuid, service_name, start_dt, end_dt)
            filepath = os.path.join(output_dir, f"{client_name}.csv")
            save_to_csv(events, filepath)
            print(f"{len(events)} events")
        except Exception as e:
            print(f"FAILED: {e}")
            failed.append(client_name)

    print()
    print(f"Done. Output: {output_dir}")
    if failed:
        print(f"Failed: {', '.join(failed)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
