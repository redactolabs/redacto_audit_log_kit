#!/usr/bin/env python3
"""
Monthly Audit Log Retrieval Script (Self-contained)

Fetches audit logs from Loki for all configured organizations for the past month.
Saves results to CSV files.

Dependencies: requests
Install: pip install requests

=== HOW TO RUN (inside Bastion pod) ===

1. Port-forward Loki:
   kubectl port-forward svc/loki 3100:3100 -n monitoring &

2. Run:
   python monthly_audit_retrieval.py --product vrm

   Options:
     --dry-run      Preview without fetching
     --output-dir   Custom output directory (default: ./audit_logs_output)

3. Output:
   CSV files saved to: ./audit_logs_output/<product>/<timestamp>/<client>.csv
"""

import argparse
import csv
import os
import sys
from datetime import datetime, timedelta, timezone

import requests


# ============================================================================
# CONFIGURATION - Add your organization mappings here
# ============================================================================

VRM_ORGS = {
    "razorpay": "069e0a7d-a09b-4840-bb99-443a992546ab",
    "vivamoney": "94acefc9-422a-45f5-8241-02714e72e663",
    "exotel": "bb594b05-6133-40fb-ab41-1de58128ba17",
    "indifi_capital": "f2407ec5-3ac5-4f9f-9ffd-432374b71412",
    "indifi_technologies": "1f53630d-0126-4fe2-9b23-8188a4767542",
    "oxyzo_finance": "393cedd2-a8d2-45d3-82d9-080d7573f66f",
    "pinelabs": "38a3b273-2546-4270-8109-428257a27066",
    "pinelabs_business_uat": "189cb6fc-0007-4ba3-80e7-dcc19e80ac5c",
    "pinelabs_pay_uat": "d890d9df-25a6-4dfe-9b8e-89c27d6ce855",
    "pinelabs_uat": "cfa67089-f98b-466d-9a84-41b2c4118ffd",
    "motilal_oswal": "50db6473-3f21-40ee-ba84-922130716db5",
}

TC_ORGS = {
    # "client_name": "org-uuid",
}

CONSENT_ORGS = {
    # "client_name": "org-uuid",
}

PRODUCT_ORG_MAPPING = {
    "vrm": VRM_ORGS,
    "tc": TC_ORGS,
    "consent": CONSENT_ORGS,
}

# Loki settings
LOKI_URL = "http://localhost:3100"
MAX_LIMIT = 1000

# CSV columns: (internal_field, display_header)
CSV_COLUMNS = [
    ("timestamp", "Timestamp"),
    ("action", "Action"),
    ("crud", "Operation Type"),
    ("actor_name", "Performed By"),
    ("actor_uuid", "User ID"),
    ("resource_name", "Resource Name"),
    ("resource_uuid", "Resource ID"),
    ("resource_type", "Resource Type"),
    ("source_ip", "IP Address"),
    ("description", "Description"),
]


# ============================================================================
# FUNCTIONS
# ============================================================================

def get_month_range():
    """Return (start, end) datetime for past month."""
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=30)
    return start_dt, end_dt


def query_loki(org_uuid, product, start_ns, end_ns, limit=MAX_LIMIT):
    """Query Loki API and return response JSON."""
    logql_query = f'{{organization_uuid="{org_uuid}", service_name="{product}"}}'

    params = {
        "query": logql_query,
        "start": start_ns,
        "end": end_ns,
        "limit": limit,
        "direction": "backward",
    }

    response = requests.get(
        f"{LOKI_URL}/loki/api/v1/query_range",
        params=params,
        headers={"Accept": "application/json"},
    )
    response.raise_for_status()
    return response.json()


def fetch_all_events(org_uuid, product, start_dt, end_dt, debug=False):
    """Fetch all events for an org, handling pagination if needed."""
    all_events = []
    current_end_ns = int(end_dt.timestamp() * 1e9)
    start_ns = int(start_dt.timestamp() * 1e9)
    first_batch = True

    while True:
        response = query_loki(org_uuid, product, start_ns, current_end_ns)
        results = response.get("data", {}).get("result", [])

        if not results:
            break

        # Debug: print first result structure to understand format
        if debug and first_batch and results:
            import json
            print("\n[DEBUG] Raw Loki response structure (first stream):")
            print(json.dumps(results[0], indent=2, default=str)[:3000])
            first_batch = False

        oldest_ts = None
        batch_count = 0

        for stream in results:
            # Extract stream labels (organization_uuid, service_name, etc.)
            stream_labels = stream.get("stream", {})

            for value in stream.get("values", []):
                ts_ns = int(value[0])
                body = value[1] if len(value) > 1 else ""

                # Structured metadata can be in value[2] (dict)
                structured_meta = {}
                if len(value) > 2 and isinstance(value[2], dict):
                    structured_meta = value[2]

                all_events.append({
                    "timestamp": datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    "description": body,
                    **stream_labels,
                    **structured_meta,
                })

                batch_count += 1
                if oldest_ts is None or ts_ns < oldest_ts:
                    oldest_ts = ts_ns

        if batch_count < MAX_LIMIT:
            break

        # Move to next page
        current_end_ns = oldest_ts - 1

    return all_events


def save_to_csv(events, filepath):
    """Save events to CSV file with PM-friendly headers."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    field_names = [col[0] for col in CSV_COLUMNS]
    display_headers = [col[1] for col in CSV_COLUMNS]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(display_headers)
        for event in events:
            writer.writerow([event.get(field, "") for field in field_names])


def main():
    parser = argparse.ArgumentParser(description="Fetch monthly audit logs from Loki")
    parser.add_argument("-p", "--product", required=True, choices=list(PRODUCT_ORG_MAPPING.keys()),
                        help="Product: vrm, tc, consent")
    parser.add_argument("--dry-run", action="store_true", help="Preview without fetching")
    parser.add_argument("--output-dir", default="./audit_logs_output", help="Output directory")
    parser.add_argument("--debug", action="store_true", help="Print raw Loki response structure")
    args = parser.parse_args()

    product = args.product
    org_mapping = PRODUCT_ORG_MAPPING[product]

    if not org_mapping:
        print(f"ERROR: No organizations configured for '{product}'")
        sys.exit(1)

    start_dt, end_dt = get_month_range()

    print(f"Product: {product}")
    print(f"Period: {start_dt.date()} to {end_dt.date()}")
    print(f"Organizations: {len(org_mapping)}")
    print()

    if args.dry_run:
        print("[DRY RUN]")
        for name, uuid in org_mapping.items():
            print(f"  {name}: {uuid}")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(args.output_dir, product, timestamp)

    failed = []

    for idx, (client_name, org_uuid) in enumerate(org_mapping.items(), 1):
        print(f"[{idx}/{len(org_mapping)}] {client_name}...", end=" ", flush=True)

        try:
            events = fetch_all_events(org_uuid, product, start_dt, end_dt, debug=args.debug)
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
