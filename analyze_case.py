"""DF-017 synthetic investigation. Implement only the two TODO functions."""
import argparse
from datetime import timedelta
from pathlib import Path
from evidence_tools import load_case, write_json

BASE = Path(__file__).resolve().parent

def find_login_sequences(rows, min_failures=3, window_minutes=5):
    """Find successes preceded by repeated failures; return a list of dicts."""
    # ASSUMPTION: the event type is stored under row["status"] with the values
    # "SUCCESS" and "FAIL". If your loader uses another key (e.g. "result"
    # or "event_type"), change STATUS_KEY only.
    STATUS_KEY = "result"

    window = timedelta(minutes=window_minutes)

    failures_by_group = {}   # group key -> list of FAIL rows
    successes = []           # list of (group key, SUCCESS row)

    # Pass 1: bucket rows without modifying them.
    for row in rows:
        key = (row["username"], row["source_ip"], row["host"])
        if row[STATUS_KEY] == "FAIL":
            failures_by_group.setdefault(key, []).append(row)
        elif row[STATUS_KEY] == "SUCCESS":
            successes.append((key, row))
        # any other status is ignored

    # Pass 2: order each group's failures (sorted() makes new lists,
    # so the caller's data is never mutated).
    for key in failures_by_group:
        failures_by_group[key] = sorted(
            failures_by_group[key],
            key=lambda r: (r["timestamp"], r["event_id"]),
        )

    # Pass 3: evaluate each success independently.
    results = []
    for key, success in successes:
        success_time = success["timestamp"]
        window_start = success_time - window

        matching_ids = []
        for failure in failures_by_group.get(key, []):
            if window_start <= failure["timestamp"] < success_time:
                matching_ids.append(failure["event_id"])

        if len(matching_ids) >= min_failures:
            results.append({
                "username": success["username"],
                "source_ip": success["source_ip"],
                "host": success["host"],
                "session_id": success["session_id"],
                "success_id": success["event_id"],
                "success_time": success_time,
                "failure_ids": matching_ids,
            })

    return sorted(results, key=lambda r: (r["success_time"], r["success_id"]))

def correlate_downloads(alerts, file_rows, followup_minutes=10):
    """Enrich each alert with file activity; return a new list of new dicts."""
    followup = timedelta(minutes=followup_minutes)

    # Index only successful downloads by the full key, so each alert
    # looks at a small list instead of scanning every file row.
    downloads_by_key = {}
    for row in file_rows:
        if row["action"] == "DOWNLOAD" and row["result"] == "SUCCESS":
            key = (row["username"], row["host"], row["session_id"])
            downloads_by_key.setdefault(key, []).append(row)

    enriched = []
    for alert in alerts:
        start = alert["success_time"]
        end = start + followup
        key = (alert["username"], alert["host"], alert["session_id"])

        matches = []
        for row in downloads_by_key.get(key, []):
            if start <= row["timestamp"] <= end:
                matches.append(row)
        matches = sorted(matches, key=lambda r: (r["timestamp"], r["event_id"]))

        # Copy the alert into a NEW dict, copying any list values too,
        # so the caller's alert and its nested lists are never shared.
        new_alert = {}
        for field, value in alert.items():
            new_alert[field] = list(value) if isinstance(value, list) else value

        new_alert["download_ids"] = [r["event_id"] for r in matches]
        new_alert["download_count"] = len(matches)
        new_alert["total_bytes"] = sum(r["bytes"] for r in matches)
        enriched.append(new_alert)

    return sorted(
        enriched,
        key=lambda a: (-a["total_bytes"], a["success_time"], a["success_id"]),
    )

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=['logins', 'all'], default='all')
    args = parser.parse_args()
    try:
        auth, files, audit = load_case(BASE)
    except ValueError as error:
        parser.exit(1, f'Evidence check failed: {error}\n')
    write_json(BASE / 'audit.json', audit)
    print('SHA-256 checks match the supplied manifest.')
    for name in ['auth_log.csv', 'file_log.csv']:
        info = audit[name]
        print(f"{name}: {info['data_rows']} rows; {info['accepted']} accepted; "
              f"{len(info['duplicates'])} duplicate; {len(info['rejected'])} rejected.")
    print('Saved audit.json. A hash match does not prove origin or completeness.')
    try:
        alerts = find_login_sequences(auth)
        write_json(BASE / 'login_alerts.json', alerts)
        print(f'Found {len(alerts)} login sequences; saved login_alerts.json.')
        if args.stage == 'logins':
            return
        findings = correlate_downloads(alerts, files)
    except NotImplementedError as error:
        print(f'Starter ready: {error}. Previously generated outputs may be stale.')
        return
    summary = {'case': 'DF-017 training data only',
               'rule': {'min_failures': 3, 'login_window_minutes': 5, 'followup_minutes': 10},
               'evidence_sha256': audit['sha256'], 'findings': findings,
               'interpretation': 'Rule matches identify sessions for review; they do not prove intrusion, exfiltration, or identity.'}
    write_json(BASE / 'summary.json', summary)
    print('Saved summary.json. Verify event IDs against both original CSV files.')
    for item in findings:
        print(f"{item['success_id']} {item['username']} {item['session_id']}: "
              f"{len(item['failure_ids'])} failures, {item['download_count']} downloads, "
              f"{item['total_bytes']} bytes")

if __name__ == '__main__':
    main()
