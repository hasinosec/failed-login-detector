"""Detect possible brute-force attacks from authentication log entries.

Expected log format:
YYYY-MM-DD HH:MM:SS event=<login_failed|login_success> user=<name> ip=<address>
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"event=(?P<event>\w+) user=(?P<user>\S+) ip=(?P<ip>\S+)$"
)


def parse_log(path: Path) -> list[tuple[datetime, str]]:
    """Return timestamps and IP addresses for failed-login events."""
    failed_logins = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = LOG_PATTERN.match(raw_line.strip())
        if not match:
            print(f"Warning: skipped invalid line {line_number}")
            continue
        if match["event"] == "login_failed":
            failed_logins.append(
                (datetime.strptime(match["timestamp"], "%Y-%m-%d %H:%M:%S"), match["ip"])
            )
    return sorted(failed_logins)


def find_brute_force_attempts(
    failed_logins: list[tuple[datetime, str]], threshold: int, window_minutes: int
) -> dict[str, tuple[int, datetime, datetime]]:
    """Find IPs with `threshold` failures inside the chosen time window."""
    attempts_by_ip = defaultdict(list)
    for timestamp, ip_address in failed_logins:
        attempts_by_ip[ip_address].append(timestamp)

    alerts = {}
    window = timedelta(minutes=window_minutes)
    for ip_address, timestamps in attempts_by_ip.items():
        for start_index, start_time in enumerate(timestamps):
            matching_times = [time for time in timestamps[start_index:] if time - start_time <= window]
            if len(matching_times) >= threshold:
                alerts[ip_address] = (len(matching_times), start_time, matching_times[-1])
                break
    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect possible brute-force login attempts.")
    parser.add_argument("log_file", type=Path, help="Path to an authentication log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts needed for an alert (default: 5)")
    parser.add_argument("--window", type=int, default=10, help="Time window in minutes (default: 10)")
    args = parser.parse_args()

    if args.threshold < 1 or args.window < 1:
        parser.error("--threshold and --window must both be positive numbers")
    if not args.log_file.is_file():
        parser.error(f"File not found: {args.log_file}")

    alerts = find_brute_force_attempts(parse_log(args.log_file), args.threshold, args.window)
    if not alerts:
        print("No brute-force patterns detected.")
        return

    print("SECURITY ALERT: possible brute-force activity detected")
    for ip_address, (count, start_time, end_time) in alerts.items():
        print(f"- IP: {ip_address} | failed attempts: {count} | period: {start_time} to {end_time}")


if __name__ == "__main__":
    main()
