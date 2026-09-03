"""Tests for the failed-login brute-force detector."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from detect_failed_logins import find_brute_force_attempts, parse_log


def _ts(minute: int, second: int = 0) -> datetime:
    return datetime(2026, 8, 11, 9, minute, second)


def test_alerts_when_threshold_reached_inside_window():
    failed = [(_ts(0), "198.51.100.42")] + [(_ts(m), "198.51.100.42") for m in (1, 2, 4, 7)]
    alerts = find_brute_force_attempts(failed, threshold=5, window_minutes=10)
    assert "198.51.100.42" in alerts
    count, start, end = alerts["198.51.100.42"]
    assert count == 5
    assert start == _ts(0)
    assert end == _ts(7)


def test_no_alert_when_failures_spread_beyond_window():
    failed = [(_ts(0), "203.0.113.80"), (_ts(20), "203.0.113.80"), (_ts(45), "203.0.113.80")]
    assert find_brute_force_attempts(failed, threshold=3, window_minutes=10) == {}


def test_no_alert_below_threshold():
    failed = [(_ts(0), "192.0.2.25"), (_ts(1), "192.0.2.25")]
    assert find_brute_force_attempts(failed, threshold=5, window_minutes=10) == {}


def test_each_ip_evaluated_independently():
    failed = [(_ts(m), "10.0.0.1") for m in (0, 1, 2)] + [(_ts(m), "10.0.0.2") for m in (0, 1, 2)]
    alerts = find_brute_force_attempts(failed, threshold=3, window_minutes=10)
    assert set(alerts) == {"10.0.0.1", "10.0.0.2"}


def test_window_boundary_is_inclusive():
    failed = [(_ts(0), "10.0.0.9"), (_ts(5), "10.0.0.9"), (_ts(10), "10.0.0.9")]
    alerts = find_brute_force_attempts(failed, threshold=3, window_minutes=10)
    assert alerts["10.0.0.9"][0] == 3


def test_parse_log_reads_only_failed_events(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "\n".join(
            [
                "2026-08-11 08:15:02 event=login_success user=amina ip=203.0.113.10",
                "2026-08-11 09:00:12 event=login_failed user=admin ip=198.51.100.42",
                "2026-08-11 09:01:08 event=login_failed user=admin ip=198.51.100.42",
                "this line is not valid and should be skipped",
            ]
        ),
        encoding="utf-8",
    )
    failed = parse_log(log)
    assert [ip for _, ip in failed] == ["198.51.100.42", "198.51.100.42"]
    assert failed == sorted(failed)


def test_parse_log_sample_file_matches_repo_fixture():
    sample = Path(__file__).resolve().parent.parent / "sample_auth.log"
    alerts = find_brute_force_attempts(parse_log(sample), threshold=5, window_minutes=10)
    assert "198.51.100.42" in alerts


def test_zero_window_never_alerts_for_distinct_times():
    failed = [(_ts(0), "10.0.0.1"), (_ts(1), "10.0.0.1"), (_ts(2), "10.0.0.1")]
    assert find_brute_force_attempts(failed, threshold=2, window_minutes=0) == {}
