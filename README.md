# Failed Login Detector

A small Python security-monitoring project that analyses authentication logs and raises an alert when one IP address has repeated failed login attempts in a short period. This can indicate a possible brute-force attack.

## Why I built this

Security Operations teams monitor logs for suspicious activity and investigate alerts. This project demonstrates a simple version of that process using Python.

## Features

- Parses authentication log entries
- Groups failed login attempts by IP address
- Detects repeated failures within a configurable time window
- Prints clear security alerts for potential brute-force activity

## Run it

You need Python 3.10 or later. No external packages are required.

```bash
python3 detect_failed_logins.py sample_auth.log
```

Expected result:

```text
SECURITY ALERT: possible brute-force activity detected
- IP: 198.51.100.42 | failed attempts: 5 | period: 2026-08-11 09:00:12 to 2026-08-11 09:07:19
```

## Change the detection rule

The default alert rule is five failed attempts in ten minutes. You can change it:

```bash
python3 detect_failed_logins.py sample_auth.log --threshold 3 --window 5
```

## Example log format

```text
2026-08-11 09:00:12 event=login_failed user=admin ip=198.51.100.42
```

All data in `sample_auth.log` is fictional and uses documentation-only IP ranges.

## Industry context

This is a learning project that recreates a small part of a Security Operations Centre (SOC) workflow: collect authentication events, group them by source IP, apply a threshold within a time window, and raise an alert for an analyst to investigate.

Professional security teams commonly perform this work in SIEM and detection platforms such as **Elastic Security**, **Splunk**, and **Microsoft Sentinel**. This script is not a replacement for those platforms; it is a simple, transparent implementation of the core detection logic.

- Elastic Security documents threshold rules for detecting many failed logins from one source IP in a time window: [Elastic threshold-rule documentation](https://www.elastic.co/docs/solutions/security/detect-and-alert/threshold).
- Elastic also provides a prebuilt rule for spikes in failed authentication events: [Spike in Failed Logon Events](https://www.elastic.co/guide/en/security/current/spike-in-failed-logon-events.html).
- MITRE ATT&CK identifies brute force as technique **T1110**: [MITRE ATT&CK: Brute Force](https://attack.mitre.org/techniques/T1110/).

## What I would improve in production

In a real environment, I would ingest real log sources, store alerts centrally, add IP reputation and user context, tune thresholds to reduce false positives, and send high-confidence alerts to the incident-response team.
