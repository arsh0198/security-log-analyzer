# Security Log Analyzer

A beginner-to-intermediate educational cybersecurity project built with Python and SQLite. The application parses authentication and server log files, stores structured security events in a relational database, executes SQL-driven threat detection queries, and generates incident response summary reports.

---

## Table of Contents

- [Overview](#overview)
- [Architecture & Modular Design](#architecture--modular-design)
- [Database Schema & Indexing](#database-schema--indexing)
- [Threat Detection Rules & SQL Queries](#threat-detection-rules--sql-queries)
  - [1. Repeated Failed Logins (Brute Force)](#1-repeated-failed-logins-brute-force)
  - [2. High Failure Volume IPs](#2-high-failure-volume-ips)
  - [3. Successful Login After Multiple Failures (Compromised Account)](#3-successful-login-after-multiple-failures-compromised-account)
  - [4. Password Spraying / Credential Stuffing](#4-password-spraying--credential-stuffing)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Installation & Requirements](#installation--requirements)
- [CLI Usage & Command Reference](#cli-usage--command-reference)
- [Example Report Output](#example-report-output)
- [Running Unit Tests](#running-unit-tests)
- [Project Directory Structure](#project-directory-structure)

---

## Overview

Security Operations Centers (SOCs) and incident responders regularly analyze authentication telemetry to identify adversary activity. 

This project simulates how a security pipeline operates without relying on third-party cloud services or external APIs:
1. **Ingest & Sanitize**: Reads raw server logs, validates IP addresses, normalizes timestamps, and filters corrupted records.
2. **Relational Storage**: Persists validated events in SQLite with optimized B-tree indexes for fast analytical querying.
3. **Detection Engine**: Executes SQL queries that model real-world intrusion patterns.
4. **Actionable Reporting**: Outputs human-readable terminal reports and exports structured findings to JSON and CSV.

---

## Architecture & Modular Design

The project separates concerns across specialized modules:

```text
       Raw Log File (sample.log)
                  │
                  ▼
         [ src/parser.py ] ◄── Uses [ src/models.py ] (Validation: IP, Timestamp, Status)
                  │
                  ▼ Valid AuthEvents
        [ src/database.py ] ──► SQLite (logs.db with multi-column indexes)
                  │
                  ▼ SQL Queries
        [ src/detector.py ] ──► Threat Detection Engine (4 Intrusion Patterns)
                  │
                  ▼ Structured DetectionReport
        [ src/reporter.py ] ──► CLI Terminal Tables / JSON / CSV Exports
                  │
                  ▲
           analyzer.py (CLI Entrypoint)
```

- **`src/models.py`**: Declares immutable `AuthEvent` dataclass and enforces strict data validation (RFC-compliant IP validation via `ipaddress`, ISO timestamps, status normalization).
- **`src/parser.py`**: Fault-tolerant log reader. Captures malformed lines and provides detailed diagnostics rather than crashing.
- **`src/database.py`**: Manages SQLite connections, executes DDL scripts, creates indexes, and performs batch insertions using transactions (`executemany`).
- **`src/detector.py`**: Implements SQL queries that flag anomalies and security alerts.
- **`src/reporter.py`**: Renders formatted ASCII dashboards, alert tables, and file export helpers.
- **`analyzer.py`**: Command-line interface built using standard library `argparse`.

---

## Database Schema & Indexing

The application stores events in the `auth_events` table within a local SQLite database (`logs.db` by default):

```sql
CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    source_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'FAILURE')),
    raw_log TEXT
);
```

### Performance Indexing Strategy

Log analysis queries aggregate over millions of rows in enterprise environments. The following indexes ensure queries remain $O(\log N)$ or fast index scans:

| Index Name | Indexed Columns | Justification / Used By |
| :--- | :--- | :--- |
| `idx_events_ip` | `(source_ip)` | Accelerates per-IP filtering and IP aggregation |
| `idx_events_user` | `(username)` | Accelerates queries filtering for targeted accounts |
| `idx_events_status` | `(status)` | Speeds up filtering for `FAILURE` or `SUCCESS` |
| `idx_events_timestamp`| `(timestamp)` | Optimizes time-window calculations and time ordering |
| `idx_events_ip_user` | `(source_ip, username)` | Speeds up composite grouping in brute-force detection |
| `idx_events_ip_status`| `(source_ip, status)` | Fast index-only scans for failure count aggregations |

---

## Threat Detection Rules & SQL Queries

### 1. Repeated Failed Logins (Brute Force)
- **Concept**: An attacker targets a specific account from an IP address, trying multiple password combinations until threshold $N$ is reached.
- **SQL Implementation**:
```sql
SELECT
    source_ip,
    username,
    COUNT(*) AS failure_count,
    MIN(timestamp) AS first_failure,
    MAX(timestamp) AS last_failure
FROM auth_events
WHERE status = 'FAILURE'
GROUP BY source_ip, username
HAVING failure_count >= :threshold
ORDER BY failure_count DESC, last_failure DESC;
```

### 2. High Failure Volume IPs
- **Concept**: Anomalous hosts generating excessive failed authentication attempts across one or more accounts (e.g. automated scanners or dictionary attack bots).
- **SQL Implementation**:
```sql
SELECT
    source_ip,
    COUNT(*) AS failure_count,
    COUNT(DISTINCT username) AS distinct_usernames_targeted,
    MIN(timestamp) AS first_failure,
    MAX(timestamp) AS last_failure
FROM auth_events
WHERE status = 'FAILURE'
GROUP BY source_ip
HAVING failure_count >= :threshold
ORDER BY failure_count DESC, last_failure DESC;
```

### 3. Successful Login After Multiple Failures (Compromised Account)
- **Concept**: Repeated failed attempts followed by a success from the same IP/account pair. This indicates a potential brute-force success or account takeover.
- **SQL Implementation** (correlated subqueries & CTE):
```sql
WITH success_events AS (
    SELECT
        s.id,
        s.timestamp AS success_time,
        s.source_ip,
        s.username,
        s.event_type,
        COALESCE(
            (SELECT MAX(s_prev.timestamp)
             FROM auth_events s_prev
             WHERE s_prev.source_ip = s.source_ip
               AND s_prev.username = s.username
               AND s_prev.status = 'SUCCESS'
               AND (s_prev.timestamp < s.timestamp OR (s_prev.timestamp = s.timestamp AND s_prev.id < s.id))
            ),
            '1970-01-01 00:00:00'
        ) AS last_success_time
    FROM auth_events s
    WHERE s.status = 'SUCCESS'
)
SELECT
    se.source_ip,
    se.username,
    se.event_type,
    se.success_time,
    (
        SELECT COUNT(*)
        FROM auth_events f
        WHERE f.source_ip = se.source_ip
          AND f.username = se.username
          AND f.status = 'FAILURE'
          AND f.timestamp > se.last_success_time
          AND (f.timestamp < se.success_time OR (f.timestamp = se.success_time AND f.id < se.id))
    ) AS preceding_failures,
    (
        SELECT MIN(f.timestamp)
        FROM auth_events f
        WHERE f.source_ip = se.source_ip
          AND f.username = se.username
          AND f.status = 'FAILURE'
          AND f.timestamp > se.last_success_time
          AND (f.timestamp < se.success_time OR (f.timestamp = se.success_time AND f.id < se.id))
    ) AS streak_start_time
FROM success_events se
WHERE preceding_failures >= :threshold
ORDER BY se.success_time DESC;
```

### 4. Password Spraying / Credential Stuffing
- **Concept**: To avoid triggering account lockouts, attackers try common passwords across many different usernames from a single origin IP.
- **SQL Implementation**:
```sql
SELECT
    source_ip,
    COUNT(DISTINCT username) AS unique_usernames_count,
    GROUP_CONCAT(DISTINCT username) AS usernames_targeted,
    COUNT(*) AS total_attempts,
    SUM(CASE WHEN status = 'FAILURE' THEN 1 ELSE 0 END) AS failure_count,
    SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS success_count,
    MIN(timestamp) AS first_seen,
    MAX(timestamp) AS last_seen
FROM auth_events
GROUP BY source_ip
HAVING unique_usernames_count >= :threshold
ORDER BY unique_usernames_count DESC, total_attempts DESC;
```

---

## MITRE ATT&CK Mapping

| Detection Rule | MITRE ATT&CK Technique | ID |
| :--- | :--- | :--- |
| Repeated Failed Logins | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| High Failure Volume IPs | Network Service Discovery / Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) |
| Success After Multiple Failures | Valid Accounts: Local / Domain Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Activity with Multiple Users from One IP | Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |

---

## Installation & Requirements

- **Python**: 3.10 or later
- **Dependencies**: None (Uses Python standard library: `sqlite3`, `argparse`, `dataclasses`, `ipaddress`, `unittest`).

### Clone the Repository
```bash
git clone https://github.com/your-username/security-log-analyzer.git
cd security-log-analyzer
```

---

## CLI Usage & Command Reference

### Basic Commands

1. **Ingest a log file**:
   ```bash
   python analyzer.py --log data/sample.log
   ```

2. **Generate the incident report**:
   ```bash
   python analyzer.py --report
   ```

3. **Ingest and report in one command**:
   ```bash
   python analyzer.py --log data/sample.log --report
   ```

### Advanced Options

- **Specify a custom database**:
  ```bash
  python analyzer.py --log data/sample.log --db incidents.db --report
  ```

- **Reset / clear database**:
  ```bash
  python analyzer.py --reset-db
  ```

- **Adjust detection thresholds**:
  ```bash
  python analyzer.py --report \
      --failed-threshold 4 \
      --high-fail-threshold 8 \
      --spray-threshold 5 \
      --compromise-threshold 3
  ```

- **Export findings to JSON and CSV**:
  ```bash
  python analyzer.py --report --export-json report.json --export-csv findings.csv
  ```

### CLI Flag Reference

| Flag | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `--log` | `PATH` | Path to log file to import and persist | None |
| `--report` | None | Run detection engine and print report | Disabled |
| `--db` | `PATH` | Path to SQLite database | `logs.db` |
| `--reset-db` | None | Clear database before operations | Disabled |
| `--failed-threshold` | `INT` | Min failures for repeated failure alert | `3` |
| `--high-fail-threshold`| `INT` | Min failures for high failure IP alert | `5` |
| `--spray-threshold` | `INT` | Min unique users for password spray alert | `3` |
| `--compromise-threshold`| `INT` | Min failures preceding success for compromise | `2` |
| `--export-json` | `PATH` | File path to export report as JSON | None |
| `--export-csv` | `PATH` | File path to export findings as CSV | None |

---

## Example Report Output

Running `python analyzer.py --log data/sample.log --report` produces:

```text
===========================================================================
                 SECURITY LOG ANALYZER - INCIDENT REPORT
===========================================================================

[+] 1. EXECUTIVE METRICS DASHBOARD
---------------------------------------------------------------------------
  Total Events Analyzed:  44
  Successful Logins:      13
  Failed Logins:          31
  Global Failure Rate:    70.45%
  Unique Source IPs:      13
  Unique Usernames:       21
  Activity Window:        2026-09-29 08:00:12 --> 2026-09-29 08:45:00

[+] 2. TOP SUSPICIOUS SOURCE IPs
---------------------------------------------------------------------------
  Rank | Source IP     | Failures | Successes | Targeted Accounts
  -----+---------------+----------+-----------+------------------
  1    | 203.0.113.45  | 9        | 0         | 2                
  2    | 192.0.2.77    | 8        | 0         | 8                
  3    | 198.51.100.22 | 5        | 0         | 1                
  4    | 198.51.100.88 | 4        | 1         | 1                
  5    | 203.0.113.199 | 4        | 0         | 1                

[+] 3. MOST TARGETED USERNAMES
---------------------------------------------------------------------------
  Rank | Username       | Failures | Successes | Distinct Origin IPs
  -----+----------------+----------+-----------+--------------------
  1    | database_admin | 5        | 0         | 1                  
  2    | root           | 5        | 0         | 1                  
  3    | dev_user       | 4        | 1         | 1                  
  4    | admin          | 4        | 0         | 1                  
  5    | guest          | 4        | 0         | 1                  

[!] 4. CRITICAL: SUCCESSFUL LOGINS AFTER MULTIPLE FAILURES
    (Indicator of Brute-Force Success / Account Takeover)
---------------------------------------------------------------------------
  Source IP     | Username | Service   | Preceding Fails | Compromise Time    
  --------------+----------+-----------+-----------------+--------------------
  198.51.100.88 | dev_user | SSH_LOGIN | 4               | 2026-09-29 08:25:35

[!] 5. HIGH: PASSWORD SPRAYING / CREDENTIAL STUFFING
    (Single IP attempting logins against multiple distinct users)
---------------------------------------------------------------------------
  Source IP  | Unique Targets | Total Tries | Failures | Sample Usernames                      
  -----------+----------------+-------------+----------+---------------------------------------
  192.0.2.77 | 8              | 8           | 8        | ceo, cfo, hr_director, billing_dept...

[!] 6. HIGH: IPs WITH ELEVATED FAILURE VOLUMES
    (High volume failure anomalies)
---------------------------------------------------------------------------
  Source IP     | Total Failures | Target Users | First Failure       | Last Failure       
  --------------+----------------+--------------+---------------------+--------------------
  203.0.113.45  | 9              | 2            | 2026-09-29 08:15:01 | 2026-09-29 08:15:35
  192.0.2.77    | 8              | 8            | 2026-09-29 08:30:00 | 2026-09-29 08:30:35
  198.51.100.22 | 5              | 1            | 2026-09-29 08:20:00 | 2026-09-29 08:20:40

[!] 7. MEDIUM: REPEATED FAILED LOGINS BY TARGET
    (Targeted account brute-force attempts)
---------------------------------------------------------------------------
  Source IP     | Target Username | Failures | First Failure       | Last Failure       
  --------------+-----------------+----------+---------------------+--------------------
  198.51.100.22 | database_admin  | 5        | 2026-09-29 08:20:00 | 2026-09-29 08:20:40
  203.0.113.45  | root            | 5        | 2026-09-29 08:15:01 | 2026-09-29 08:15:16
  203.0.113.199 | guest           | 4        | 2026-09-29 08:35:10 | 2026-09-29 08:35:25
  198.51.100.88 | dev_user        | 4        | 2026-09-29 08:25:05 | 2026-09-29 08:25:27
  203.0.113.45  | admin           | 4        | 2026-09-29 08:15:21 | 2026-09-29 08:15:35

===========================================================================
                       END OF SECURITY REPORT
===========================================================================
```

---

## Running Unit Tests

Execute the automated test suite using Python's standard `unittest` framework:

```bash
python3 -m unittest discover -s tests -v
```

Output:
```text
test_empty_database_metrics (test_detector.TestSecurityDetector.test_empty_database_metrics) ... ok
test_high_failure_ips_detection (test_detector.TestSecurityDetector.test_high_failure_ips_detection) ... ok
test_password_spraying_detection (test_detector.TestSecurityDetector.test_password_spraying_detection) ... ok
test_repeated_failed_logins_detection (test_detector.TestSecurityDetector.test_repeated_failed_logins_detection) ... ok
test_success_after_multiple_failures_detection (test_detector.TestSecurityDetector.test_success_after_multiple_failures_detection) ... ok
test_top_rankings_metrics (test_detector.TestSecurityDetector.test_top_rankings_metrics) ... ok
test_comments_and_blank_lines (test_parser.TestLogParser.test_comments_and_blank_lines) ... ok
test_empty_username_raises_validation_error (test_parser.TestLogParser.test_empty_username_raises_validation_error) ... ok
test_invalid_ip_raises_validation_error (test_parser.TestLogParser.test_invalid_ip_raises_validation_error) ... ok
test_invalid_status_raises_validation_error (test_parser.TestLogParser.test_invalid_status_raises_validation_error) ... ok
test_invalid_timestamp_raises_validation_error (test_parser.TestLogParser.test_invalid_timestamp_raises_validation_error) ... ok
test_malformed_pipe_count (test_parser.TestLogParser.test_malformed_pipe_count) ... ok
test_missing_file_raises_error (test_parser.TestLogParser.test_missing_file_raises_error) ... ok
test_parse_file_with_mixed_content (test_parser.TestLogParser.test_parse_file_with_mixed_content) ... ok
test_valid_dash_log_line (test_parser.TestLogParser.test_valid_dash_log_line) ... ok
test_valid_pipe_log_line (test_parser.TestLogParser.test_valid_pipe_log_line) ... ok

----------------------------------------------------------------------
Ran 16 tests in 0.007s

OK
```

---

## Project Directory Structure

```text
pythonproject1/
├── analyzer.py               # Main CLI entrypoint
├── src/
│   ├── __init__.py           # Package indicator & metadata
│   ├── models.py             # Event dataclass & field validation (IP, datetime, status)
│   ├── parser.py             # File and line log parser with error diagnostics
│   ├── database.py           # SQLite connection & schema management
│   ├── detector.py           # SQL detection engine for security anomalies
│   └── reporter.py           # Terminal ASCII tables, metrics, and JSON/CSV export
├── tests/
│   ├── __init__.py           # Test package indicator
│   ├── test_parser.py        # 10 unit tests for parsing and validation
│   └── test_detector.py      # 6 unit tests for SQL detection rules
├── data/
│   └── sample.log            # Realistic authentication log dataset with attacks
├── .gitignore                # Standard Python & SQLite ignores
└── README.md                 # Complete documentation
```
