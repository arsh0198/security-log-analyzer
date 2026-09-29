"""Reporting and formatting module for Security Log Analyzer."""

import csv
import json
from pathlib import Path
from typing import Any, List, Sequence

from .detector import DetectionReport
from .parser import ParseResult


class SecurityReporter:
    """Formats and prints security analysis reports to the console and exports to files."""

    @staticmethod
    def _format_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
        """Format tabular data into an ASCII table without external dependencies."""
        if not rows:
            return "  (No data to display)\n"

        # Convert all cells to strings
        str_rows = [[str(cell) for cell in row] for row in rows]
        col_widths = [len(h) for h in headers]

        for row in str_rows:
            for idx, cell in enumerate(row):
                if idx < len(col_widths):
                    col_widths[idx] = max(col_widths[idx], len(cell))
                else:
                    col_widths.append(len(cell))

        # Format header and divider
        header_line = "  " + " | ".join(
            h.ljust(col_widths[i]) for i, h in enumerate(headers)
        )
        divider_line = "  " + "-+-".join("-" * col_widths[i] for i in range(len(headers)))

        # Format rows
        formatted_rows = [
            "  " + " | ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row))
            for row in str_rows
        ]

        return "\n".join([header_line, divider_line] + formatted_rows) + "\n"

    def print_ingestion_summary(self, result: ParseResult, log_path: str | Path) -> None:
        """Print summary of log file parsing and ingestion."""
        print("\n" + "=" * 65)
        print("  LOG FILE INGESTION SUMMARY")
        print("=" * 65)
        print(f"  Target File:     {log_path}")
        print(f"  Total Lines:     {result.total_lines}")
        print(f"  Valid Events:    {result.parsed_count}")
        print(f"  Skipped Lines:   {result.skipped_count} (comments & blank lines)")
        print(f"  Parsing Errors:  {result.error_count}")

        if result.errors:
            print("\n  [!] Parser Error Warnings:")
            for err in result.errors[:10]:
                print(f"    - Line {err.line_number}: {err.reason}")
                print(f"      Content: '{err.raw_line}'")
            if len(result.errors) > 10:
                print(f"    ... and {len(result.errors) - 10} more parsing errors.")
        print("=" * 65 + "\n")

    def print_security_report(self, report: DetectionReport) -> None:
        """Print the complete security analysis report."""
        summary = report.summary

        print("\n" + "=" * 75)
        print("                 SECURITY LOG ANALYZER - INCIDENT REPORT")
        print("=" * 75)

        # 1. High-level Summary Dashboard
        print("\n[+] 1. EXECUTIVE METRICS DASHBOARD")
        print("-" * 75)
        print(f"  Total Events Analyzed:  {summary.total_events:,}")
        print(f"  Successful Logins:      {summary.successful_logins:,}")
        print(f"  Failed Logins:          {summary.failed_logins:,}")
        print(f"  Global Failure Rate:    {summary.failure_rate_percent}%")
        print(f"  Unique Source IPs:      {summary.unique_ips_count}")
        print(f"  Unique Usernames:       {summary.unique_users_count}")
        if summary.first_event_time and summary.last_event_time:
            print(f"  Activity Window:        {summary.first_event_time} --> {summary.last_event_time}")

        # 2. Top Suspicious IPs
        print("\n[+] 2. TOP SUSPICIOUS SOURCE IPs")
        print("-" * 75)
        ip_headers = ["Rank", "Source IP", "Failures", "Successes", "Targeted Accounts"]
        ip_rows = [
            [idx, ip.source_ip, ip.failures, ip.successes, ip.unique_targets]
            for idx, ip in enumerate(report.top_suspicious_ips, start=1)
        ]
        print(self._format_table(ip_headers, ip_rows))

        # 3. Most Targeted Usernames
        print("[+] 3. MOST TARGETED USERNAMES")
        print("-" * 75)
        user_headers = ["Rank", "Username", "Failures", "Successes", "Distinct Origin IPs"]
        user_rows = [
            [idx, u.username, u.failures, u.successes, u.unique_ips]
            for idx, u in enumerate(report.top_targeted_users, start=1)
        ]
        print(self._format_table(user_headers, user_rows))

        # 4. Critical Detection: Potential Compromised Logins (Success after Failures)
        print("[!] 4. CRITICAL: SUCCESSFUL LOGINS AFTER MULTIPLE FAILURES")
        print("    (Indicator of Brute-Force Success / Account Takeover)")
        print("-" * 75)
        if report.compromised_logins:
            comp_headers = ["Source IP", "Username", "Service", "Preceding Fails", "Compromise Time"]
            comp_rows = [
                [
                    cl.source_ip,
                    cl.username,
                    cl.event_type,
                    cl.preceding_failures,
                    cl.success_time,
                ]
                for cl in report.compromised_logins
            ]
            print(self._format_table(comp_headers, comp_rows))
        else:
            print("  [OK] No compromised login patterns detected.\n")

        # 5. Detection: Password Spraying Attacks
        print("[!] 5. HIGH: PASSWORD SPRAYING / CREDENTIAL STUFFING")
        print("    (Single IP attempting logins against multiple distinct users)")
        print("-" * 75)
        if report.password_spraying:
            spray_headers = ["Source IP", "Unique Targets", "Total Tries", "Failures", "Sample Usernames"]
            spray_rows = [
                [
                    ps.source_ip,
                    ps.unique_usernames_count,
                    ps.total_attempts,
                    ps.failure_count,
                    ", ".join(ps.usernames_targeted[:4]) + ("..." if len(ps.usernames_targeted) > 4 else ""),
                ]
                for ps in report.password_spraying
            ]
            print(self._format_table(spray_headers, spray_rows))
        else:
            print("  [OK] No password spraying activity detected.\n")

        # 6. Detection: IPs with Unusually High Failure Counts
        print("[!] 6. HIGH: IPs WITH ELEVATED FAILURE VOLUMES")
        print("    (High volume failure anomalies)")
        print("-" * 75)
        if report.high_failure_ips:
            hf_headers = ["Source IP", "Total Failures", "Target Users", "First Failure", "Last Failure"]
            hf_rows = [
                [
                    hf.source_ip,
                    hf.failure_count,
                    hf.distinct_usernames_targeted,
                    hf.first_failure,
                    hf.last_failure,
                ]
                for hf in report.high_failure_ips
            ]
            print(self._format_table(hf_headers, hf_rows))
        else:
            print("  [OK] No IPs exceeded high failure threshold.\n")

        # 7. Detection: Repeated Failed Logins (Brute Force by IP & User)
        print("[!] 7. MEDIUM: REPEATED FAILED LOGINS BY TARGET")
        print("    (Targeted account brute-force attempts)")
        print("-" * 75)
        if report.repeated_failures:
            rf_headers = ["Source IP", "Target Username", "Failures", "First Failure", "Last Failure"]
            rf_rows = [
                [
                    rf.source_ip,
                    rf.username,
                    rf.failure_count,
                    rf.first_failure,
                    rf.last_failure,
                ]
                for rf in report.repeated_failures
            ]
            print(self._format_table(rf_headers, rf_rows))
        else:
            print("  [OK] No repeated failed login thresholds exceeded.\n")

        print("=" * 75)
        print("                       END OF SECURITY REPORT")
        print("=" * 75 + "\n")

    def export_json(self, report: DetectionReport, output_path: str | Path) -> None:
        """Export detection report to a JSON file."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"[+] Security report successfully exported to JSON: {out.resolve()}")

    def export_csv_summary(self, report: DetectionReport, output_path: str | Path) -> None:
        """Export high failure and suspicious IP findings to CSV."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["category", "source_ip", "username", "count", "details"])

            for hf in report.high_failure_ips:
                writer.writerow(["high_failure_ip", hf.source_ip, "ALL", hf.failure_count, f"targets={hf.distinct_usernames_targeted}"])

            for cl in report.compromised_logins:
                writer.writerow(["compromised_login", cl.source_ip, cl.username, cl.preceding_failures, f"success_time={cl.success_time}"])

            for ps in report.password_spraying:
                writer.writerow(["password_spray", ps.source_ip, ";".join(ps.usernames_targeted), ps.unique_usernames_count, f"attempts={ps.total_attempts}"])

            for rf in report.repeated_failures:
                writer.writerow(["repeated_failure", rf.source_ip, rf.username, rf.failure_count, f"{rf.first_failure} to {rf.last_failure}"])

        print(f"[+] Findings successfully exported to CSV: {out.resolve()}")
