#!/usr/bin/env python3
"""Security Log Analyzer - CLI Entrypoint.

Analyzes authentication server logs for suspicious activity and security anomalies.
"""

import argparse
import sys
from pathlib import Path

from src.database import DatabaseManager
from src.detector import SecurityDetector
from src.parser import LogParser
from src.reporter import SecurityReporter


def build_argument_parser() -> argparse.ArgumentParser:
    """Configure command-line arguments and flags."""
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Security Log Analyzer: Ingest authentication logs and detect brute-force, password spraying, and compromised accounts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Ingest a log file into the database
  python analyzer.py --log data/sample.log

  # Generate the comprehensive security incident report
  python analyzer.py --report

  # Ingest and report in a single command
  python analyzer.py --log data/sample.log --report

  # Ingest using a custom database and export report to JSON
  python analyzer.py --log data/sample.log --report --db custom.db --export-json output.json

  # Adjust detection sensitivity thresholds
  python analyzer.py --report --failed-threshold 2 --spray-threshold 4
        """,
    )

    # Core actions
    parser.add_argument(
        "--log",
        type=str,
        metavar="PATH",
        help="Path to the authentication log file to import and store.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Analyze stored events and generate a formatted security report.",
    )

    # Database options
    parser.add_argument(
        "--db",
        type=str,
        default="logs.db",
        metavar="PATH",
        help="Path to SQLite database file (default: logs.db).",
    )
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="Clear existing events from the database before performing actions.",
    )

    # Threshold options
    parser.add_argument(
        "--failed-threshold",
        type=int,
        default=3,
        metavar="N",
        help="Minimum failed logins for repeated failure alert (default: 3).",
    )
    parser.add_argument(
        "--high-fail-threshold",
        type=int,
        default=5,
        metavar="N",
        help="Minimum failed logins for high failure IP alert (default: 5).",
    )
    parser.add_argument(
        "--spray-threshold",
        type=int,
        default=3,
        metavar="N",
        help="Minimum distinct usernames targeted from one IP for spray alert (default: 3).",
    )
    parser.add_argument(
        "--compromise-threshold",
        type=int,
        default=2,
        metavar="N",
        help="Minimum preceding failures before success for compromise alert (default: 2).",
    )

    # Export options
    parser.add_argument(
        "--export-json",
        type=str,
        metavar="FILE",
        help="Export security analysis results to JSON file.",
    )
    parser.add_argument(
        "--export-csv",
        type=str,
        metavar="FILE",
        help="Export findings summary to CSV file.",
    )

    return parser


def main() -> int:
    """Main CLI execution flow."""
    parser = build_argument_parser()

    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return 0

    args = parser.parse_args()

    # Validate that at least one action is requested
    if not args.log and not args.report and not args.reset_db:
        print(
            "[-] Error: Please specify an action such as --log <path> or --report.",
            file=sys.stderr,
        )
        print("    Run 'python analyzer.py --help' for usage guidance.", file=sys.stderr)
        return 1

    try:
        # Initialize database
        db_manager = DatabaseManager(args.db)
        reporter = SecurityReporter()

        # Handle DB reset if requested
        if args.reset_db:
            db_manager.clear_events()
            print(f"[+] Database '{args.db}' has been cleared.")

        # Ingestion step
        if args.log:
            log_file = Path(args.log)
            if not log_file.exists():
                print(f"[-] Error: Log file does not exist: {log_file}", file=sys.stderr)
                return 1
            if not log_file.is_file():
                print(f"[-] Error: Path is not a regular file: {log_file}", file=sys.stderr)
                return 1

            parser_engine = LogParser()
            parse_result = parser_engine.parse_file(log_file)

            # Persist valid events
            inserted = db_manager.insert_events(parse_result.events)
            reporter.print_ingestion_summary(parse_result, log_file)
            print(f"[+] Ingestion complete. Stored {inserted:,} new events in '{args.db}'.")

        # Security Reporting step
        if args.report:
            total_events = db_manager.get_total_events_count()
            if total_events == 0:
                print(
                    f"[-] Notice: Database '{args.db}' contains 0 events. "
                    "Import a log file first using: python analyzer.py --log <path>",
                    file=sys.stderr,
                )
                return 0

            detector = SecurityDetector(db_manager)
            report = detector.run_full_analysis(
                repeated_failure_threshold=args.failed_threshold,
                high_failure_ip_threshold=args.high_fail_threshold,
                compromise_min_failures=args.compromise_threshold,
                spray_min_users=args.spray_threshold,
            )

            # Display formatted terminal report
            reporter.print_security_report(report)

            # Optional exports
            if args.export_json:
                reporter.export_json(report, args.export_json)

            if args.export_csv:
                reporter.export_csv_summary(report, args.export_csv)

        return 0

    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[-] Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
