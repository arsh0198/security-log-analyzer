"""Unit tests for the SQL security detection rules and detector engine."""

import unittest

from src.database import DatabaseManager
from src.detector import SecurityDetector
from src.models import AuthEvent


class TestSecurityDetector(unittest.TestCase):
    """Test suite for SecurityDetector SQL intrusion queries."""

    def setUp(self) -> None:
        self.db = DatabaseManager(":memory:")
        self.detector = SecurityDetector(self.db)

    def tearDown(self) -> None:
        self.db.close()

    def test_empty_database_metrics(self) -> None:
        summary = self.detector.get_security_summary()
        self.assertEqual(summary.total_events, 0)
        self.assertEqual(summary.successful_logins, 0)
        self.assertEqual(summary.failed_logins, 0)
        self.assertEqual(summary.failure_rate_percent, 0.0)

        report = self.detector.run_full_analysis()
        self.assertEqual(len(report.repeated_failures), 0)
        self.assertEqual(len(report.high_failure_ips), 0)
        self.assertEqual(len(report.compromised_logins), 0)
        self.assertEqual(len(report.password_spraying), 0)

    def test_repeated_failed_logins_detection(self) -> None:
        # IP 192.168.1.10 tries admin 3 times (fails)
        # IP 192.168.1.11 tries admin 2 times (fails)
        events = [
            AuthEvent.create("2026-09-29 10:00:01", "192.168.1.10", "admin", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 10:00:02", "192.168.1.10", "admin", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 10:00:03", "192.168.1.10", "admin", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 10:00:04", "192.168.1.11", "admin", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 10:00:05", "192.168.1.11", "admin", "SSH", "FAILURE"),
        ]
        self.db.insert_events(events)

        alerts = self.detector.detect_repeated_failed_logins(threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "192.168.1.10")
        self.assertEqual(alerts[0].username, "admin")
        self.assertEqual(alerts[0].failure_count, 3)

    def test_high_failure_ips_detection(self) -> None:
        # IP 10.0.0.99 produces 5 failures across distinct users
        events = [
            AuthEvent.create("2026-09-29 11:00:01", "10.0.0.99", "user1", "WEB", "FAILURE"),
            AuthEvent.create("2026-09-29 11:00:02", "10.0.0.99", "user2", "WEB", "FAILURE"),
            AuthEvent.create("2026-09-29 11:00:03", "10.0.0.99", "user3", "WEB", "FAILURE"),
            AuthEvent.create("2026-09-29 11:00:04", "10.0.0.99", "user4", "WEB", "FAILURE"),
            AuthEvent.create("2026-09-29 11:00:05", "10.0.0.99", "user5", "WEB", "FAILURE"),
            # Low failure IP
            AuthEvent.create("2026-09-29 11:00:06", "10.0.0.50", "user1", "WEB", "FAILURE"),
        ]
        self.db.insert_events(events)

        alerts = self.detector.detect_high_failure_ips(threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "10.0.0.99")
        self.assertEqual(alerts[0].failure_count, 5)
        self.assertEqual(alerts[0].distinct_usernames_targeted, 5)

    def test_success_after_multiple_failures_detection(self) -> None:
        # Scenario A: 3 failures then SUCCESS (Compromise alert)
        # Scenario B: 1 failure then SUCCESS (Should be filtered out when threshold=2)
        events = [
            # IP 172.16.0.5 attacking victim_a
            AuthEvent.create("2026-09-29 12:00:00", "172.16.0.5", "victim_a", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 12:00:10", "172.16.0.5", "victim_a", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 12:00:20", "172.16.0.5", "victim_a", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 12:00:30", "172.16.0.5", "victim_a", "SSH", "SUCCESS"),

            # IP 172.16.0.9 normal user minor typo (1 failure then success)
            AuthEvent.create("2026-09-29 12:05:00", "172.16.0.9", "victim_b", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 12:05:10", "172.16.0.9", "victim_b", "SSH", "SUCCESS"),
        ]
        self.db.insert_events(events)

        alerts = self.detector.detect_success_after_failures(min_failures=2)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "172.16.0.5")
        self.assertEqual(alerts[0].username, "victim_a")
        self.assertEqual(alerts[0].preceding_failures, 3)
        self.assertEqual(alerts[0].success_time, "2026-09-29 12:00:30")

    def test_password_spraying_detection(self) -> None:
        # Attacker 192.0.2.10 targets 4 different usernames
        # Regular user 192.168.1.20 targets only 1 username
        events = [
            AuthEvent.create("2026-09-29 13:00:00", "192.0.2.10", "admin", "API", "FAILURE"),
            AuthEvent.create("2026-09-29 13:00:05", "192.0.2.10", "root", "API", "FAILURE"),
            AuthEvent.create("2026-09-29 13:00:10", "192.0.2.10", "service", "API", "FAILURE"),
            AuthEvent.create("2026-09-29 13:00:15", "192.0.2.10", "dev", "API", "FAILURE"),

            AuthEvent.create("2026-09-29 13:05:00", "192.168.1.20", "alice", "API", "SUCCESS"),
            AuthEvent.create("2026-09-29 13:06:00", "192.168.1.20", "alice", "API", "SUCCESS"),
        ]
        self.db.insert_events(events)

        alerts = self.detector.detect_password_spraying(min_unique_users=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "192.0.2.10")
        self.assertEqual(alerts[0].unique_usernames_count, 4)
        self.assertEqual(alerts[0].failure_count, 4)
        self.assertEqual(alerts[0].total_attempts, 4)
        self.assertIn("admin", alerts[0].usernames_targeted)
        self.assertIn("root", alerts[0].usernames_targeted)

    def test_top_rankings_metrics(self) -> None:
        events = [
            AuthEvent.create("2026-09-29 14:00:00", "10.0.0.1", "userA", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 14:00:01", "10.0.0.1", "userA", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 14:00:02", "10.0.0.2", "userB", "SSH", "FAILURE"),
            AuthEvent.create("2026-09-29 14:00:03", "10.0.0.3", "userC", "SSH", "SUCCESS"),
        ]
        self.db.insert_events(events)

        top_ips = self.detector.get_top_suspicious_ips(limit=2)
        self.assertEqual(len(top_ips), 2)
        self.assertEqual(top_ips[0].source_ip, "10.0.0.1")
        self.assertEqual(top_ips[0].failures, 2)

        top_users = self.detector.get_top_targeted_usernames(limit=2)
        self.assertEqual(len(top_users), 2)
        self.assertEqual(top_users[0].username, "userA")
        self.assertEqual(top_users[0].failures, 2)


if __name__ == "__main__":
    unittest.main()
