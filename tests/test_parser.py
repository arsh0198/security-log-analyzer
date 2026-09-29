"""Unit tests for the log parser and validation models."""

import os
from pathlib import Path
import tempfile
import unittest

from src.models import AuthEvent, ValidationError
from src.parser import LogParser


class TestLogParser(unittest.TestCase):
    """Test suite for AuthEvent validation and LogParser parsing."""

    def setUp(self) -> None:
        self.parser = LogParser()

    def test_valid_pipe_log_line(self) -> None:
        line = "2026-09-29 08:00:12 | 192.168.1.50 | alice | SSH_LOGIN | SUCCESS"
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.timestamp, "2026-09-29 08:00:12")
        self.assertEqual(event.source_ip, "192.168.1.50")
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.event_type, "SSH_LOGIN")
        self.assertEqual(event.status, "SUCCESS")

    def test_valid_dash_log_line(self) -> None:
        line = "2026-09-29 08:00:12 - 10.0.0.1 - bob - WEB_AUTH - FAILURE"
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.timestamp, "2026-09-29 08:00:12")
        self.assertEqual(event.source_ip, "10.0.0.1")
        self.assertEqual(event.username, "bob")
        self.assertEqual(event.event_type, "WEB_AUTH")
        self.assertEqual(event.status, "FAILURE")

    def test_comments_and_blank_lines(self) -> None:
        self.assertIsNone(self.parser.parse_line(""))
        self.assertIsNone(self.parser.parse_line("   \n"))
        self.assertIsNone(self.parser.parse_line("# This is a comment"))
        self.assertIsNone(self.parser.parse_line("// Another comment"))

    def test_invalid_ip_raises_validation_error(self) -> None:
        line = "2026-09-29 08:00:12 | 999.999.999.999 | alice | SSH_LOGIN | SUCCESS"
        with self.assertRaises(ValidationError) as ctx:
            self.parser.parse_line(line)
        self.assertIn("Invalid IP address", str(ctx.exception))

    def test_invalid_timestamp_raises_validation_error(self) -> None:
        line = "not-a-date | 192.168.1.50 | alice | SSH_LOGIN | SUCCESS"
        with self.assertRaises(ValidationError) as ctx:
            self.parser.parse_line(line)
        self.assertIn("Invalid timestamp format", str(ctx.exception))

    def test_invalid_status_raises_validation_error(self) -> None:
        line = "2026-09-29 08:00:12 | 192.168.1.50 | alice | SSH_LOGIN | PENDING"
        with self.assertRaises(ValidationError) as ctx:
            self.parser.parse_line(line)
        self.assertIn("Invalid status", str(ctx.exception))

    def test_empty_username_raises_validation_error(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            AuthEvent.create(
                timestamp_str="2026-09-29 08:00:12",
                source_ip="192.168.1.50",
                username="   ",
                event_type="SSH_LOGIN",
                status="SUCCESS",
            )
        self.assertIn("Username cannot be empty", str(ctx.exception))

    def test_malformed_pipe_count(self) -> None:
        line = "2026-09-29 08:00:12 | 192.168.1.50 | alice | SSH_LOGIN"
        with self.assertRaises(ValidationError) as ctx:
            self.parser.parse_line(line)
        self.assertIn("Malformed line structure", str(ctx.exception))

    def test_parse_file_with_mixed_content(self) -> None:
        content = (
            "# Header comment\n"
            "2026-09-29 08:00:12 | 192.168.1.50 | alice | SSH_LOGIN | SUCCESS\n"
            "\n"
            "INVALID_CORRUPTED_LINE\n"
            "2026-09-29 08:01:00 | 192.168.1.51 | bob | SSH_LOGIN | FAILURE\n"
            "2026-09-29 08:02:00 | 888.888.888.888 | bad_ip | SSH_LOGIN | FAILURE\n"
        )
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            result = self.parser.parse_file(tmp_path)
            self.assertEqual(result.total_lines, 6)
            self.assertEqual(result.parsed_count, 2)
            self.assertEqual(result.skipped_count, 2)
            self.assertEqual(result.error_count, 2)
            self.assertEqual(len(result.errors), 2)
            self.assertEqual(result.errors[0].line_number, 4)
            self.assertEqual(result.errors[1].line_number, 6)
        finally:
            os.remove(tmp_path)

    def test_missing_file_raises_error(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.parser.parse_file("nonexistent_path_to_file.log")


if __name__ == "__main__":
    unittest.main()
