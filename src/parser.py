"""Log file parsing module for authentication events."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import List, Optional

from .models import AuthEvent, ValidationError


@dataclass
class ParseError:
    """Details about a line that failed to parse."""
    line_number: int
    raw_line: str
    reason: str


@dataclass
class ParseResult:
    """Overall outcome of parsing a log file."""
    events: List[AuthEvent] = field(default_factory=list)
    total_lines: int = 0
    parsed_count: int = 0
    error_count: int = 0
    skipped_count: int = 0
    errors: List[ParseError] = field(default_factory=list)


class LogParser:
    """Parser for authentication log files with validation and error reporting."""

    # Matches pipe-delimited format: TIMESTAMP | IP | USERNAME | EVENT_TYPE | STATUS
    # Optional leading/trailing whitespace around fields
    PIPE_PATTERN = re.compile(
        r"^(?P<timestamp>[\d\-]+(?:\s|T)[\d:]+(?:Z|[+-]\d{2}:?\d{2})?)\s*\|\s*"
        r"(?P<ip>[^\s|]+)\s*\|\s*"
        r"(?P<username>[^\s|]+)\s*\|\s*"
        r"(?P<event_type>[^\s|]+)\s*\|\s*"
        r"(?P<status>[^\s|]+)$"
    )

    # Secondary pattern: dash-separated format: TIMESTAMP - IP - USERNAME - EVENT_TYPE - STATUS
    DASH_PATTERN = re.compile(
        r"^(?P<timestamp>[\d\-]+(?:\s|T)[\d:]+(?:Z|[+-]\d{2}:?\d{2})?)\s+-\s+"
        r"(?P<ip>\S+)\s+-\s+"
        r"(?P<username>\S+)\s+-\s+"
        r"(?P<event_type>\S+)\s+-\s+"
        r"(?P<status>\S+)$"
    )

    def parse_line(self, line: str, line_num: int = 0) -> Optional[AuthEvent]:
        """Parse a single raw log line into an AuthEvent.

        Raises ValidationError if line format or fields are invalid.
        Returns None if line is blank or a comment.
        """
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            return None

        # Try pipe delimiter first
        match = self.PIPE_PATTERN.match(stripped)
        if not match:
            # Try dash delimiter
            match = self.DASH_PATTERN.match(stripped)

        if not match:
            # Check if there are pipes but incorrect count of fields
            parts = [p.strip() for p in stripped.split("|")]
            if len(parts) != 5:
                raise ValidationError(
                    f"Malformed line structure. Expected 5 pipe-delimited fields, got {len(parts)}."
                )
            # If 5 parts, use them directly
            ts, ip, user, event, status = parts
            return AuthEvent.create(
                timestamp_str=ts,
                source_ip=ip,
                username=user,
                event_type=event,
                status=status,
                raw_log=stripped,
            )

        groups = match.groupdict()
        return AuthEvent.create(
            timestamp_str=groups["timestamp"],
            source_ip=groups["ip"],
            username=groups["username"],
            event_type=groups["event_type"],
            status=groups["status"],
            raw_log=stripped,
        )

    def parse_file(self, file_path: str | Path) -> ParseResult:
        """Read and parse all entries in a log file.

        Handles missing files and recording line-by-line errors gracefully.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {path}")

        result = ParseResult()

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f, start=1):
                result.total_lines += 1
                try:
                    event = self.parse_line(line, line_num=idx)
                    if event is None:
                        result.skipped_count += 1
                    else:
                        result.events.append(event)
                        result.parsed_count += 1
                except ValidationError as e:
                    result.error_count += 1
                    result.errors.append(
                        ParseError(line_number=idx, raw_line=line.strip(), reason=str(e))
                    )
                except Exception as e:
                    result.error_count += 1
                    result.errors.append(
                        ParseError(
                            line_number=idx,
                            raw_line=line.strip(),
                            reason=f"Unexpected parsing error: {e}",
                        )
                    )

        return result
