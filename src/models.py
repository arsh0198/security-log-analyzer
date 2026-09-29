"""Data models and validation logic for authentication events."""

from dataclasses import dataclass
from datetime import datetime
import ipaddress
from typing import Optional


class ValidationError(Exception):
    """Raised when an authentication event contains invalid fields."""
    pass


@dataclass(frozen=True)
class AuthEvent:
    """Represents a validated authentication event."""

    timestamp: str  # Format: YYYY-MM-DD HH:MM:SS
    source_ip: str
    username: str
    event_type: str
    status: str  # 'SUCCESS' or 'FAILURE'
    raw_log: Optional[str] = None

    @classmethod
    def create(
        cls,
        timestamp_str: str,
        source_ip: str,
        username: str,
        event_type: str,
        status: str,
        raw_log: Optional[str] = None,
    ) -> "AuthEvent":
        """Validate fields and construct an AuthEvent instance."""
        # 1. Validate & normalize Timestamp
        ts_clean = timestamp_str.strip()
        parsed_dt: Optional[datetime] = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                parsed_dt = datetime.strptime(ts_clean, fmt)
                break
            except ValueError:
                continue

        if parsed_dt is None:
            raise ValidationError(
                f"Invalid timestamp format: '{timestamp_str}'. Expected 'YYYY-MM-DD HH:MM:SS'."
            )
        normalized_timestamp = parsed_dt.strftime("%Y-%m-%d %H:%M:%S")

        # 2. Validate IP Address
        ip_clean = source_ip.strip()
        try:
            ipaddress.ip_address(ip_clean)
        except ValueError:
            raise ValidationError(f"Invalid IP address: '{source_ip}'.")

        # 3. Validate Username
        user_clean = username.strip()
        if not user_clean:
            raise ValidationError("Username cannot be empty.")

        # 4. Validate Event Type
        event_clean = event_type.strip().upper()
        if not event_clean:
            event_clean = "UNKNOWN_AUTH"

        # 5. Validate Status
        status_clean = status.strip().upper()
        if status_clean not in ("SUCCESS", "FAILURE"):
            raise ValidationError(
                f"Invalid status: '{status}'. Allowed values are 'SUCCESS' or 'FAILURE'."
            )

        return cls(
            timestamp=normalized_timestamp,
            source_ip=ip_clean,
            username=user_clean,
            event_type=event_clean,
            status=status_clean,
            raw_log=raw_log,
        )
