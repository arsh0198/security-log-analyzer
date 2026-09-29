"""Detection engine executing SQL security queries on authentication logs."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .database import DatabaseManager


@dataclass
class RepeatedFailureAlert:
    """Alert for repeated failed logins against an account from an IP."""
    source_ip: str
    username: str
    failure_count: int
    first_failure: str
    last_failure: str


@dataclass
class HighFailureIPAlert:
    """Alert for an IP address generating an unusually high volume of failures."""
    source_ip: str
    failure_count: int
    distinct_usernames_targeted: int
    first_failure: str
    last_failure: str


@dataclass
class SuccessAfterFailureAlert:
    """Alert for a successful login preceded by multiple failed attempts (compromise indicator)."""
    source_ip: str
    username: str
    event_type: str
    success_time: str
    preceding_failures: int
    streak_start_time: str


@dataclass
class PasswordSprayAlert:
    """Alert for a single IP address attempting to authenticate against multiple usernames."""
    source_ip: str
    unique_usernames_count: int
    usernames_targeted: List[str]
    total_attempts: int
    failure_count: int
    success_count: int
    first_seen: str
    last_seen: str


@dataclass
class TopSuspiciousIP:
    """Metrics for the most suspicious IP addresses."""
    source_ip: str
    total_attempts: int
    failures: int
    successes: int
    unique_targets: int


@dataclass
class TopTargetedUser:
    """Metrics for the most frequently targeted usernames."""
    username: str
    total_attempts: int
    failures: int
    successes: int
    unique_ips: int


@dataclass
class SecuritySummary:
    """Overall security summary statistics."""
    total_events: int = 0
    successful_logins: int = 0
    failed_logins: int = 0
    failure_rate_percent: float = 0.0
    first_event_time: Optional[str] = None
    last_event_time: Optional[str] = None
    unique_ips_count: int = 0
    unique_users_count: int = 0


@dataclass
class DetectionReport:
    """Complete security analysis report containing summary and all alerts."""
    summary: SecuritySummary
    top_suspicious_ips: List[TopSuspiciousIP] = field(default_factory=list)
    top_targeted_users: List[TopTargetedUser] = field(default_factory=list)
    repeated_failures: List[RepeatedFailureAlert] = field(default_factory=list)
    high_failure_ips: List[HighFailureIPAlert] = field(default_factory=list)
    compromised_logins: List[SuccessAfterFailureAlert] = field(default_factory=list)
    password_spraying: List[PasswordSprayAlert] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to a dictionary suitable for JSON export."""
        return {
            "summary": self.summary.__dict__,
            "top_suspicious_ips": [ip.__dict__ for ip in self.top_suspicious_ips],
            "top_targeted_users": [u.__dict__ for u in self.top_targeted_users],
            "repeated_failures": [rf.__dict__ for rf in self.repeated_failures],
            "high_failure_ips": [hf.__dict__ for hf in self.high_failure_ips],
            "compromised_logins": [cl.__dict__ for cl in self.compromised_logins],
            "password_spraying": [ps.__dict__ for ps in self.password_spraying],
        }


class SecurityDetector:
    """Executes SQL security detection rules against stored authentication events."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db = db_manager

    def get_security_summary(self) -> SecuritySummary:
        """Calculate high-level summary metrics of all authentication events."""
        with self.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    COALESCE(SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END), 0) AS successes,
                    COALESCE(SUM(CASE WHEN status = 'FAILURE' THEN 1 ELSE 0 END), 0) AS failures,
                    MIN(timestamp) AS first_event,
                    MAX(timestamp) AS last_event,
                    COUNT(DISTINCT source_ip) AS unique_ips,
                    COUNT(DISTINCT username) AS unique_users
                FROM auth_events
                """
            )
            row = cursor.fetchone()
            if not row or row["total_events"] == 0:
                return SecuritySummary()

            total = row["total_events"]
            failures = row["failures"]
            rate = round((failures / total) * 100, 2) if total > 0 else 0.0

            return SecuritySummary(
                total_events=total,
                successful_logins=row["successes"],
                failed_logins=failures,
                failure_rate_percent=rate,
                first_event_time=row["first_event"],
                last_event_time=row["last_event"],
                unique_ips_count=row["unique_ips"],
                unique_users_count=row["unique_users"],
            )

    def detect_repeated_failed_logins(
        self, threshold: int = 3
    ) -> List[RepeatedFailureAlert]:
        """Detect accounts and IPs with repeated failed logins (Brute Force by target)."""
        query = """
            SELECT
                source_ip,
                username,
                COUNT(*) AS failure_count,
                MIN(timestamp) AS first_failure,
                MAX(timestamp) AS last_failure
            FROM auth_events
            WHERE status = 'FAILURE'
            GROUP BY source_ip, username
            HAVING failure_count >= ?
            ORDER BY failure_count DESC, last_failure DESC
        """
        with self.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (threshold,))
            return [
                RepeatedFailureAlert(
                    source_ip=row["source_ip"],
                    username=row["username"],
                    failure_count=row["failure_count"],
                    first_failure=row["first_failure"],
                    last_failure=row["last_failure"],
                )
                for row in cursor.fetchall()
            ]

    def detect_high_failure_ips(self, threshold: int = 5) -> List[HighFailureIPAlert]:
        """Detect source IPs generating an unusually high volume of failed logins."""
        query = """
            SELECT
                source_ip,
                COUNT(*) AS failure_count,
                COUNT(DISTINCT username) AS distinct_usernames_targeted,
                MIN(timestamp) AS first_failure,
                MAX(timestamp) AS last_failure
            FROM auth_events
            WHERE status = 'FAILURE'
            GROUP BY source_ip
            HAVING failure_count >= ?
            ORDER BY failure_count DESC, last_failure DESC
        """
        with self.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (threshold,))
            return [
                HighFailureIPAlert(
                    source_ip=row["source_ip"],
                    failure_count=row["failure_count"],
                    distinct_usernames_targeted=row["distinct_usernames_targeted"],
                    first_failure=row["first_failure"],
                    last_failure=row["last_failure"],
                )
                for row in cursor.fetchall()
            ]

    def detect_success_after_failures(
        self, min_failures: int = 2
    ) -> List[SuccessAfterFailureAlert]:
        """Detect successful login after multiple consecutive failures (Account Takeover indicator)."""
        query = """
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
            WHERE preceding_failures >= ?
            ORDER BY se.success_time DESC
        """
        with self.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (min_failures,))
            return [
                SuccessAfterFailureAlert(
                    source_ip=row["source_ip"],
                    username=row["username"],
                    event_type=row["event_type"],
                    success_time=row["success_time"],
                    preceding_failures=row["preceding_failures"],
                    streak_start_time=row["streak_start_time"] or row["success_time"],
                )
                for row in cursor.fetchall()
            ]

    def detect_password_spraying(
        self, min_unique_users: int = 3
    ) -> List[PasswordSprayAlert]:
        """Detect a single IP attempting logins on multiple distinct usernames."""
        query = """
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
            HAVING unique_usernames_count >= ?
            ORDER BY unique_usernames_count DESC, total_attempts DESC
        """
        with self.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (min_unique_users,))
            alerts = []
            for row in cursor.fetchall():
                users_raw = row["usernames_targeted"] or ""
                user_list = [u.strip() for u in users_raw.split(",") if u.strip()]
                alerts.append(
                    PasswordSprayAlert(
                        source_ip=row["source_ip"],
                        unique_usernames_count=row["unique_usernames_count"],
                        usernames_targeted=user_list,
                        total_attempts=row["total_attempts"],
                        failure_count=row["failure_count"],
                        success_count=row["success_count"],
                        first_seen=row["first_seen"],
                        last_seen=row["last_seen"],
                    )
                )
            return alerts

    def get_top_suspicious_ips(self, limit: int = 5) -> List[TopSuspiciousIP]:
        """Retrieve top IPs by failure volume and unique targets."""
        query = """
            SELECT
                source_ip,
                COUNT(*) AS total_attempts,
                SUM(CASE WHEN status = 'FAILURE' THEN 1 ELSE 0 END) AS failures,
                SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS successes,
                COUNT(DISTINCT username) AS unique_targets
            FROM auth_events
            GROUP BY source_ip
            ORDER BY failures DESC, unique_targets DESC
            LIMIT ?
        """
        with self.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            return [
                TopSuspiciousIP(
                    source_ip=row["source_ip"],
                    total_attempts=row["total_attempts"],
                    failures=row["failures"],
                    successes=row["successes"],
                    unique_targets=row["unique_targets"],
                )
                for row in cursor.fetchall()
            ]

    def get_top_targeted_usernames(self, limit: int = 5) -> List[TopTargetedUser]:
        """Retrieve top usernames targeted by failed attempts."""
        query = """
            SELECT
                username,
                COUNT(*) AS total_attempts,
                SUM(CASE WHEN status = 'FAILURE' THEN 1 ELSE 0 END) AS failures,
                SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS successes,
                COUNT(DISTINCT source_ip) AS unique_ips
            FROM auth_events
            GROUP BY username
            ORDER BY failures DESC, total_attempts DESC
            LIMIT ?
        """
        with self.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            return [
                TopTargetedUser(
                    username=row["username"],
                    total_attempts=row["total_attempts"],
                    failures=row["failures"],
                    successes=row["successes"],
                    unique_ips=row["unique_ips"],
                )
                for row in cursor.fetchall()
            ]

    def run_full_analysis(
        self,
        repeated_failure_threshold: int = 3,
        high_failure_ip_threshold: int = 5,
        compromise_min_failures: int = 2,
        spray_min_users: int = 3,
        top_limit: int = 5,
    ) -> DetectionReport:
        """Run all detection rules and generate a consolidated DetectionReport."""
        return DetectionReport(
            summary=self.get_security_summary(),
            top_suspicious_ips=self.get_top_suspicious_ips(limit=top_limit),
            top_targeted_users=self.get_top_targeted_usernames(limit=top_limit),
            repeated_failures=self.detect_repeated_failed_logins(
                threshold=repeated_failure_threshold
            ),
            high_failure_ips=self.detect_high_failure_ips(
                threshold=high_failure_ip_threshold
            ),
            compromised_logins=self.detect_success_after_failures(
                min_failures=compromise_min_failures
            ),
            password_spraying=self.detect_password_spraying(
                min_unique_users=spray_min_users
            ),
        )
