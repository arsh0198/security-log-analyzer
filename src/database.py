"""SQLite database manager for storing and querying authentication events."""

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Generator, Iterable, Optional

from .models import AuthEvent


class DatabaseManager:
    """Manages SQLite database initialization, indexing, and event persistence."""

    def __init__(self, db_path: str | Path = "logs.db") -> None:
        self.db_path = str(db_path)
        self._is_memory = self.db_path == ":memory:" or "mode=memory" in self.db_path
        self._memory_conn: Optional[sqlite3.Connection] = None

        if self._is_memory:
            self._memory_conn = sqlite3.connect(self.db_path)
            self._memory_conn.row_factory = sqlite3.Row
            self._memory_conn.execute("PRAGMA foreign_keys = ON;")

        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a configured SQLite connection."""
        if self._is_memory and self._memory_conn is not None:
            return self._memory_conn

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    @contextmanager
    def session(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for managing transactions."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if not self._is_memory:
                conn.close()

    def init_db(self) -> None:
        """Create necessary tables and performance indexes."""
        # Ensure parent directory exists if path includes directories
        db_file = Path(self.db_path)
        if not self._is_memory and db_file.parent:
            db_file.parent.mkdir(parents=True, exist_ok=True)

        with self.session() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS auth_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    source_ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'FAILURE')),
                    raw_log TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_ip ON auth_events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_events_user ON auth_events(username);
                CREATE INDEX IF NOT EXISTS idx_events_status ON auth_events(status);
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON auth_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_ip_user ON auth_events(source_ip, username);
                CREATE INDEX IF NOT EXISTS idx_events_ip_status ON auth_events(source_ip, status);
                """
            )

    def insert_events(self, events: Iterable[AuthEvent]) -> int:
        """Batch insert authentication events into the database.

        Returns the number of events inserted.
        """
        records = [
            (
                e.timestamp,
                e.source_ip,
                e.username,
                e.event_type,
                e.status,
                e.raw_log,
            )
            for e in events
        ]

        if not records:
            return 0

        with self.session() as conn:
            cursor = conn.cursor()
            cursor.executemany(
                """
                INSERT INTO auth_events (timestamp, source_ip, username, event_type, status, raw_log)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                records,
            )
            return cursor.rowcount

    def get_total_events_count(self) -> int:
        """Return the count of all stored events."""
        with self.session() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM auth_events")
            return cursor.fetchone()[0]

    def clear_events(self) -> None:
        """Remove all records from auth_events."""
        with self.session() as conn:
            conn.execute("DELETE FROM auth_events")

    def close(self) -> None:
        """Close connection if open."""
        if self._memory_conn is not None:
            self._memory_conn.close()
            self._memory_conn = None
