from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from worker import SHARED_REPLY_ROOM
from worker.protocol import parse_contribution_response_v2
from worker.transport import Technocore

logger = logging.getLogger(__name__)
MAX_RESULTS = 4096
RESULT_TTL_SECONDS = 3600

SCHEMA = """
CREATE TABLE IF NOT EXISTS collector_state (
  room TEXT PRIMARY KEY, cursor INTEGER NOT NULL, health TEXT NOT NULL,
  detail TEXT, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
  worker_did TEXT NOT NULL, job_id TEXT NOT NULL, requester_did TEXT NOT NULL,
  request_hash TEXT NOT NULL, request_sequence INTEGER NOT NULL,
  reply_after INTEGER NOT NULL, response_sequence INTEGER NOT NULL,
  received_at REAL NOT NULL, response_json TEXT NOT NULL,
  PRIMARY KEY(worker_did, job_id, requester_did, request_hash)
);
CREATE TABLE IF NOT EXISTS registrations (
  session TEXT NOT NULL, job_id TEXT NOT NULL, requester_did TEXT NOT NULL,
  request_hash TEXT NOT NULL, reply_after INTEGER NOT NULL, request_sequence INTEGER,
  expires_at REAL NOT NULL,
  PRIMARY KEY(session, job_id)
);
"""


class Reader(Protocol):
    def read(self, room: str, *, since: int, wait: float = 10.0) -> dict[str, Any]: ...


@dataclass(frozen=True)
class CollectorHealth:
    status: str
    cursor: int
    detail: str | None


class ReplyCollector:
    def __init__(
        self,
        path: Path,
        *,
        worker_did: str,
        room: str = SHARED_REPLY_ROOM,
        reader: Reader | None = None,
        clock: Any = time.time,
    ) -> None:
        self.path = path
        self.worker_did = worker_did
        self.room = room
        self.reader = reader or Technocore()
        self.clock = clock
        self._condition = threading.Condition()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(SCHEMA)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(registrations)")}
            if "request_sequence" not in columns:
                connection.execute("ALTER TABLE registrations ADD COLUMN request_sequence INTEGER")
            connection.execute(
                """INSERT OR IGNORE INTO collector_state
                (room, cursor, health, detail, updated_at) VALUES (?, 0, 'starting', NULL, ?)""",
                (room, self.clock()),
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def health(self) -> CollectorHealth:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT cursor, health, detail FROM collector_state WHERE room = ?", (self.room,)
            ).fetchone()
        if row is None:  # pragma: no cover
            return CollectorHealth("degraded", 0, "collector state missing")
        return CollectorHealth(str(row[1]), int(row[0]), str(row[2]) if row[2] else None)

    def baseline(self) -> int:
        health = self.health()
        if health.status == "degraded":
            raise RuntimeError("Reply collector is degraded.")
        return health.cursor

    def process(self, view: dict[str, Any]) -> int:
        messages = view.get("messages")
        if not isinstance(messages, list) or len(messages) > 200:
            raise ValueError("Malformed or oversized shared reply response.")
        current = self.health().cursor
        first = view.get("first_seq")
        if isinstance(first, int) and first > current + 1:
            self._set_health("degraded", f"sequence gap: expected {current + 1}, received {first}")
            raise RuntimeError("Shared reply stream sequence gap.")
        ordered = sorted(messages, key=lambda item: item.get("seq", -1))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = current
            for record in ordered:
                sequence = record.get("seq") if isinstance(record, dict) else None
                if not isinstance(sequence, int) or sequence <= cursor:
                    continue
                if sequence != cursor + 1:
                    connection.rollback()
                    self._set_health(
                        "degraded", f"sequence gap: expected {cursor + 1}, received {sequence}"
                    )
                    raise RuntimeError("Shared reply stream sequence gap.")
                payload = parse_contribution_response_v2(record, worker_did=self.worker_did)
                if payload is not None:
                    request = payload["request"]
                    connection.execute(
                        """INSERT OR IGNORE INTO results
                        (worker_did, job_id, requester_did, request_hash, request_sequence,
                         reply_after, response_sequence, received_at, response_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            self.worker_did, payload["job"], request["did"],
                            request["sha256"], request["seq"], request["reply_after"],
                            sequence, self.clock(), json.dumps(payload, separators=(",", ":")),
                        ),
                    )
                cursor = sequence
            connection.execute(
                """UPDATE collector_state SET cursor = ?, health = 'healthy', detail = NULL,
                updated_at = ? WHERE room = ?""",
                (cursor, self.clock(), self.room),
            )
            self._prune(connection)
        with self._condition:
            self._condition.notify_all()
        return cursor

    def _prune(self, connection: sqlite3.Connection) -> None:
        cutoff = self.clock() - RESULT_TTL_SECONDS
        connection.execute("DELETE FROM results WHERE received_at < ?", (cutoff,))
        connection.execute("DELETE FROM registrations WHERE expires_at < ?", (self.clock(),))
        connection.execute(
            """DELETE FROM results WHERE rowid IN (
            SELECT rowid FROM results ORDER BY received_at DESC LIMIT -1 OFFSET ?)""",
            (MAX_RESULTS,),
        )

    def _set_health(self, status: str, detail: str | None) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE collector_state SET health = ?, detail = ?, updated_at = ? WHERE room = ?",
                (status, detail, self.clock(), self.room),
            )
        with self._condition:
            self._condition.notify_all()

    def register(
        self, *, session: str, job: str, did: str, request_hash: str, reply_after: int
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO registrations
                (session, job_id, requester_did, request_hash, reply_after, request_sequence, expires_at)
                VALUES (?, ?, ?, ?, ?, NULL, ?)
                ON CONFLICT(session, job_id) DO UPDATE SET
                requester_did=excluded.requester_did, request_hash=excluded.request_hash,
                reply_after=excluded.reply_after, request_sequence=NULL,
                expires_at=excluded.expires_at""",
                (session, job, did, request_hash, reply_after, self.clock() + RESULT_TTL_SECONDS),
            )

    def confirm_registration(self, *, session: str, job: str, request_sequence: int) -> None:
        if not isinstance(request_sequence, int) or request_sequence < 1:
            raise ValueError("Invalid request sequence.")
        with self._connect() as connection:
            changed = connection.execute(
                """UPDATE registrations SET request_sequence = ?
                WHERE session = ? AND job_id = ? AND expires_at >= ?""",
                (request_sequence, session, job, self.clock()),
            ).rowcount
        if changed != 1:
            raise ValueError("Unknown browser job registration.")

    def result(self, *, session: str, job: str, did: str, request_hash: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            registered = connection.execute(
                """SELECT reply_after, request_sequence FROM registrations WHERE session = ? AND job_id = ?
                AND requester_did = ? AND request_hash = ? AND expires_at >= ?""",
                (session, job, did, request_hash, self.clock()),
            ).fetchone()
            if registered is None:
                raise ValueError("Unknown or mismatched browser job.")
            row = connection.execute(
                """SELECT response_json, response_sequence FROM results
                WHERE worker_did = ? AND job_id = ? AND requester_did = ? AND request_hash = ?""",
                (self.worker_did, job, did, request_hash),
            ).fetchone()
        if row is None:
            return None
        if registered[1] is None or int(row[1]) <= int(registered[0]):
            return None
        value = json.loads(str(row[0]))
        if value.get("request", {}).get("seq") != int(registered[1]):
            return None
        return value if isinstance(value, dict) else None

    def wait_result(
        self, *, session: str, job: str, did: str, request_hash: str, timeout: float = 10
    ) -> dict[str, Any] | None:
        deadline = time.monotonic() + max(0, min(timeout, 10))
        while True:
            result = self.result(session=session, job=job, did=did, request_hash=request_hash)
            if result is not None:
                return result
            if self.health().status == "degraded":
                raise RuntimeError("Reply collector is degraded.")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            with self._condition:
                self._condition.wait(remaining)

    def poll_once(self) -> int:
        cursor = self.health().cursor
        return self.process(self.reader.read(self.room, since=cursor, wait=10))

    def _run(self) -> None:
        delay = 0.5
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.poll_once()
                delay = 0.5
                # Wait-slot denial can return an empty response immediately. Never tight-loop.
                if time.monotonic() - started < 0.25:
                    self._stop.wait(delay)
            except urllib.error.HTTPError as error:
                retry = error.headers.get("Retry-After")
                try:
                    requested_delay = float(retry) if retry else delay * 2
                except ValueError:
                    requested_delay = delay * 2
                delay = max(1.0, min(requested_delay, 60.0))
                self._set_health("backoff", f"upstream HTTP {error.code}")
            except RuntimeError as error:
                if self.health().status == "degraded":
                    logger.error("collector stopped: %s", error)
                    return
                delay = min(delay * 2, 30.0)
                self._set_health("backoff", str(error))
            except (OSError, TypeError, ValueError) as error:
                delay = min(delay * 2, 30.0)
                self._set_health("backoff", str(error))
            self._stop.wait(delay)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="reply-collector", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=20)
