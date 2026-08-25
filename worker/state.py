from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL,
    requester_did TEXT NOT NULL,
    request_room TEXT NOT NULL,
    request_sequence INTEGER NOT NULL,
    received_at TEXT NOT NULL,
    capability TEXT NOT NULL,
    status TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    result_json TEXT NOT NULL,
    response_room TEXT NOT NULL,
    response_sequence INTEGER,
    completed_at TEXT,
    UNIQUE(requester_did, job_id),
    UNIQUE(request_room, request_sequence)
);
CREATE TABLE IF NOT EXISTS cursors (
    room TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS outbound_nonces (
    room TEXT PRIMARY KEY,
    nonce INTEGER NOT NULL
);
"""

JOB_COLUMNS = {
    "repository": "TEXT",
    "claimed_commit_sha": "TEXT",
    "resolved_commit_sha": "TEXT",
    "checks_json": "TEXT",
    "verified_at": "TEXT",
    "requested_file_path": "TEXT",
}


@dataclass(frozen=True)
class JobClaim:
    inserted: bool
    conflict: bool


@dataclass(frozen=True)
class PendingJob:
    job_id: str
    requester_did: str
    request_sequence: int
    request_hash: str
    capability: str
    result: dict[str, Any]
    response_room: str
    checks: dict[str, object] | None


class State:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(SCHEMA)
            existing = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
            }
            for column, kind in JOB_COLUMNS.items():
                if column not in existing:
                    connection.execute(f"ALTER TABLE jobs ADD COLUMN {column} {kind}")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def cursor(self, room: str) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT sequence FROM cursors WHERE room = ?", (room,)).fetchone()
        return int(row[0]) if row else 0

    def set_cursor(self, room: str, sequence: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO cursors(room, sequence) VALUES (?, ?) "
                "ON CONFLICT(room) DO UPDATE SET sequence = excluded.sequence",
                (room, sequence),
            )

    def next_nonce(self, room: str, candidate: int) -> int:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT nonce FROM outbound_nonces WHERE room = ?", (room,)
            ).fetchone()
            nonce = max(candidate, int(row[0]) + 1 if row else candidate)
            connection.execute(
                "INSERT INTO outbound_nonces(room, nonce) VALUES (?, ?) "
                "ON CONFLICT(room) DO UPDATE SET nonce = excluded.nonce",
                (room, nonce),
            )
        return nonce

    def existing_claim(
        self, requester_did: str, job_id: str, request_hash: str
    ) -> JobClaim | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT request_hash FROM jobs WHERE requester_did = ? AND job_id = ?",
                (requester_did, job_id),
            ).fetchone()
        if row is None:
            return None
        return JobClaim(inserted=False, conflict=str(row[0]) != request_hash)

    def pending_claim(
        self, requester_did: str, job_id: str, request_hash: str
    ) -> PendingJob | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT job_id, requester_did, request_sequence, request_hash,
                capability, result_json, response_room, checks_json
                FROM jobs WHERE requester_did = ? AND job_id = ?
                AND request_hash = ? AND status = 'processed'""",
                (requester_did, job_id, request_hash),
            ).fetchone()
        if row is None:
            return None
        return PendingJob(
            job_id=str(row[0]),
            requester_did=str(row[1]),
            request_sequence=int(row[2]),
            request_hash=str(row[3]),
            capability=str(row[4]),
            result=json.loads(str(row[5])),
            response_room=str(row[6]),
            checks=json.loads(str(row[7])) if row[7] is not None else None,
        )

    def claim(
        self,
        *,
        job_id: str,
        requester_did: str,
        request_room: str,
        request_sequence: int,
        request_hash: str,
        capability: str,
        result: dict[str, object],
        response_room: str,
        repository: str | None = None,
        claimed_commit_sha: str | None = None,
        resolved_commit_sha: str | None = None,
        checks: dict[str, object] | None = None,
        requested_file_path: str | None = None,
    ) -> JobClaim:
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO jobs (
                        job_id, requester_did, request_room, request_sequence,
                        received_at, capability, status, request_hash, result_json,
                        response_room, repository, claimed_commit_sha,
                        resolved_commit_sha, checks_json, verified_at, requested_file_path
                    ) VALUES (?, ?, ?, ?, ?, ?, 'processed', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        job_id,
                        requester_did,
                        request_room,
                        request_sequence,
                        now,
                        capability,
                        request_hash,
                        json.dumps(result, separators=(",", ":"), sort_keys=True),
                        response_room,
                        repository,
                        claimed_commit_sha,
                        resolved_commit_sha,
                        json.dumps(checks, separators=(",", ":"), sort_keys=True)
                        if checks is not None
                        else None,
                        now if checks is not None else None,
                        requested_file_path,
                    ),
                )
                return JobClaim(inserted=True, conflict=False)
            except sqlite3.IntegrityError:
                row = connection.execute(
                    "SELECT request_hash FROM jobs WHERE requester_did = ? AND job_id = ?",
                    (requester_did, job_id),
                ).fetchone()
                return JobClaim(inserted=False, conflict=bool(row and row[0] != request_hash))

    def complete(self, requester_did: str, job_id: str, response_sequence: int) -> None:
        with self._connect() as connection:
            connection.execute(
                """UPDATE jobs SET status = 'completed', response_sequence = ?, completed_at = ?
                WHERE requester_did = ? AND job_id = ?""",
                (response_sequence, datetime.now(UTC).isoformat(), requester_did, job_id),
            )
