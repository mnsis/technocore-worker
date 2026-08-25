from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from worker.identity import public_did
from worker.protocol import canonical_request
from worker.service import Worker
from worker.state import State
from worker.transport import Posted

INBOX = "mb-p-fedcba9876543210fedcba98"
REPLY = "mb-p-0123456789abcdef01234567"


class FakeSender:
    def __init__(self) -> None:
        self.posts: list[tuple[str, str, int]] = []

    def post_signed(
        self, room: str, text: str, key: Ed25519PrivateKey, nonce: int
    ) -> Posted:
        self.posts.append((room, text, nonce))
        return Posted(room=room, sequence=900 + len(self.posts), timestamp="2026-01-01T00:00:00Z")


class FailOnceSender(FakeSender):
    def post_signed(
        self, room: str, text: str, key: Ed25519PrivateKey, nonce: int
    ) -> Posted:
        self.posts.append((room, text, nonce))
        if len(self.posts) == 1:
            raise RuntimeError("simulated reply rejection")
        return Posted(room=room, sequence=902, timestamp="2026-01-01T00:00:00Z")


def build_worker(tmp_path: Path) -> tuple[Worker, FakeSender, State]:
    state = State(tmp_path / "jobs.sqlite3")
    sender = FakeSender()
    worker = Worker(
        inbox=INBOX,
        key=Ed25519PrivateKey.generate(),
        state=state,
        transport=sender,
    )
    return worker, sender, state


def signed_record(
    key: Ed25519PrivateKey, job: str = "job-1", sequence: int = 1
) -> dict[str, object]:
    return {
        "from": public_did(key),
        "nonce": 100,
        "seq": sequence,
        "text": canonical_request(job, REPLY, "small deterministic input"),
    }


def test_valid_signed_request_produces_signed_response_metadata(tmp_path: Path) -> None:
    worker, sender, _ = build_worker(tmp_path)
    requester = Ed25519PrivateKey.generate()
    outcome = worker.handle(signed_record(requester))
    assert outcome.status == "completed"
    assert len(sender.posts) == 1
    assert sender.posts[0][0] == REPLY
    assert '"status":"ok"' in sender.posts[0][1]
    assert f'"worker":"{worker.did}"' in sender.posts[0][1]
    assert f'"did":"{public_did(requester)}"' in sender.posts[0][1]


def test_unsigned_request_rejected(tmp_path: Path) -> None:
    worker, sender, _ = build_worker(tmp_path)
    record = {"from": "alice", "seq": 1, "text": canonical_request("job-1", REPLY, "x")}
    assert worker.handle(record).status == "unsigned-or-invalid"
    assert not sender.posts


def test_duplicate_and_replay_are_idempotent(tmp_path: Path) -> None:
    worker, sender, _ = build_worker(tmp_path)
    requester = Ed25519PrivateKey.generate()
    record = signed_record(requester)
    assert worker.handle(record).status == "completed"
    assert worker.handle(record).status == "duplicate"
    replay = dict(record, seq=2)
    assert worker.handle(replay).status == "duplicate"
    assert len(sender.posts) == 1


def test_failed_reply_is_retried_without_reprocessing_request(tmp_path: Path) -> None:
    state = State(tmp_path / "jobs.sqlite3")
    sender = FailOnceSender()
    worker = Worker(
        inbox=INBOX,
        key=Ed25519PrivateKey.generate(),
        state=state,
        transport=sender,
    )
    requester = Ed25519PrivateKey.generate()
    record = signed_record(requester)
    with pytest.raises(RuntimeError, match="reply rejection"):
        worker.handle(record)
    request_hash = hashlib.sha256(str(record["text"]).encode()).hexdigest()
    assert state.pending_claim(public_did(requester), "job-1", request_hash) is not None
    assert worker.handle(record).status == "completed"
    assert len(sender.posts) == 2
    assert sender.posts[0][1] == sender.posts[1][1]


def test_changed_replay_is_conflict(tmp_path: Path) -> None:
    worker, sender, _ = build_worker(tmp_path)
    requester = Ed25519PrivateKey.generate()
    assert worker.handle(signed_record(requester)).status == "completed"
    changed = signed_record(requester, sequence=2)
    changed["text"] = canonical_request("job-1", REPLY, "changed")
    assert worker.handle(changed).status == "job-conflict"
    assert len(sender.posts) == 1


def test_same_job_id_from_different_dids_is_separate(tmp_path: Path) -> None:
    worker, sender, _ = build_worker(tmp_path)
    first = Ed25519PrivateKey.generate()
    second = Ed25519PrivateKey.generate()
    assert worker.handle(signed_record(first, sequence=1)).status == "completed"
    assert worker.handle(signed_record(second, sequence=2)).status == "completed"
    assert len(sender.posts) == 2


def test_malformed_request_is_rejected(tmp_path: Path) -> None:
    worker, sender, _ = build_worker(tmp_path)
    requester = Ed25519PrivateKey.generate()
    record = signed_record(requester)
    record["text"] = "not-json"
    assert worker.handle(record).status == "malformed"
    assert not sender.posts


def test_private_key_and_request_text_are_not_in_database(tmp_path: Path) -> None:
    worker, _, state = build_worker(tmp_path)
    requester = Ed25519PrivateKey.generate()
    secret_marker = "transient-marker-never-persisted"
    record = signed_record(requester)
    record["text"] = canonical_request("job-1", REPLY, secret_marker)
    assert worker.handle(record).status == "completed"
    database_bytes = state.path.read_bytes()
    assert secret_marker.encode() not in database_bytes
    assert b"PRIVATE KEY" not in database_bytes
    with sqlite3.connect(state.path) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(jobs)")]
    assert "request_text" not in columns
    assert "private_key" not in columns
