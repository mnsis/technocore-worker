from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from worker import PROTOCOL_V2, SHARED_REPLY_ROOM
from worker.collector import ReplyCollector
from worker.protocol import canonical_contribution_response

WORKER = "did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM"
REQUESTER = "did:key:z6MkrAtiZ6xp111111111111111111111111111111111111"


def response(
    seq: int, *, job: str = "browser-job", reply_after: int = 0,
    requester: str = REQUESTER, digest: str = "a" * 64,
    request_sequence: int = 9, sender: str = WORKER,
) -> dict[str, Any]:
    text = canonical_contribution_response(
        worker_did=WORKER, requester_did=requester, job_id=job,
        request_room="mb-technocore-worker", request_sequence=request_sequence,
        request_hash=digest,
        checks={
            "repository": {"status": "CONFIRMED", "full_name": "owner/repo"},
            "commit": {"status": "CONFIRMED", "sha": "b" * 40},
            "requested_file": {"status": "NOT_CHECKED"},
        },
        version=PROTOCOL_V2, reply_after=reply_after,
    )
    return {"seq": seq, "from": sender, "nonce": seq, "text": text}


def view(messages: list[dict[str, Any]], *, since: int = 0) -> dict[str, Any]:
    return {
        "room": SHARED_REPLY_ROOM,
        "first_seq": messages[0]["seq"] if messages else None,
        "last_seq": messages[-1]["seq"] if messages else since,
        "messages": messages,
    }


def collector(tmp_path: Path) -> ReplyCollector:
    return ReplyCollector(tmp_path / "collector.sqlite3", worker_did=WORKER)


def register(
    c: ReplyCollector, *, job: str = "browser-job", digest: str = "a" * 64,
    requester: str = REQUESTER, baseline: int = 0, session: str = "s" * 32,
) -> None:
    c.register(session=session, job=job, did=requester, request_hash=digest, reply_after=baseline)
    c.confirm_registration(session=session, job=job, request_sequence=9)


def test_atomic_store_and_cursor_survive_restart(tmp_path: Path) -> None:
    first = collector(tmp_path)
    register(first)
    assert first.process(view([response(1)])) == 1
    reopened = collector(tmp_path)
    assert reopened.health().cursor == 1
    assert reopened.result(
        session="s" * 32, job="browser-job", did=REQUESTER, request_hash="a" * 64
    )["job"] == "browser-job"


def test_result_is_hidden_until_request_sequence_is_confirmed(tmp_path: Path) -> None:
    c = collector(tmp_path)
    c.register(session="s" * 32, job="browser-job", did=REQUESTER,
               request_hash="a" * 64, reply_after=0)
    c.process(view([response(1)]))
    assert c.result(session="s" * 32, job="browser-job", did=REQUESTER,
                    request_hash="a" * 64) is None
    c.confirm_registration(session="s" * 32, job="browser-job", request_sequence=9)
    assert c.result(session="s" * 32, job="browser-job", did=REQUESTER,
                    request_hash="a" * 64) is not None


def test_wrong_request_sequence_is_not_released(tmp_path: Path) -> None:
    c = collector(tmp_path)
    register(c)
    c.process(view([response(1, request_sequence=10)]))
    assert c.result(session="s" * 32, job="browser-job", did=REQUESTER,
                    request_hash="a" * 64) is None


def test_immediate_response_before_first_wait_is_available(tmp_path: Path) -> None:
    c = collector(tmp_path)
    c.process(view([
        {"seq": i, "from": WORKER, "nonce": i, "text": '{"kind":"keepalive"}'}
        for i in range(1, 5)
    ]))
    register(c, baseline=4)
    c.process(view([response(5, reply_after=4)], since=4))
    assert c.wait_result(
        session="s" * 32, job="browser-job", did=REQUESTER,
        request_hash="a" * 64, timeout=0,
    ) is not None


def test_unrelated_and_out_of_order_jobs_are_correlated(tmp_path: Path) -> None:
    c = collector(tmp_path)
    register(c, job="browser-a", digest="a" * 64)
    register(c, job="browser-b", digest="b" * 64, session="t" * 32)
    c.process(view([
        response(1, job="browser-b", digest="b" * 64),
        response(2, job="browser-a", digest="a" * 64),
    ]))
    assert c.result(session="s" * 32, job="browser-a", did=REQUESTER,
                    request_hash="a" * 64)["job"] == "browser-a"
    assert c.result(session="t" * 32, job="browser-b", did=REQUESTER,
                    request_hash="b" * 64)["job"] == "browser-b"


@pytest.mark.parametrize("field", ["sender", "worker", "job", "did", "digest", "baseline"])
def test_bound_field_mismatches_are_rejected(tmp_path: Path, field: str) -> None:
    c = collector(tmp_path)
    register(c)
    record = response(1)
    payload = json.loads(record["text"])
    if field == "sender": record["from"] = REQUESTER
    elif field == "worker": payload["worker"] = REQUESTER
    elif field == "job": payload["job"] = "browser-other"
    elif field == "did": payload["request"]["did"] = WORKER
    elif field == "digest": payload["request"]["sha256"] = "b" * 64
    else: payload["request"]["reply_after"] = 1
    record["text"] = json.dumps(payload, separators=(",", ":"))
    c.process(view([record]))
    assert c.result(session="s" * 32, job="browser-job", did=REQUESTER,
                    request_hash="a" * 64) is None


def test_duplicate_response_is_deduplicated(tmp_path: Path) -> None:
    c = collector(tmp_path)
    register(c)
    c.process(view([response(1)]))
    c.process(view([response(2)], since=1))
    with c._connect() as connection:
        assert connection.execute("SELECT count(*) FROM results").fetchone()[0] == 1


def test_gap_marks_degraded_without_advancing(tmp_path: Path) -> None:
    c = collector(tmp_path)
    with pytest.raises(RuntimeError, match="gap"):
        c.process(view([response(2)]))
    assert c.health().status == "degraded"
    assert c.health().cursor == 0
    with pytest.raises(RuntimeError, match="degraded"):
        c.baseline()


def test_crash_before_commit_stores_neither_result_nor_cursor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = collector(tmp_path)
    register(c)
    monkeypatch.setattr(c, "_prune", lambda connection: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError, match="crash"):
        c.process(view([response(1)]))
    assert c.health().cursor == 0
    with c._connect() as connection:
        assert connection.execute("SELECT count(*) FROM results").fetchone()[0] == 0


def test_200_results_and_oversized_batch(tmp_path: Path) -> None:
    c = collector(tmp_path)
    records = []
    for i in range(1, 201):
        job = f"browser-{i}"
        digest = hashlib.sha256(str(i).encode()).hexdigest()
        register(c, job=job, digest=digest, session=f"s{i}")
        records.append(response(i, job=job, digest=digest))
    c.process(view(records))
    assert c.health().cursor == 200
    assert c.result(session="s200", job="browser-200", did=REQUESTER,
                    request_hash=hashlib.sha256(b"200").hexdigest()) is not None
    with pytest.raises(ValueError, match="oversized"):
        c.process(view([response(i, job=f"x-{i}") for i in range(201, 402)], since=200))


def test_more_than_200_cached_replies_are_processed_in_bounded_batches(tmp_path: Path) -> None:
    c = collector(tmp_path)
    for start, stop in ((1, 201), (201, 251)):
        records = []
        for i in range(start, stop):
            digest = f"{i:064x}"
            register(c, job=f"browser-{i}", digest=digest, session=f"s{i}")
            records.append(response(i, job=f"browser-{i}", digest=digest))
        c.process(view(records, since=start - 1))
    with c._connect() as connection:
        assert connection.execute("SELECT count(*) FROM results").fetchone()[0] == 250
    assert c.health().cursor == 250


def test_many_local_waiters_do_not_poll_upstream(tmp_path: Path) -> None:
    c = collector(tmp_path)
    for i in range(60):
        register(c, job=f"browser-{i}", digest=f"{i:064x}", session=f"s{i}")
    completed: list[object] = []
    threads = [threading.Thread(target=lambda i=i: completed.append(c.wait_result(
        session=f"s{i}", job=f"browser-{i}", did=REQUESTER,
        request_hash=f"{i:064x}", timeout=0.01))) for i in range(60)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert len(completed) == 60 and all(item is None for item in completed)


class EmptyReader:
    def __init__(self) -> None: self.calls = 0
    def read(self, room: str, *, since: int, wait: float = 10) -> dict[str, Any]:
        self.calls += 1
        return view([], since=since)


def test_one_upstream_poll_is_independent_of_browser_count(tmp_path: Path) -> None:
    reader = EmptyReader()
    c = ReplyCollector(tmp_path / "c.sqlite3", worker_did=WORKER, reader=reader)
    for i in range(100):
        register(c, job=f"browser-{i}", digest=f"{i:064x}", session=f"s{i}")
    c.poll_once()
    assert reader.calls == 1


def test_immediate_empty_wait_slot_response_cannot_tight_loop(tmp_path: Path) -> None:
    reader = EmptyReader()
    c = ReplyCollector(tmp_path / "c.sqlite3", worker_did=WORKER, reader=reader)
    c.start()
    time.sleep(0.08)
    c.stop()
    assert reader.calls == 1


class ErrorReader:
    def __init__(self, retry_after: str | None) -> None:
        self.calls = 0
        self.retry_after = retry_after

    def read(self, room: str, *, since: int, wait: float = 10) -> dict[str, Any]:
        self.calls += 1
        headers = Message()
        if self.retry_after is not None:
            headers["Retry-After"] = self.retry_after
        raise urllib.error.HTTPError("https://technocore.chat", 429, "limited", headers, None)


@pytest.mark.parametrize("retry_after", ["2", "not-a-number", None])
def test_429_enters_bounded_backoff_without_repolling(tmp_path: Path, retry_after: str | None) -> None:
    reader = ErrorReader(retry_after)
    c = ReplyCollector(tmp_path / "c.sqlite3", worker_did=WORKER, reader=reader)
    c.start()
    time.sleep(0.08)
    assert c.health().status == "backoff"
    c.stop()
    assert reader.calls == 1
