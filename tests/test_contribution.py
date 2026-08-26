from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from worker import PROTOCOL_V2, SHARED_REPLY_ROOM
from worker.github import (
    GitHubBoundaryError,
    GitHubVerifier,
    HTTPResponse,
    ResponseTooLarge,
    Verification,
    redirect_path,
)
from worker.identity import public_did
from worker.protocol import (
    ProtocolError,
    canonical_contribution_request,
    canonical_contribution_request_v2,
    parse_request,
)
from worker.service import Worker
from worker.state import State
from worker.transport import Posted

INBOX = "mb-p-fedcba9876543210fedcba98"
REPLY = "mb-p-0123456789abcdef01234567"
SHA = "93dab08e185121186d009f9b637a37365c294ea1"
REPOSITORY = "paiin-arc/technocore-beginner-guide"


class FakeGetter:
    def __init__(self, responses: list[HTTPResponse | Exception]):
        self.responses = responses
        self.paths: list[str] = []

    def __call__(self, path: str) -> HTTPResponse:
        self.paths.append(path)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def response(status: int, payload: object) -> HTTPResponse:
    return HTTPResponse(status, {}, json.dumps(payload).encode())


def valid_getter(*, commit_sha: str = SHA) -> FakeGetter:
    return FakeGetter(
        [
            response(200, {"full_name": REPOSITORY, "private": False}),
            response(200, {"commit": {"tree": {"sha": "b" * 40}}, "sha": commit_sha}),
        ]
    )


@pytest.mark.parametrize(
    ("repository", "message"),
    [
        ("https://github.com/owner/repo", "repository"),
        ("owner/repo/extra", "repository"),
        ("owner%2Frepo", "repository"),
        ("-owner/repo", "repository"),
        ("owner/repo..name", "repository"),
    ],
)
def test_malformed_repository_and_arbitrary_url_are_rejected(
    repository: str, message: str
) -> None:
    wire = canonical_contribution_request("job-1", REPLY, repository, SHA)
    with pytest.raises(ProtocolError, match=message):
        parse_request(wire)


@pytest.mark.parametrize("sha", ["abc", "g" * 40, "a" * 39, "a" * 41])
def test_commit_requires_full_hex_sha(sha: str) -> None:
    with pytest.raises(ProtocolError, match="40-character"):
        parse_request(canonical_contribution_request("job-1", REPLY, REPOSITORY, sha))


def test_valid_public_repository_and_exact_commit() -> None:
    getter = valid_getter()
    result = GitHubVerifier(getter).verify(REPOSITORY, SHA)
    assert result.checks == {
        "commit": {"sha": SHA, "status": "CONFIRMED"},
        "requested_file": {"status": "NOT_CHECKED"},
        "repository": {"full_name": REPOSITORY, "status": "CONFIRMED"},
    }
    assert result.resolved_sha == SHA
    assert len(getter.paths) == 2
    assert all(path.startswith("/repos/") for path in getter.paths)


def test_nonexistent_repository_does_not_check_commit() -> None:
    getter = FakeGetter([response(404, {"message": "Not Found"})])
    result = GitHubVerifier(getter).verify(REPOSITORY, SHA)
    assert result.checks["repository"] == {
        "reason": "not_found_or_inaccessible",
        "status": "NOT_FOUND",
    }
    assert result.checks["commit"] == {"status": "NOT_CHECKED"}
    assert result.checks["requested_file"] == {"status": "NOT_CHECKED"}
    assert len(getter.paths) == 1


def test_nonexistent_commit_is_distinct_from_repository_result() -> None:
    getter = FakeGetter(
        [
            response(200, {"full_name": REPOSITORY, "private": False}),
            response(404, {"message": "Not Found"}),
        ]
    )
    result = GitHubVerifier(getter).verify(REPOSITORY, SHA)
    assert result.checks["repository"]["status"] == "CONFIRMED"
    assert result.checks["commit"] == {
        "reason": "not_found_or_inaccessible",
        "status": "NOT_FOUND",
    }
    assert result.checks["requested_file"] == {"status": "NOT_CHECKED"}


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (TimeoutError(), "github_unavailable"),
        (ResponseTooLarge(), "response_too_large"),
    ],
)
def test_network_failures_are_unavailable(failure: Exception, reason: str) -> None:
    result = GitHubVerifier(FakeGetter([failure])).verify(REPOSITORY, SHA)
    assert result.checks["repository"] == {"reason": reason, "status": "UNAVAILABLE"}
    assert result.checks["commit"] == {"status": "NOT_CHECKED"}


@pytest.mark.parametrize("status", [403, 429])
def test_rate_limit_is_unavailable(status: int) -> None:
    result = GitHubVerifier(FakeGetter([response(status, {})])).verify(REPOSITORY, SHA)
    assert result.checks["repository"] == {
        "reason": "rate_limited",
        "status": "UNAVAILABLE",
    }


def test_malformed_github_response_is_unavailable() -> None:
    getter = FakeGetter([HTTPResponse(200, {}, b"not-json")])
    result = GitHubVerifier(getter).verify(REPOSITORY, SHA)
    assert result.checks["repository"]["status"] == "UNAVAILABLE"


def test_private_repository_response_is_not_confirmed() -> None:
    getter = FakeGetter([response(200, {"full_name": REPOSITORY, "private": True})])
    result = GitHubVerifier(getter).verify(REPOSITORY, SHA)
    assert result.checks["repository"] == {"reason": "not_public", "status": "NOT_FOUND"}
    assert result.checks["commit"] == {"status": "NOT_CHECKED"}


def test_repository_rename_uses_canonical_name_for_commit() -> None:
    renamed = "paiin-arc/renamed-guide"
    getter = FakeGetter(
        [
            response(200, {"full_name": renamed, "private": False}),
            response(200, {"sha": SHA}),
        ]
    )
    result = GitHubVerifier(getter).verify(REPOSITORY, SHA)
    assert result.checks["repository"]["renamed"] is True
    assert getter.paths[1].startswith(f"/repos/{renamed}/commits/")


def test_foreign_redirect_and_ambiguous_targets_are_blocked() -> None:
    for location in (
        "https://example.com/repos/a/b",
        "http://api.github.com/repos/a/b",
        "https://user@api.github.com/repos/a/b",
        "https://api.github.com:444/repos/a/b",
        "https://127.0.0.1/repos/a/b",
        "https://api.github.com/user",
    ):
        with pytest.raises(GitHubBoundaryError):
            redirect_path(location)
    assert redirect_path("https://api.github.com/repositories/123") == "/repositories/123"


class FakeSender:
    def __init__(self) -> None:
        self.posts: list[tuple[str, str, int]] = []

    def post_signed(
        self, room: str, text: str, key: Ed25519PrivateKey, nonce: int
    ) -> Posted:
        self.posts.append((room, text, nonce))
        return Posted(room, 901, "2026-01-01T00:00:00Z")


class FailOnceSender(FakeSender):
    def post_signed(
        self, room: str, text: str, key: Ed25519PrivateKey, nonce: int
    ) -> Posted:
        self.posts.append((room, text, nonce))
        if len(self.posts) == 1:
            raise RuntimeError("simulated reply rejection")
        return Posted(room, 902, "2026-01-01T00:00:00Z")


class FakeVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(
        self, repository: str, commit_sha: str, file_path: str | None = None
    ) -> Verification:
        self.calls += 1
        return Verification(
            checks={
                "commit": {"sha": commit_sha, "status": "CONFIRMED"},
                "requested_file": {"status": "NOT_CHECKED"},
                "repository": {"full_name": repository, "status": "CONFIRMED"},
            },
            resolved_sha=commit_sha,
            repository_full_name=repository,
        )


def contribution_record(key: Ed25519PrivateKey, sequence: int = 1) -> dict[str, Any]:
    return {
        "from": public_did(key),
        "nonce": 100,
        "seq": sequence,
        "text": canonical_contribution_request("job-verify", REPLY, REPOSITORY, SHA),
    }


def contribution_record_v2(
    key: Ed25519PrivateKey, sequence: int = 1, *, reply_after: int = 0
) -> dict[str, Any]:
    return {
        "from": public_did(key), "nonce": 100, "seq": sequence,
        "text": canonical_contribution_request_v2(
            "job-v2", REPOSITORY, SHA, reply_after,
        ),
    }


def build_worker(tmp_path: Path) -> tuple[Worker, FakeSender, FakeVerifier, State]:
    sender, verifier, state = FakeSender(), FakeVerifier(), State(tmp_path / "jobs.sqlite3")
    worker = Worker(
        inbox=INBOX,
        key=Ed25519PrivateKey.generate(),
        state=state,
        transport=sender,
        verifier=verifier,
    )
    return worker, sender, verifier, state


def test_contribution_response_is_bounded_granular_and_non_misleading(tmp_path: Path) -> None:
    worker, sender, _, _ = build_worker(tmp_path)
    requester = Ed25519PrivateKey.generate()
    assert worker.handle(contribution_record(requester)).status == "completed"
    wire = sender.posts[0][1]
    payload = json.loads(wire)
    assert len(wire) <= 4096
    assert payload["status"] == "completed"
    assert payload["checks"]["repository"]["status"] == "CONFIRMED"
    assert payload["checks"]["commit"]["status"] == "CONFIRMED"
    assert payload["checks"]["requested_file"]["status"] == "NOT_CHECKED"
    assert "VERIFIED" not in wire.upper()
    assert set(payload["claims_not_established"]) == {
        "did_github_ownership",
        "requester_commit_authorship",
        "contribution_quality_or_acceptance",
        "flop_eligibility_or_endorsement",
    }


def test_v1_and_v2_route_to_their_exact_reply_streams(tmp_path: Path) -> None:
    worker, sender, _, _ = build_worker(tmp_path)
    requester = Ed25519PrivateKey.generate()
    assert worker.handle(contribution_record(requester)).status == "completed"
    assert worker.handle(contribution_record_v2(requester, sequence=2, reply_after=5)).status == "completed"
    assert [post[0] for post in sender.posts] == [REPLY, SHARED_REPLY_ROOM]
    v2 = json.loads(sender.posts[1][1])
    assert v2["v"] == PROTOCOL_V2
    assert v2["request"]["reply_after"] == 5
    assert v2["request"]["seq"] == 2


class CapacityTransport(FakeSender):
    def __init__(self, owner: str) -> None:
        super().__init__()
        self.rooms = {SHARED_REPLY_ROOM}
        self.owner = owner
        self.creations = 0

    def create(self, room: str) -> None:
        self.creations += 1
        raise RuntimeError("room capacity reached")

    def post_signed(self, room: str, text: str, key: Ed25519PrivateKey, nonce: int) -> Posted:
        if room not in self.rooms:
            self.create(room)
        if public_did(key) != self.owner:
            raise RuntimeError("owned room rejects writer")
        return super().post_signed(room, text, key, nonce)


def test_room_capacity_refusal_does_not_block_existing_owned_v2_stream(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    transport = CapacityTransport(public_did(key))
    with pytest.raises(RuntimeError, match="capacity"):
        transport.create("mb-p-new-reply-room-000000")
    worker = Worker(inbox=INBOX, key=key, state=State(tmp_path / "jobs.sqlite3"),
                    transport=transport, verifier=FakeVerifier())
    assert worker.handle(contribution_record_v2(Ed25519PrivateKey.generate())).status == "completed"
    assert transport.posts[0][0] == SHARED_REPLY_ROOM
    assert transport.creations == 1  # only the explicit refused probe; the job created no room
    with pytest.raises(RuntimeError, match="rejects writer"):
        transport.post_signed(SHARED_REPLY_ROOM, "{}", Ed25519PrivateKey.generate(), 2)


def test_keepalive_is_minimal_and_only_due_after_six_days(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker, sender, _, state = build_worker(tmp_path)
    monkeypatch.setattr("worker.service.time.time", lambda: 1_000_000.0)
    assert worker.keepalive_if_due().status == "keepalive-not-due"
    state.set_shared_activity(1_000_000.0)
    assert worker.keepalive_if_due().status == "keepalive-not-due"
    monkeypatch.setattr("worker.service.time.time", lambda: 1_000_000.0 + 6 * 86400 + 1)
    assert worker.keepalive_if_due().status == "keepalive-completed"
    assert sender.posts[-1][0] == SHARED_REPLY_ROOM
    assert json.loads(sender.posts[-1][1]) == {
        "kind": "keepalive", "v": PROTOCOL_V2, "worker": worker.did,
    }


def test_duplicate_conflict_and_did_isolation_avoid_reexecution(tmp_path: Path) -> None:
    worker, sender, verifier, _ = build_worker(tmp_path)
    first, second = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    record = contribution_record(first)
    assert worker.handle(record).status == "completed"
    assert worker.handle(record).status == "duplicate"
    changed = contribution_record(first, sequence=2)
    changed["text"] = canonical_contribution_request(
        "job-verify", REPLY, REPOSITORY, "a" * 40
    )
    assert worker.handle(changed).status == "job-conflict"
    assert verifier.calls == 1
    assert worker.handle(contribution_record(second, sequence=3)).status == "completed"
    assert verifier.calls == 2
    assert len(sender.posts) == 2


def test_failed_contribution_reply_retries_persisted_result_without_github(
    tmp_path: Path,
) -> None:
    sender, verifier, state = FailOnceSender(), FakeVerifier(), State(tmp_path / "jobs.sqlite3")
    worker = Worker(
        inbox=INBOX,
        key=Ed25519PrivateKey.generate(),
        state=state,
        transport=sender,
        verifier=verifier,
    )
    requester = Ed25519PrivateKey.generate()
    record = contribution_record(requester)
    assert worker.handle(record).status == "delivery-pending"
    assert verifier.calls == 1
    assert worker.handle(record).status == "completed"
    assert verifier.calls == 1
    assert sender.posts[0][1] == sender.posts[1][1]


def test_database_has_only_bounded_provenance_not_fetched_content(tmp_path: Path) -> None:
    worker, _, _, state = build_worker(tmp_path)
    requester = Ed25519PrivateKey.generate()
    assert worker.handle(contribution_record(requester)).status == "completed"
    raw = state.path.read_bytes()
    assert b"PRIVATE KEY" not in raw
    assert b"README contents" not in raw
    with sqlite3.connect(state.path) as connection:
        row = connection.execute(
            "SELECT repository, claimed_commit_sha, resolved_commit_sha, checks_json, "
            "verified_at FROM jobs"
        ).fetchone()
        columns = {item[1] for item in connection.execute("PRAGMA table_info(jobs)")}
    assert row[0:3] == (REPOSITORY, SHA, SHA)
    assert row[3] is not None and row[4] is not None
    assert "request_text" not in columns and "fetched_body" not in columns


def test_github_client_never_requests_content_or_executes_repository_code() -> None:
    getter = valid_getter()
    GitHubVerifier(getter).verify(REPOSITORY, SHA)
    assert len(getter.paths) <= 2
    assert all("/contents" not in path and "/tarball" not in path for path in getter.paths)


@pytest.mark.parametrize("path", ["../README.md", "/README.md", "a//b", "a/%2e%2e/b"])
def test_unsafe_file_path_is_rejected(path: str) -> None:
    wire = canonical_contribution_request("job-1", REPLY, REPOSITORY, SHA, path)
    with pytest.raises(ProtocolError, match="file path"):
        parse_request(wire)


@pytest.mark.parametrize(
    ("entries", "expected"),
    [
        ([{"path": "README.md", "type": "blob"}], "CONFIRMED"),
        ([{"path": "other.txt", "type": "blob"}], "NOT_FOUND"),
    ],
)
def test_requested_file_exists_or_is_absent(entries: list[dict[str, str]], expected: str) -> None:
    getter = FakeGetter(
        [
            response(200, {"full_name": REPOSITORY, "private": False}),
            response(200, {"commit": {"tree": {"sha": "b" * 40}}, "sha": SHA}),
            response(200, {"tree": entries, "truncated": False}),
        ]
    )
    result = GitHubVerifier(getter).verify(REPOSITORY, SHA, "README.md")
    assert result.checks["requested_file"] == {"path": "README.md", "status": expected}
    assert len(getter.paths) == 3
    assert "/git/trees/" in getter.paths[2]
