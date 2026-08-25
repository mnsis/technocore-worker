from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from worker import PROTOCOL_VERSION

MAX_WIRE_CHARS = 1024
MAX_TEXT_CHARS = 512
JOB_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MAILBOX_RE = re.compile(r"^mb-p-[a-z0-9][a-z0-9_-]{15,42}$")
DID_RE = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
REPOSITORY_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/"
    r"(?P<name>[A-Za-z0-9_.-]{1,100})$"
)
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
FILE_PATH_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
ECHO_REQUEST_KEYS = {"v", "job", "capability", "reply", "text"}
CONTRIBUTION_REQUEST_KEYS = {"v", "job", "capability", "reply", "repository", "commit"}


class ProtocolError(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate field: {key}")
        result[key] = value
    return result


def _has_disallowed_characters(value: str) -> bool:
    return any(unicodedata.category(char) in {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"} for char in value)


@dataclass(frozen=True)
class EchoRequest:
    job_id: str
    reply_room: str
    text: str
    capability: str = "echo-analysis"


@dataclass(frozen=True)
class ContributionRequest:
    job_id: str
    reply_room: str
    repository: str
    commit_sha: str
    file_path: str | None = None
    capability: str = "contribution-verify"


type Request = EchoRequest | ContributionRequest


def parse_request(wire_text: str) -> Request:
    if not isinstance(wire_text, str) or not wire_text or len(wire_text) > MAX_WIRE_CHARS:
        raise ProtocolError("request size is outside the allowed range")
    try:
        payload = json.loads(wire_text, object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, TypeError) as error:
        raise ProtocolError("request is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ProtocolError("request is not an object")
    if payload.get("v") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    capability = payload.get("capability")
    if capability not in {"echo-analysis", "contribution-verify"}:
        raise ProtocolError("unknown capability")
    expected = ECHO_REQUEST_KEYS if capability == "echo-analysis" else CONTRIBUTION_REQUEST_KEYS
    allowed = expected | ({"path"} if capability == "contribution-verify" else set())
    if set(payload) not in (expected, allowed):
        raise ProtocolError("request fields do not match tc-worker/v1 capability")
    job_id = payload["job"]
    reply = payload["reply"]
    if not isinstance(job_id, str) or not JOB_RE.fullmatch(job_id):
        raise ProtocolError("invalid job id")
    if not isinstance(reply, str) or not MAILBOX_RE.fullmatch(reply):
        raise ProtocolError("invalid reply mailbox")
    if capability == "contribution-verify":
        repository = payload["repository"]
        commit = payload["commit"]
        if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
            raise ProtocolError("invalid GitHub repository")
        if repository.endswith(".") or ".." in repository.split("/", 1)[1]:
            raise ProtocolError("invalid GitHub repository")
        if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
            raise ProtocolError("commit must be a full 40-character hexadecimal SHA")
        file_path = payload.get("path")
        if file_path is not None and (
            not isinstance(file_path, str)
            or len(file_path) > 240
            or not FILE_PATH_RE.fullmatch(file_path)
            or any(part in {".", ".."} for part in file_path.split("/"))
        ):
            raise ProtocolError("invalid repository file path")
        return ContributionRequest(
            job_id=job_id,
            reply_room=reply,
            repository=repository,
            commit_sha=commit.lower(),
            file_path=file_path,
        )
    text = payload["text"]
    if not isinstance(text, str) or not 1 <= len(text) <= MAX_TEXT_CHARS:
        raise ProtocolError("text size is outside the allowed range")
    if _has_disallowed_characters(text):
        raise ProtocolError("text contains disallowed invisible characters")
    return EchoRequest(job_id=job_id, reply_room=reply, text=text)


def canonical_request(job_id: str, reply_room: str, text: str) -> str:
    return json.dumps(
        {
            "capability": "echo-analysis",
            "job": job_id,
            "reply": reply_room,
            "text": text,
            "v": PROTOCOL_VERSION,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_contribution_request(
    job_id: str,
    reply_room: str,
    repository: str,
    commit_sha: str,
    file_path: str | None = None,
) -> str:
    payload = {
        "capability": "contribution-verify",
        "commit": commit_sha,
        "job": job_id,
        "reply": reply_room,
        "repository": repository,
        "v": PROTOCOL_VERSION,
    }
    if file_path is not None:
        payload["path"] = file_path
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def analyze(text: str) -> dict[str, int | str]:
    return {
        "ack": "analyzed",
        "characters": len(text),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "words": len(text.split()),
    }


def canonical_response(
    *,
    worker_did: str,
    requester_did: str,
    job_id: str,
    request_room: str,
    request_sequence: int,
    request_hash: str,
    result: dict[str, int | str],
) -> str:
    if not DID_RE.fullmatch(worker_did) or not DID_RE.fullmatch(requester_did):
        raise ProtocolError("response identity is not a canonical Ed25519 did:key")
    return json.dumps(
        {
            "capability": "echo-analysis",
            "job": job_id,
            "request": {
                "did": requester_did,
                "room": request_room,
                "seq": request_sequence,
                "sha256": request_hash,
            },
            "result": result,
            "status": "ok",
            "v": PROTOCOL_VERSION,
            "worker": worker_did,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_contribution_response(
    *,
    worker_did: str,
    requester_did: str,
    job_id: str,
    request_room: str,
    request_sequence: int,
    request_hash: str,
    checks: dict[str, Any],
) -> str:
    if not DID_RE.fullmatch(worker_did) or not DID_RE.fullmatch(requester_did):
        raise ProtocolError("response identity is not a canonical Ed25519 did:key")
    response = json.dumps(
        {
            "capability": "contribution-verify",
            "checks": checks,
            "claims_not_established": [
                "did_github_ownership",
                "requester_commit_authorship",
                "contribution_quality_or_acceptance",
                "flop_eligibility_or_endorsement",
            ],
            "job": job_id,
            "request": {
                "did": requester_did,
                "room": request_room,
                "seq": request_sequence,
                "sha256": request_hash,
            },
            "status": "completed",
            "v": PROTOCOL_VERSION,
            "worker": worker_did,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(response) > 4096:
        raise ProtocolError("response exceeds Technocore message limit")
    return response
