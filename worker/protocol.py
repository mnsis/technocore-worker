from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from worker import PROTOCOL_V1, PROTOCOL_V2, SHARED_REPLY_ROOM

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
CONTRIBUTION_V2_KEYS = {
    "v", "job", "capability", "repository", "commit", "reply_after"
}


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
    reply_after: int | None = None
    version: str = PROTOCOL_V1
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
    version = payload.get("v")
    if version not in {PROTOCOL_V1, PROTOCOL_V2}:
        raise ProtocolError("unsupported protocol version")
    capability = payload.get("capability")
    if capability not in {"echo-analysis", "contribution-verify"}:
        raise ProtocolError("unknown capability")
    if version == PROTOCOL_V2 and capability != "contribution-verify":
        raise ProtocolError("tc-worker/v2 supports contribution-verify only")
    expected = (
        ECHO_REQUEST_KEYS if capability == "echo-analysis"
        else CONTRIBUTION_V2_KEYS if version == PROTOCOL_V2
        else CONTRIBUTION_REQUEST_KEYS
    )
    allowed = expected | ({"path"} if capability == "contribution-verify" else set())
    if set(payload) not in (expected, allowed):
        raise ProtocolError("request fields do not match tc-worker/v1 capability")
    job_id = payload["job"]
    reply = payload.get("reply", SHARED_REPLY_ROOM)
    if not isinstance(job_id, str) or not JOB_RE.fullmatch(job_id):
        raise ProtocolError("invalid job id")
    if version == PROTOCOL_V2 and "reply" in payload:
        raise ProtocolError("tc-worker/v2 does not accept a reply target")
    if version == PROTOCOL_V1 and (not isinstance(reply, str) or not MAILBOX_RE.fullmatch(reply)):
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
        reply_after = payload.get("reply_after")
        if version == PROTOCOL_V2 and (
            not isinstance(reply_after, int) or isinstance(reply_after, bool)
            or not 0 <= reply_after <= 2**63 - 1
        ):
            raise ProtocolError("invalid shared reply baseline")
        return ContributionRequest(
            job_id=job_id,
            reply_room=reply,
            repository=repository,
            commit_sha=commit.lower(),
            file_path=file_path,
            reply_after=reply_after,
            version=version,
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
            "v": PROTOCOL_V1,
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
        "v": PROTOCOL_V1,
    }
    if file_path is not None:
        payload["path"] = file_path
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_contribution_request_v2(
    job_id: str,
    repository: str,
    commit_sha: str,
    reply_after: int,
    file_path: str | None = None,
) -> str:
    payload: dict[str, Any] = {
        "capability": "contribution-verify",
        "commit": commit_sha.lower(),
        "job": job_id,
        "reply_after": reply_after,
        "repository": repository,
        "v": PROTOCOL_V2,
    }
    if file_path is not None:
        payload["path"] = file_path
    wire = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    parsed = parse_request(wire)
    if not isinstance(parsed, ContributionRequest):  # pragma: no cover
        raise ProtocolError("canonical v2 request was not contribution-verify")
    return wire


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
            "v": PROTOCOL_V1,
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
    version: str = PROTOCOL_V1,
    reply_after: int | None = None,
) -> str:
    if not DID_RE.fullmatch(worker_did) or not DID_RE.fullmatch(requester_did):
        raise ProtocolError("response identity is not a canonical Ed25519 did:key")
    request_provenance: dict[str, Any] = {
        "did": requester_did,
        "room": request_room,
        "seq": request_sequence,
        "sha256": request_hash,
    }
    if version == PROTOCOL_V2:
        if reply_after is None:
            raise ProtocolError("v2 response requires shared reply baseline")
        request_provenance["reply_after"] = reply_after
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
            "request": request_provenance,
            "status": "completed",
            "v": version,
            "worker": worker_did,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(response) > 4096:
        raise ProtocolError("response exceeds Technocore message limit")
    return response


def parse_contribution_response_v2(
    record: dict[str, Any], *, worker_did: str
) -> dict[str, Any] | None:
    if record.get("from") != worker_did or not isinstance(record.get("seq"), int):
        return None
    text = record.get("text")
    if not isinstance(text, str) or len(text) > 4096:
        return None
    try:
        payload = json.loads(text, object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, ProtocolError, TypeError):
        return None
    if not isinstance(payload, dict) or set(payload) != {
        "capability", "checks", "claims_not_established", "job", "request",
        "status", "v", "worker",
    }:
        return None
    request = payload.get("request")
    checks = payload.get("checks")
    claims = payload.get("claims_not_established")
    if (
        payload.get("v") != PROTOCOL_V2
        or payload.get("capability") != "contribution-verify"
        or payload.get("status") != "completed"
        or payload.get("worker") != worker_did
        or not isinstance(payload.get("job"), str)
        or not JOB_RE.fullmatch(payload["job"])
        or not isinstance(request, dict)
        or set(request) != {"did", "room", "seq", "sha256", "reply_after"}
        or not isinstance(request.get("did"), str)
        or not DID_RE.fullmatch(request["did"])
        or request.get("room") != "mb-technocore-worker"
        or not isinstance(request.get("seq"), int)
        or not isinstance(request.get("reply_after"), int)
        or not isinstance(request.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", request["sha256"])
        or record["seq"] <= request["reply_after"]
        or not isinstance(checks, dict)
        or set(checks) != {"repository", "commit", "requested_file"}
        or not all(isinstance(item, dict) for item in checks.values())
        or any(
            item.get("status") not in {
                "CONFIRMED", "NOT_FOUND", "NOT_CHECKED", "UNAVAILABLE"
            }
            for item in checks.values()
        )
        or claims != [
            "did_github_ownership",
            "requester_commit_authorship",
            "contribution_quality_or_acceptance",
            "flop_eligibility_or_endorsement",
        ]
    ):
        return None
    return payload
