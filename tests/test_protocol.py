from __future__ import annotations

import hashlib
import json

import pytest

from worker.protocol import (
    ProtocolError,
    analyze,
    canonical_request,
    parse_request,
)

REPLY = "mb-p-0123456789abcdef01234567"


def test_valid_request_and_deterministic_analysis() -> None:
    wire = canonical_request("job-1", REPLY, "hello deterministic world")
    request = parse_request(wire)
    assert request.job_id == "job-1"
    assert request.reply_room == REPLY
    assert analyze(request.text) == {
        "ack": "analyzed",
        "characters": 25,
        "sha256": hashlib.sha256(b"hello deterministic world").hexdigest(),
        "words": 3,
    }
    assert analyze(request.text) == analyze(request.text)


@pytest.mark.parametrize(
    "wire",
    [
        "not-json",
        json.dumps({"v": "tc-worker/v1"}),
        '{"v":"tc-worker/v1","v":"tc-worker/v1","job":"x"}',
    ],
)
def test_malformed_request_rejected(wire: str) -> None:
    with pytest.raises(ProtocolError):
        parse_request(wire)


def test_unknown_capability_rejected() -> None:
    wire = canonical_request("job-1", REPLY, "hello").replace("echo-analysis", "shell")
    with pytest.raises(ProtocolError, match="unknown capability"):
        parse_request(wire)


def test_oversized_request_rejected() -> None:
    wire = canonical_request("job-1", REPLY, "a" * 513)
    with pytest.raises(ProtocolError, match="text size"):
        parse_request(wire)


def test_invalid_reply_target_rejected() -> None:
    for target in ("lobby", "https://example.com", "mb-public", "mb-p-short"):
        with pytest.raises(ProtocolError, match="reply mailbox"):
            parse_request(canonical_request("job-1", target, "hello"))
