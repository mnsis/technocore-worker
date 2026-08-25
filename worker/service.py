from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from worker.github import GitHubVerifier, Verification
from worker.identity import public_did
from worker.protocol import (
    DID_RE,
    ContributionRequest,
    EchoRequest,
    ProtocolError,
    analyze,
    canonical_contribution_response,
    canonical_response,
    parse_request,
)
from worker.state import State
from worker.transport import Posted, Technocore

logger = logging.getLogger(__name__)


class Sender(Protocol):
    def post_signed(
        self, room: str, text: str, key: Ed25519PrivateKey, nonce: int
    ) -> Posted: ...


class ContributionVerifier(Protocol):
    def verify(
        self, repository: str, commit_sha: str, file_path: str | None = None
    ) -> Verification: ...


@dataclass(frozen=True)
class Outcome:
    status: str
    response: Posted | None = None


class Worker:
    def __init__(
        self,
        *,
        inbox: str,
        key: Ed25519PrivateKey,
        state: State,
        transport: Sender,
        verifier: ContributionVerifier | None = None,
    ):
        self.inbox = inbox
        self.key = key
        self.did = public_did(key)
        self.state = state
        self.transport = transport
        self.verifier = verifier or GitHubVerifier()

    def handle(self, record: dict[str, Any]) -> Outcome:
        requester = record.get("from")
        nonce = record.get("nonce")
        sequence = record.get("seq")
        wire_text = record.get("text")
        if (
            not isinstance(requester, str)
            or not DID_RE.fullmatch(requester)
            or not isinstance(nonce, int)
            or not isinstance(sequence, int)
            or not isinstance(wire_text, str)
        ):
            return Outcome("unsigned-or-invalid")
        try:
            request = parse_request(wire_text)
        except ProtocolError:
            return Outcome("malformed")
        request_hash = hashlib.sha256(wire_text.encode()).hexdigest()
        existing = self.state.existing_claim(requester, request.job_id, request_hash)
        if existing is not None:
            return Outcome("job-conflict" if existing.conflict else "duplicate")
        repository: str | None = None
        claimed_commit: str | None = None
        resolved_commit: str | None = None
        checks: dict[str, Any] | None = None
        if isinstance(request, EchoRequest):
            result: Any = analyze(request.text)
        elif isinstance(request, ContributionRequest):
            repository = request.repository
            claimed_commit = request.commit_sha
            verification = self.verifier.verify(repository, claimed_commit, request.file_path)
            resolved_commit = verification.resolved_sha
            checks = verification.checks
            result = {"checks": checks}
        else:  # pragma: no cover - exhaustive guard for future protocol variants
            raise TypeError("unsupported parsed request")
        claim = self.state.claim(
            job_id=request.job_id,
            requester_did=requester,
            request_room=self.inbox,
            request_sequence=sequence,
            request_hash=request_hash,
            capability=request.capability,
            result=result,
            response_room=request.reply_room,
            repository=repository,
            claimed_commit_sha=claimed_commit,
            resolved_commit_sha=resolved_commit,
            checks=checks,
            requested_file_path=request.file_path if isinstance(request, ContributionRequest) else None,
        )
        if not claim.inserted:
            return Outcome("job-conflict" if claim.conflict else "duplicate")
        if isinstance(request, ContributionRequest):
            if checks is None:
                raise RuntimeError("contribution checks were not produced")
            response_text = canonical_contribution_response(
                worker_did=self.did,
                requester_did=requester,
                job_id=request.job_id,
                request_room=self.inbox,
                request_sequence=sequence,
                request_hash=request_hash,
                checks=checks,
            )
        else:
            response_text = canonical_response(
                worker_did=self.did,
                requester_did=requester,
                job_id=request.job_id,
                request_room=self.inbox,
                request_sequence=sequence,
                request_hash=request_hash,
                result=result,
            )
        outbound_nonce = self.state.next_nonce(request.reply_room, time.time_ns())
        posted = self.transport.post_signed(request.reply_room, response_text, self.key, outbound_nonce)
        self.state.complete(requester, request.job_id, posted.sequence)
        return Outcome("completed", posted)


def run_forever(*, inbox: str, key: Ed25519PrivateKey, state: State) -> None:
    transport = Technocore()
    worker = Worker(inbox=inbox, key=key, state=state, transport=transport)
    cursor = state.cursor(inbox)
    failures = 0
    while True:
        try:
            response = transport.read(inbox, since=cursor, wait=10)
            first_seq = response.get("first_seq")
            if isinstance(first_seq, int) and first_seq > cursor + 1:
                logger.warning("mailbox sequence gap: expected %s, received %s", cursor + 1, first_seq)
            for record in response.get("messages", []):
                sequence = record.get("seq")
                if isinstance(sequence, int) and sequence > cursor:
                    worker.handle(record)
                    cursor = sequence
                    state.set_cursor(inbox, cursor)
            failures = 0
        except Exception:
            failures += 1
            logger.exception("poll cycle failed")
            time.sleep(min(30, 2**min(failures, 5)))
