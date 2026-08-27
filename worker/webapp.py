from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

from cryptography.exceptions import InvalidSignature

from worker import PROTOCOL_V2
from worker.collector import ReplyCollector
from worker.identity import public_key_from_did
from worker.protocol import DID_RE, ContributionRequest, parse_request
from worker.transport import BASE_URL

CHALLENGE_TTL_SECONDS = 120
MAX_REQUEST_BYTES = 4096
MAX_URL_BYTES = 1024
MAX_SESSION_BINDINGS = 4096
PURPOSE = "technocore-browser-did-control-v1"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self'; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


def validate_public_envelope(body: dict[str, Any]) -> dict[str, str]:
    if set(body) != {"did", "nonce", "sig", "text"}:
        raise ValueError("Only public signed-write fields are accepted.")
    if not all(isinstance(body.get(field), str) for field in body):
        raise ValueError("Signed-write fields must be strings.")
    did, nonce, signature, text = body["did"], body["nonce"], body["sig"], body["text"]
    if not DID_RE.fullmatch(did) or not nonce.isascii() or not nonce.isdigit() or not 1 <= len(nonce) <= 19:
        raise ValueError("Malformed signed-write identity or nonce.")
    if len(signature) != 86 or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in signature):
        raise ValueError("Malformed signed-write signature.")
    request = parse_request(text)
    if not isinstance(request, ContributionRequest):
        raise TypeError("Only contribution-verify requests are accepted.")
    if request.version != PROTOCOL_V2:
        raise ValueError("The public browser accepts tc-worker/v2 requests only.")
    return {"did": did, "nonce": nonce, "sig": signature, "text": text}


def technocore_request(body: dict[str, str]) -> dict[str, Any]:
    encoded = json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(
        f"{BASE_URL}/r/mb-technocore-worker?format=json",
        data=encoded,
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        result = json.load(response)
    if not isinstance(result, dict):
        raise TypeError("Technocore returned malformed JSON.")
    return result


@dataclass
class Challenge:
    value: str
    payload: str
    expires_at: int
    session: str
    origin: str
    used: bool = False


class ChallengeStore:
    def __init__(self, *, clock: Any = time.time, max_items: int = 4096) -> None:
        self._clock = clock
        self._max_items = max_items
        self._items: dict[str, Challenge] = {}
        self._lock = threading.Lock()

    def create(self, *, origin: str, session: str) -> Challenge:
        now = int(self._clock())
        value = secrets.token_urlsafe(24)
        expires = now + CHALLENGE_TTL_SECONDS
        payload = f"{PURPOSE}|{origin}|{session}|{value}|{expires}"
        challenge = Challenge(
            value=value, payload=payload, expires_at=expires, session=session, origin=origin
        )
        with self._lock:
            self._items[value] = challenge
            self._prune(now)
            while len(self._items) > self._max_items:
                del self._items[next(iter(self._items))]
        return challenge

    def consume(self, value: str, *, session: str, origin: str) -> Challenge:
        now = int(self._clock())
        with self._lock:
            challenge = self._items.get(value)
            if challenge is None or challenge.used:
                raise ValueError("Challenge is unknown or has already been used.")
            challenge.used = True
            if not secrets.compare_digest(challenge.session, session) or challenge.origin != origin:
                raise ValueError("Challenge does not belong to this browser session.")
            if now > challenge.expires_at:
                raise ValueError("Challenge has expired.")
            return challenge

    def _prune(self, now: int) -> None:
        stale = [key for key, item in self._items.items() if item.expires_at + 60 < now]
        for key in stale:
            del self._items[key]


def verify_challenge(
    store: ChallengeStore, body: dict[str, Any], *, session: str, origin: str
) -> str:
    if set(body) != {"did", "challenge", "signature"}:
        raise ValueError("Only DID, challenge, and signature are accepted.")
    did, value, signature = body["did"], body["challenge"], body["signature"]
    if not all(isinstance(item, str) for item in (did, value, signature)):
        raise ValueError("Challenge proof fields must be strings.")
    assert isinstance(did, str) and isinstance(value, str) and isinstance(signature, str)
    if len(value) > 64 or len(signature) != 86:
        raise ValueError("Malformed challenge proof.")
    challenge = store.consume(value, session=session, origin=origin)
    try:
        raw = base64.urlsafe_b64decode(signature + "==")
        public_key_from_did(did).verify(raw, challenge.payload.encode())
    except (ValueError, InvalidSignature) as error:
        raise ValueError("Challenge signature is invalid.") from error
    return did


class RateLimiter:
    def __init__(self, *, clock: Any = time.monotonic, max_keys: int = 4096) -> None:
        self._clock = clock
        self._max_keys = max_keys
        self._items: dict[tuple[str, str], tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str, bucket: str, *, limit: int, window: int = 60) -> bool:
        now = self._clock()
        key = (client, bucket)
        with self._lock:
            started, count = self._items.get(key, (now, 0))
            if now - started >= window:
                started, count = now, 0
            if count >= limit:
                return False
            self._items[key] = (started, count + 1)
            if len(self._items) > self._max_keys:
                oldest = min(self._items, key=lambda item: self._items[item][0])
                del self._items[oldest]
        return True


class PrototypeHandler(SimpleHTTPRequestHandler):
    store = ChallengeStore()
    limiter = RateLimiter()
    allowed_hosts = frozenset({"127.0.0.1:18787"})
    allowed_origins = frozenset({"http://127.0.0.1:18787"})
    secure_cookie = False
    served_commit = "development"
    web_root = Path(__file__).resolve().parents[1] / "web"
    collector: ReplyCollector | None = None
    session_dids: ClassVar[dict[str, str]] = {}
    session_baselines: ClassVar[dict[str, int]] = {}
    session_lock = threading.Lock()

    @classmethod
    def _prune_session_bindings(cls) -> None:
        while len(cls.session_dids) > MAX_SESSION_BINDINGS:
            stale = next(iter(cls.session_dids))
            del cls.session_dids[stale]
            cls.session_baselines.pop(stale, None)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(self.web_root), **kwargs)

    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        if self.secure_cookie:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        super().end_headers()

    def _request_origin(self) -> str:
        origin = self.headers.get("Origin")
        if origin not in self.allowed_origins:
            raise ValueError("Missing or disallowed Origin header.")
        referer = self.headers.get("Referer")
        if referer is not None and not any(
            referer == allowed + "/" or referer.startswith(allowed + "/")
            for allowed in self.allowed_origins
        ):
            raise ValueError("Disallowed Referer header.")
        if self.headers.get("Sec-Fetch-Site") not in {None, "same-origin"}:
            raise ValueError("Cross-origin browser request rejected.")
        return origin

    def _valid_host(self) -> bool:
        return self.headers.get("Host") in self.allowed_hosts

    def _session(self, *, create: bool = False) -> tuple[str, bool]:
        cookies = self.headers.get("Cookie", "")
        values = [part.strip()[11:] for part in cookies.split(";") if part.strip().startswith("tc_session=")]
        if len(values) == 1 and len(values[0]) == 32 and values[0].isalnum():
            return values[0], False
        if create:
            return secrets.token_hex(16), True
        raise ValueError("Missing browser session.")

    def _rate_limit(self, bucket: str, limit: int) -> bool:
        if self.limiter.allow(self.client_address[0], bucket, limit=limit):
            return True
        self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Rate limit exceeded."})
        return False

    def _reject_bad_host(self) -> bool:
        if self._valid_host():
            return False
        self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "Unexpected Host header."})
        return True

    def do_GET(self) -> None:
        if self._reject_bad_host():
            return
        if len(self.path.encode("utf-8", "surrogatepass")) > MAX_URL_BYTES:
            self._json(HTTPStatus.REQUEST_URI_TOO_LONG, {"error": "Request URL is too long."})
            return
        if self.path == "/api/challenge":
            if not self._rate_limit("challenge-create", 20):
                return
            session, created = self._session(create=True)
            origin = next(iter(self.allowed_origins))
            challenge = self.store.create(origin=origin, session=session)
            cookie = f"tc_session={session}; HttpOnly; SameSite=Strict; Path=/"
            if self.secure_cookie:
                cookie += "; Secure"
            headers = {"Set-Cookie": cookie} if created else {}
            self._json(
                HTTPStatus.OK,
                {
                    "challenge": challenge.value,
                    "payload": challenge.payload,
                    "expires_at": challenge.expires_at,
                    "purpose": PURPOSE,
                },
                headers=headers,
            )
            return
        if self.path == "/api/meta":
            self._json(
                HTTPStatus.OK,
                {"commit": self.served_commit, "protocol": PROTOCOL_V2},
            )
            return
        if self.path == "/api/reply-baseline":
            try:
                session, _ = self._session()
                with self.session_lock:
                    if session not in self.session_dids:
                        raise ValueError("DID control is required.")
                if self.collector is None:
                    raise RuntimeError("Reply collector is unavailable.")
                baseline = self.collector.baseline()
                with self.session_lock:
                    self.session_baselines[session] = baseline
                self._json(HTTPStatus.OK, {"reply_after": baseline})
            except ValueError as error:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            except RuntimeError as error:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(error)})
            return
        if self.path == "/api/collector/health":
            health = self.collector.health() if self.collector else None
            self._json(
                HTTPStatus.OK if health and health.status != "degraded" else HTTPStatus.SERVICE_UNAVAILABLE,
                {"status": health.status, "cursor": health.cursor} if health else {"status": "unavailable"},
            )
            return
        if self.path.startswith("/api/jobs/"):
            if not self._rate_limit("reply", 120):
                return
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, strict_parsing=True)
                if set(query) != {"did", "sha256", "n"} or any(len(value) != 1 for value in query.values()):
                    raise ValueError("Malformed local job query.")
                job = urllib.parse.urlsplit(self.path).path.removeprefix("/api/jobs/")
                if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", job):
                    raise ValueError("Malformed job ID.")
                if not DID_RE.fullmatch(query["did"][0]) or not re.fullmatch(
                    r"[0-9a-f]{64}", query["sha256"][0]
                ) or not query["n"][0].isdigit():
                    raise ValueError("Malformed local job query.")
                session, _ = self._session()
                if self.collector is None:
                    raise RuntimeError("Reply collector is unavailable.")
                result = self.collector.wait_result(
                    session=session, job=job, did=query["did"][0],
                    request_hash=query["sha256"][0], timeout=10,
                )
            except ValueError as error:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            except RuntimeError as error:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(error)})
                return
            self._json(HTTPStatus.OK, {"result": result})
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self._reject_bad_host():
            return
        if self.path not in {"/api/challenge/verify", "/api/technocore/request"}:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return
        try:
            origin = self._request_origin()
            bucket = "challenge-verify" if self.path == "/api/challenge/verify" else "forward"
            limit = 20 if self.path == "/api/challenge/verify" else 5
            if not self._rate_limit(bucket, limit):
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_REQUEST_BYTES:
                raise ValueError("Invalid request size.")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("Content-Type must be application/json.")
            raw = self.rfile.read(length)
            body = json.loads(raw.decode("utf-8"))
            if not isinstance(body, dict):
                raise TypeError("Request body must be an object.")
            if self.path == "/api/challenge/verify":
                session, _ = self._session()
                proved_did = verify_challenge(self.store, body, session=session, origin=origin)
                with self.session_lock:
                    self.session_dids[session] = proved_did
                    self._prune_session_bindings()
            else:
                envelope = validate_public_envelope(body)
                session, _ = self._session()
                request = parse_request(envelope["text"])
                if not isinstance(request, ContributionRequest) or request.reply_after is None:
                    raise ValueError("Malformed tc-worker/v2 request.")
                with self.session_lock:
                    if self.session_dids.get(session) != envelope["did"]:
                        raise ValueError("Request DID does not match this browser session.")
                    issued = self.session_baselines.get(session)
                if issued is None or request.reply_after != issued:
                    raise ValueError("Request baseline was not issued to this browser session.")
                if self.collector is None:
                    raise RuntimeError("Reply collector is unavailable.")
                digest = hashlib.sha256(envelope["text"].encode()).hexdigest()
                self.collector.register(
                    session=session, job=request.job_id, did=envelope["did"],
                    request_hash=digest, reply_after=request.reply_after,
                )
                result = technocore_request(envelope)
                posted = result.get("posted")
                if not isinstance(posted, dict) or not isinstance(posted.get("seq"), int):
                    raise RuntimeError("Technocore returned malformed request provenance.")
                self.collector.confirm_registration(
                    session=session, job=request.job_id, request_sequence=posted["seq"]
                )
        except RuntimeError as error:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(error)})
            return
        except (TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        if self.path == "/api/technocore/request":
            self._json(HTTPStatus.OK, result)
        else:
            self._json(
                HTTPStatus.OK,
                {"result": "Control of this DID was demonstrated for this session."},
            )

    def _json(
        self, status: HTTPStatus, payload: dict[str, Any], *, headers: dict[str, str] | None = None
    ) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:
        # Deliberately omit request bodies, query data, and user-agent details.
        return


def serve(
    host: str = "127.0.0.1",
    port: int = 18787,
    *,
    public_origin: str | None = None,
    request_host: str | None = None,
    served_commit: str = "development",
    collector_database: Path | None = None,
    worker_did: str | None = None,
) -> None:
    origin = public_origin or f"http://{host}:{port}"
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("public origin must be an exact http(s) origin without a path")
    # The browser Origin allowlist is exactly this one public origin. The accepted Host
    # header defaults to that origin's host, but can be set independently for the case
    # where a front proxy forwards the browser Origin yet presents this server's own host.
    accepted_host = request_host or parsed.netloc
    if not accepted_host or any(character in accepted_host for character in "/@ \t"):
        raise ValueError("request host must be a bare host[:port] value")
    PrototypeHandler.allowed_origins = frozenset({origin})
    PrototypeHandler.allowed_hosts = frozenset({accepted_host})
    PrototypeHandler.secure_cookie = parsed.scheme == "https"
    if served_commit != "development" and (
        len(served_commit) != 40 or any(character not in "0123456789abcdef" for character in served_commit)
    ):
        raise ValueError("served commit must be a full lowercase Git commit SHA")
    PrototypeHandler.served_commit = served_commit
    PrototypeHandler.store = ChallengeStore()
    PrototypeHandler.limiter = RateLimiter()
    PrototypeHandler.session_dids = {}
    PrototypeHandler.session_baselines = {}
    collector = None
    if collector_database is not None and worker_did is not None:
        collector = ReplyCollector(collector_database, worker_did=worker_did)
        collector.start()
    PrototypeHandler.collector = collector
    try:
        ThreadingHTTPServer((host, port), PrototypeHandler).serve_forever()
    finally:
        if collector is not None:
            collector.stop()
