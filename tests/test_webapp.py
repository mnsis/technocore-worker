from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from worker.identity import public_did, sign_message
from worker.protocol import canonical_contribution_request_v2
from worker.webapp import (
    CSP,
    MAX_SESSION_BINDINGS,
    ChallengeStore,
    PrototypeHandler,
    RateLimiter,
    validate_public_envelope,
    verify_challenge,
)

SESSION = "0123456789abcdef0123456789abcdef"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def proof(key: Ed25519PrivateKey, challenge: str, payload: str) -> dict[str, str]:
    signature = base64.urlsafe_b64encode(key.sign(payload.encode())).rstrip(b"=").decode()
    return {"did": public_did(key), "challenge": challenge, "signature": signature}


def test_challenge_is_bound_verified_and_single_use() -> None:
    clock = Clock()
    store = ChallengeStore(clock=clock)
    origin = "http://127.0.0.1:8787"
    challenge = store.create(origin=origin, session=SESSION)
    assert "technocore-browser-did-control-v1|http://127.0.0.1:8787|" in challenge.payload
    body = proof(Ed25519PrivateKey.generate(), challenge.value, challenge.payload)
    verify_challenge(store, body, session=SESSION, origin=origin)
    with pytest.raises(ValueError, match="already been used"):
        verify_challenge(store, body, session=SESSION, origin=origin)


def test_challenge_expiry_and_bad_signature() -> None:
    clock = Clock()
    store = ChallengeStore(clock=clock)
    origin = "http://localhost:8787"
    challenge = store.create(origin=origin, session=SESSION)
    body = proof(Ed25519PrivateKey.generate(), challenge.value, challenge.payload)
    clock.now += 121
    with pytest.raises(ValueError, match="expired"):
        verify_challenge(store, body, session=SESSION, origin=origin)
    other = store.create(origin=origin, session=SESSION)
    wrong = proof(Ed25519PrivateKey.generate(), other.value, "wrong payload")
    with pytest.raises(ValueError, match="invalid"):
        verify_challenge(store, wrong, session=SESSION, origin=origin)


def test_challenge_rejects_another_session_and_consumes_token() -> None:
    origin = "http://127.0.0.1:8787"
    store = ChallengeStore()
    challenge = store.create(origin=origin, session=SESSION)
    body = proof(Ed25519PrivateKey.generate(), challenge.value, challenge.payload)
    with pytest.raises(ValueError, match="browser session"):
        verify_challenge(store, body, session="f" * 32, origin=origin)
    with pytest.raises(ValueError, match="already been used"):
        verify_challenge(store, body, session=SESSION, origin=origin)


@pytest.mark.parametrize(
    "extra",
    [
        {"passphrase": "secret"},
        {"pem": "-----BEGIN ENCRYPTED PRIVATE KEY-----"},
        {"private_key": "bytes"},
        {"seed_phrase": "words"},
    ],
)
def test_challenge_endpoint_schema_rejects_private_material(extra: dict[str, str]) -> None:
    store = ChallengeStore()
    origin = "http://localhost:8787"
    challenge = store.create(origin=origin, session=SESSION)
    body = proof(Ed25519PrivateKey.generate(), challenge.value, challenge.payload) | extra
    with pytest.raises(ValueError, match="Only DID, challenge, and signature"):
        verify_challenge(store, body, session=SESSION, origin=origin)


def test_static_network_and_csp_audit() -> None:
    root = Path(__file__).parents[1]
    javascript = "\n".join(path.read_text() for path in (root / "web").glob("*.js"))
    html = (root / "web/index.html").read_text()
    assert javascript.count("fetch(") == 6
    assert "https://technocore.chat" not in javascript
    assert not any(term in javascript for term in ("localStorage", "sessionStorage", "indexedDB", "document.cookie"))
    assert not any(term in javascript for term in ("console.log", "console.debug", "console.info"))
    assert "privateKey" not in json.dumps({"did": "public", "challenge": "public", "signature": "public"})
    required = (
        "default-src 'self'", "script-src 'self'", "style-src 'self'",
        "connect-src 'self'", "object-src 'none'",
        "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'",
    )
    assert all(directive in CSP for directive in required)
    assert all(directive in html for directive in required if not directive.startswith("frame-ancestors"))
    assert "frame-ancestors" not in html
    assert {part.split('"')[0] for part in html.split('href="https://')[1:]} == {
        "github.com/mnsis/technocore-worker", "x.com/amjawaeth", "x.com/flop_labs"
    }


def test_public_transport_endpoint_rejects_private_fields() -> None:
    body = {
        "did": "did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM",
        "nonce": "123",
        "sig": "A" * 86,
        "text": canonical_contribution_request_v2(
            "browser-test",
            "paiin-arc/technocore-beginner-guide",
            "93dab08e185121186d009f9b637a37365c294ea1",
            0,
        ),
    }
    assert validate_public_envelope(body) == body
    for field in ("pem", "passphrase", "private_key", "seed_phrase"):
        with pytest.raises(ValueError, match="Only public"):
            validate_public_envelope(body | {field: "secret"})


def test_rate_limiter_is_bounded_and_resets() -> None:
    clock = Clock()
    limiter = RateLimiter(clock=clock, max_keys=2)
    assert limiter.allow("client", "write", limit=2)
    assert limiter.allow("client", "write", limit=2)
    assert not limiter.allow("client", "write", limit=2)
    clock.now += 61
    assert limiter.allow("client", "write", limit=2)
    assert limiter.allow("second", "write", limit=1)
    assert limiter.allow("third", "write", limit=1)
    assert len(limiter._items) <= 2


def test_challenge_store_is_bounded() -> None:
    store = ChallengeStore(max_items=2)
    first = store.create(origin="http://127.0.0.1:8787", session=SESSION)
    store.create(origin="http://127.0.0.1:8787", session=SESSION)
    store.create(origin="http://127.0.0.1:8787", session=SESSION)
    assert len(store._items) == 2
    with pytest.raises(ValueError, match="unknown"):
        store.consume(first.value, session=SESSION, origin="http://127.0.0.1:8787")


def test_browser_session_bindings_are_bounded() -> None:
    PrototypeHandler.session_dids = {
        f"{item:032x}": "did" for item in range(MAX_SESSION_BINDINGS + 1)
    }
    PrototypeHandler.session_baselines = {f"{item:032x}": item for item in range(2)}
    PrototypeHandler._prune_session_bindings()
    assert len(PrototypeHandler.session_dids) == MAX_SESSION_BINDINGS
    assert f"{0:032x}" not in PrototypeHandler.session_dids
    assert f"{0:032x}" not in PrototypeHandler.session_baselines


@pytest.fixture
def web_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), PrototypeHandler)
    port = server.server_address[1]
    origin = f"http://127.0.0.1:{port}"
    PrototypeHandler.allowed_hosts = frozenset({f"127.0.0.1:{port}"})
    PrototypeHandler.allowed_origins = frozenset({origin})
    PrototypeHandler.secure_cookie = False
    PrototypeHandler.store = ChallengeStore()
    PrototypeHandler.limiter = RateLimiter()
    PrototypeHandler.session_dids = {}
    PrototypeHandler.session_baselines = {}
    PrototypeHandler.collector = None
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield origin
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def http_status(request: urllib.request.Request) -> int:
    try:
        with urllib.request.urlopen(request) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return error.code


def test_host_origin_content_type_and_body_controls(web_server: str) -> None:
    assert http_status(urllib.request.Request(web_server + "/", headers={"Host": "evil.example"})) == 421
    assert http_status(urllib.request.Request(web_server + "/", headers={"Host": "attacker.test"})) == 421

    endpoint = web_server + "/api/technocore/request"
    valid_headers = {"Content-Type": "application/json", "Origin": web_server}
    assert http_status(urllib.request.Request(endpoint, data=b"{}", headers={"Content-Type": "application/json"})) == 400
    assert http_status(urllib.request.Request(endpoint, data=b"{}", headers={**valid_headers, "Origin": "https://evil.example"})) == 400
    assert http_status(urllib.request.Request(endpoint, data=b"{}", headers={**valid_headers, "Referer": "https://evil.example/"})) == 400
    assert http_status(urllib.request.Request(endpoint, data=b"{}", headers={"Origin": web_server})) == 400
    oversized = urllib.request.Request(endpoint, data=b"{" + b" " * 4096, headers=valid_headers)
    assert http_status(oversized) == 400
    malformed = urllib.request.Request(endpoint, data=b'"\xff"', headers=valid_headers)
    assert http_status(malformed) == 400


def test_security_headers(web_server: str) -> None:
    with urllib.request.urlopen(web_server + "/") as response:
        assert response.headers["Content-Security-Policy"] == CSP
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
        assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert response.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"


def test_http_challenge_rate_limit(web_server: str) -> None:
    for _ in range(20):
        assert http_status(urllib.request.Request(web_server + "/api/challenge")) == 200
    assert http_status(urllib.request.Request(web_server + "/api/challenge")) == 429


def test_local_v2_job_registration_binds_session_digest_and_sequence(
    web_server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeCollector:
        def __init__(self) -> None:
            self.registered: dict[str, Any] | None = None
            self.confirmed: dict[str, Any] | None = None

        def baseline(self) -> int: return 4
        def register(self, **values: Any) -> None: self.registered = values
        def confirm_registration(self, **values: Any) -> None: self.confirmed = values

    fake = FakeCollector()
    PrototypeHandler.collector = fake  # type: ignore[assignment]
    monkeypatch.setattr("worker.webapp.technocore_request", lambda body: {"posted": {"seq": 17}})
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    with opener.open(web_server + "/api/challenge") as response:
        challenge = json.load(response)
    key = Ed25519PrivateKey.generate()
    verify_body = json.dumps(proof(key, challenge["challenge"], challenge["payload"])).encode()
    opener.open(urllib.request.Request(
        web_server + "/api/challenge/verify", data=verify_body,
        headers={"Content-Type": "application/json", "Origin": web_server},
    )).close()
    with opener.open(web_server + "/api/reply-baseline") as response:
        assert json.load(response) == {"reply_after": 4}
    did = public_did(key)
    text = canonical_contribution_request_v2(
        "browser-bound", "paiin-arc/technocore-beginner-guide",
        "93dab08e185121186d009f9b637a37365c294ea1", 4,
    )
    envelope = {
        "did": did, "nonce": "123", "sig": sign_message(key, "mb-technocore-worker", 123, text),
        "text": text,
    }
    opener.open(urllib.request.Request(
        web_server + "/api/technocore/request", data=json.dumps(envelope).encode(),
        headers={"Content-Type": "application/json", "Origin": web_server},
    )).close()
    digest = hashlib.sha256(text.encode()).hexdigest()
    assert fake.registered is not None
    assert fake.registered["did"] == did and fake.registered["request_hash"] == digest
    assert fake.confirmed == {
        "session": fake.registered["session"], "job": "browser-bound", "request_sequence": 17,
    }


class _StubServer:
    """Stand-in for ThreadingHTTPServer so serve()'s config wiring can be exercised."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def serve_forever(self) -> None:
        pass


def _configure(monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> None:
    from worker import webapp

    monkeypatch.setattr(webapp, "ThreadingHTTPServer", _StubServer)
    webapp.serve("127.0.0.1", 0, **kwargs)


def test_serve_decouples_request_host_from_public_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(
        monkeypatch,
        public_origin="https://technocore-worker.vercel.app",
        request_host="worker.37.27.18.191.sslip.io",
    )
    assert PrototypeHandler.allowed_origins == frozenset({"https://technocore-worker.vercel.app"})
    assert PrototypeHandler.allowed_hosts == frozenset({"worker.37.27.18.191.sslip.io"})
    assert PrototypeHandler.secure_cookie is True


def test_serve_request_host_defaults_to_public_origin_host(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, public_origin="https://worker.37.27.18.191.sslip.io")
    assert PrototypeHandler.allowed_hosts == frozenset({"worker.37.27.18.191.sslip.io"})
    assert PrototypeHandler.allowed_origins == frozenset({"https://worker.37.27.18.191.sslip.io"})


@pytest.mark.parametrize("bad", ["evil/../x", "https://evil.test", "a b", "user@host"])
def test_serve_rejects_malformed_request_host(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    with pytest.raises(ValueError):
        _configure(monkeypatch, public_origin="https://example.test", request_host=bad)
