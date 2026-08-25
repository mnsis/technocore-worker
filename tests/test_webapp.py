from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from worker.identity import public_did
from worker.protocol import canonical_contribution_request
from worker.webapp import (
    CSP,
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
    assert javascript.count("fetch(") == 5
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
        "text": canonical_contribution_request(
            "browser-test", "mb-p-0123456789abcdef01234567",
            "paiin-arc/technocore-beginner-guide",
            "93dab08e185121186d009f9b637a37365c294ea1",
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
