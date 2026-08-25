from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from worker.identity import load_identity, public_did


def test_browser_python_pem_and_signature_interoperability(tmp_path: Path) -> None:
    passphrase = "correct horse battery staple"
    payload = "mb-technocore-worker|123|controlled-test-text"
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    )
    (tmp_path / "python.pem").write_bytes(pem)
    (tmp_path / "python.json").write_text(
        json.dumps(
            {
                "did": public_did(key),
                "passphrase": passphrase,
                "payload": payload,
                "signature": base64.urlsafe_b64encode(key.sign(payload.encode()))
                .rstrip(b"=")
                .decode(),
            }
        )
    )
    environment = dict(os.environ, NODE_NO_WARNINGS="1")
    subprocess.run(
        ["node", "tests/browser_interop.mjs", str(tmp_path)],
        check=True,
        cwd=Path(__file__).parents[1],
        env=environment,
    )
    browser = json.loads((tmp_path / "browser.json").read_text())
    browser_key = serialization.load_pem_private_key(
        (tmp_path / "browser.pem").read_bytes(), password=passphrase.encode()
    )
    assert isinstance(browser_key, Ed25519PrivateKey)
    assert public_did(browser_key) == browser["did"]
    assert public_did(load_identity(tmp_path / "browser.pem", passphrase.encode())) == browser["did"]
    signature = base64.urlsafe_b64decode(browser["signature"] + "==")
    browser_key.public_key().verify(signature, payload.encode())
