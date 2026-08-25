from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_MULTICODEC_ED25519 = b"\xed\x01"


def _b58encode(raw: bytes) -> str:
    zeros = len(raw) - len(raw.lstrip(b"\0"))
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _B58[remainder] + encoded
    return "1" * zeros + encoded


def public_did(key: Ed25519PrivateKey) -> str:
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "did:key:z" + _b58encode(_MULTICODEC_ED25519 + public)


def _b58decode(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            digit = _B58.index(character)
        except ValueError as error:
            raise ValueError("invalid base58btc DID") from error
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + decoded


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not isinstance(did, str) or not did.startswith("did:key:z6Mk") or len(did) != 56:
        raise ValueError("invalid canonical Ed25519 did:key")
    decoded = _b58decode(did.removeprefix("did:key:z"))
    if len(decoded) != 34 or not decoded.startswith(_MULTICODEC_ED25519):
        raise ValueError("DID is not an Ed25519 did:key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def generate_identity(path: Path) -> str:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
        handle.flush()
        os.fsync(handle.fileno())
    return public_did(key)


def load_identity(path: Path, password: bytes | None = None) -> Ed25519PrivateKey:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(f"identity file must be mode 0600, got {mode:04o}")
    loaded = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError("identity is not an Ed25519 private key")
    return loaded


def sign_message(key: Ed25519PrivateKey, room: str, nonce: int, text: str) -> str:
    payload = f"{room}|{nonce}|{text}".encode()
    return base64.urlsafe_b64encode(key.sign(payload)).rstrip(b"=").decode("ascii")
