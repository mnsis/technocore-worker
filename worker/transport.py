from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from worker.identity import public_did, sign_message

ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
BASE_URL = "https://technocore.chat"


@dataclass(frozen=True)
class Posted:
    room: str
    sequence: int
    timestamp: str


class Technocore:
    def __init__(self, *, timeout: float = 20.0):
        self.timeout = timeout

    def read(self, room: str, *, since: int, wait: float = 10.0) -> dict[str, Any]:
        if not ROOM_RE.fullmatch(room):
            raise ValueError("invalid room")
        query = urllib.parse.urlencode(
            {"format": "json", "since": since, "limit": 200, "wait": wait, "n": since}
        )
        request = urllib.request.Request(
            f"{BASE_URL}/r/{room}?{query}",
            headers={"Accept": "application/json", "User-Agent": "technocore-worker/0.1"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = json.load(response)
        if not isinstance(payload, dict):
            raise TypeError("Technocore room response is not an object")
        return payload

    def post_signed(
        self, room: str, text: str, key: Ed25519PrivateKey, nonce: int
    ) -> Posted:
        if not ROOM_RE.fullmatch(room):
            raise ValueError("invalid room")
        body = json.dumps(
            {
                "did": public_did(key),
                "nonce": str(nonce),
                "sig": sign_message(key, room, nonce, text),
                "text": text,
            },
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            f"{BASE_URL}/r/{room}?format=json",
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "technocore-worker/0.1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except HTTPError as error:
            detail = error.read(1024).decode("utf-8", "replace").replace(
                room, "<redacted-room>"
            )
            raise RuntimeError(
                f"Technocore reply HTTP {error.code}: {detail.strip()}"
            ) from error
        posted = payload["posted"]
        return Posted(room=room, sequence=int(posted["seq"]), timestamp=str(posted["ts"]))
