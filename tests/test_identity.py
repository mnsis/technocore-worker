from __future__ import annotations

import stat

import pytest

from worker.identity import generate_identity, load_identity, public_did


def test_identity_is_created_mode_0600_and_round_trips(tmp_path) -> None:
    path = tmp_path / "private" / "identity.pem"
    did = generate_identity(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert public_did(load_identity(path)) == did


def test_identity_rejects_loose_permissions(tmp_path) -> None:
    path = tmp_path / "identity.pem"
    generate_identity(path)
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        load_identity(path)
