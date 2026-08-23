"""The kiro-cli readiness gates must not block a host running another backend.

Every probe behind those gates asks about kiro-cli — is it installed, is it
signed in, are its agent specs present. On a Codex-only host those questions are
unanswerable rather than merely false, so a not-ready answer would refuse resume,
regenerate, rewind and /v1/chat/completions permanently while ordinary sends
(deliberately ungated) kept working. That asymmetry is worse than either extreme.
"""

from __future__ import annotations

from typing import Any

import pytest

from kiro_crew.dashboard import kiro_readiness
from kiro_crew.dashboard.handlers import kiro_prerequisite as prereq_handler


class TestReadinessGateBackendScope:
    def test_default_backend_still_consults_the_latch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The kiro path is unchanged: the gate still fails closed."""
        monkeypatch.setattr(kiro_readiness, "_configured_acp_backend", lambda: "", raising=True)
        consulted: list[bool] = []

        async def _verified(_service: Any) -> bool:
            consulted.append(True)
            return False

        monkeypatch.setattr(kiro_readiness, "kiro_verified_ready", _verified)
        monkeypatch.setattr(kiro_readiness, "_service", lambda request: object())

        import asyncio

        response = asyncio.run(kiro_readiness.reject_if_kiro_unverified(_FakeRequest()))
        assert response is not None
        assert response.status == 503
        assert consulted, "the kiro path must still probe"

    def test_non_default_backend_opens_the_gate_without_probing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Skipping the probe is the point, not running it and ignoring it.

        The probe spawns a subprocess; on a Codex-only host that binary may not
        exist at all.
        """
        monkeypatch.setattr(
            kiro_readiness, "_configured_acp_backend", lambda: "codex", raising=True
        )
        probed: list[bool] = []

        async def _verified(_service: Any) -> bool:
            probed.append(True)
            return False

        monkeypatch.setattr(kiro_readiness, "kiro_verified_ready", _verified)

        import asyncio

        response = asyncio.run(kiro_readiness.reject_if_kiro_unverified(_FakeRequest()))
        assert response is None
        assert not probed, "the gate must open BEFORE the probe runs"

    def test_an_unreadable_config_keeps_the_gate_closed(self) -> None:
        """Fails closed: opening the gate is the permissive direction."""
        assert kiro_readiness._configured_acp_backend() in ("", "codex", "claude", "kas")


class TestFirstRunWallBackendScope:
    def test_alt_backend_snapshot_reports_ready(self) -> None:
        snapshot = prereq_handler._alt_backend_snapshot()
        assert snapshot["ready"] is True
        assert snapshot["installed"] is True
        assert snapshot["authenticated"] is True

    def test_alt_backend_snapshot_does_not_demote_to_first_run(self) -> None:
        """``ready`` alone satisfies the blocking gate.

        ``initial_setup_complete`` is set too so no other consumer reads a
        half-ready state and raises a partial setup prompt.
        """
        assert prereq_handler._alt_backend_snapshot()["initial_setup_complete"] is True

    def test_snapshot_shape_matches_the_real_one(self) -> None:
        """Built from the same dataclass, so the shape cannot drift."""
        alt = set(prereq_handler._alt_backend_snapshot())
        real = set(prereq_handler._not_ready_snapshot())
        assert alt == real

    def test_backend_reader_fails_closed(self) -> None:
        assert prereq_handler._configured_acp_backend() in ("", "codex", "claude", "kas")


class _FakeRequest(dict):
    """Minimal stand-in: the gate reads nothing off the request before the check."""

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        return default
