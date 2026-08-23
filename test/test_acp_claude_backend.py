"""Claude Code backend: descriptor, permission-mode probe, and seeding.

The adapter machinery itself (binary resolution, the vendored-copy completeness
check, CLAUDE_CONFIG_DIR isolation, CLAUDE_CODE_EXECUTABLE resolution) predates
this work and is deliberately unchanged. What is new is that the backend is
described in the registry and that its tool-gate routing is established by
reading a file back rather than assumed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kiro_crew.acp import backends, claude
from kiro_crew.acp.codex import Verdict
from kiro_crew.acp.types import (
    ACP_BACKEND_CLAUDE,
    CC_PERMISSION_MODE_AUTO,
    CC_PERMISSION_MODE_DEFAULT,
)


class TestDescriptor:
    def test_registered_as_an_experimental_spec_adapter(self) -> None:
        descriptor = backends.descriptor_for(ACP_BACKEND_CLAUDE)
        assert descriptor.experimental
        assert descriptor.dialect is backends.Dialect.SPEC
        assert descriptor.routing is backends.Routing.SEEDED_SETTINGS

    def test_declares_no_session_sharing(self) -> None:
        """One process per session: the adapter runs on the legacy client path."""
        assert not backends.supports(ACP_BACKEND_CLAUDE, backends.CAP_SESSION_SHARING)

    def test_declares_no_agent_profiles(self) -> None:
        """No set_mode equivalent, which is what the agent guard exists for."""
        assert not backends.supports(ACP_BACKEND_CLAUDE, backends.CAP_AGENT_PROFILES)

    def test_names_no_credential_store(self) -> None:
        """Kiro Crew reads no credential for this backend.

        The vendor CLI owns sign-in entirely, so there is no path for Kiro Crew to
        protect — unlike Codex, whose auth.json Kiro Crew does fence off.
        """
        assert backends.descriptor_for(ACP_BACKEND_CLAUDE).credential_leaves == ()


class TestPermissionModeProbe:
    def test_absent_file_is_indeterminate(self, tmp_path: Path) -> None:
        """The adapter falls back to its own default, which Kiro Crew never set.

        Reporting that as routed would be the "assumed but not present" case that
        silently disables the gate.
        """
        verdict, reason = claude.routing_verdict(tmp_path)
        assert verdict is Verdict.INDETERMINATE
        assert "does not set" in reason

    def test_default_mode_is_routed(self, tmp_path: Path) -> None:
        self._write(tmp_path, {"permissions": {"defaultMode": CC_PERMISSION_MODE_DEFAULT}})
        verdict, _ = claude.routing_verdict(tmp_path)
        assert verdict is Verdict.ROUTED

    @pytest.mark.parametrize("mode", sorted(claude.PERMISSION_BYPASS_MODES))
    def test_bypass_modes_are_bypassed(self, mode: str, tmp_path: Path) -> None:
        self._write(tmp_path, {"permissions": {"defaultMode": mode}})
        verdict, reason = claude.routing_verdict(tmp_path)
        assert verdict is Verdict.BYPASSED
        assert "without asking" in reason

    def test_auto_mode_is_recognised_as_a_bypass(self, tmp_path: Path) -> None:
        """auto is the SDK's auto-accept mode, not a gentler 'default'."""
        assert CC_PERMISSION_MODE_AUTO in claude.PERMISSION_BYPASS_MODES

    def test_an_unrecognised_mode_is_indeterminate(self, tmp_path: Path) -> None:
        """The adapter may add a mode that auto-approves.

        Defaulting to routed would adopt it silently the moment it ships.
        """
        self._write(tmp_path, {"permissions": {"defaultMode": "future-mode"}})
        verdict, _ = claude.routing_verdict(tmp_path)
        assert verdict is Verdict.INDETERMINATE

    def test_malformed_json_is_indeterminate(self, tmp_path: Path) -> None:
        path = claude.local_settings_path(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text("{not json")
        verdict, _ = claude.routing_verdict(tmp_path)
        assert verdict is Verdict.INDETERMINATE

    def test_a_non_object_document_is_indeterminate(self, tmp_path: Path) -> None:
        self._write_raw(tmp_path, json.dumps(["a", "list"]))
        assert claude.configured_permission_mode(tmp_path) == ""

    def test_a_non_string_mode_is_indeterminate(self, tmp_path: Path) -> None:
        self._write(tmp_path, {"permissions": {"defaultMode": 7}})
        assert claude.configured_permission_mode(tmp_path) == ""

    def _write(self, work_dir: Path, payload: dict) -> None:
        self._write_raw(work_dir, json.dumps(payload))

    def _write_raw(self, work_dir: Path, raw: str) -> None:
        path = claude.local_settings_path(work_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw)


class TestRoutingRestsOnTheAdapterReadPath:
    """Why claude is in ACP_BACKENDS_SELECTABLE at all.

    The ROUTED verdict is MANUFACTURED: Kiro Crew writes a permission mode and
    then reports the session governed. That is only honest while two things hold,
    and both were verified by reading the installed adapter's own settings
    resolver rather than assumed — so they are pinned here, because a silent break
    would leave Kiro Crew claiming a gate it does not have, which is worse than
    refusing the backend outright.
    """

    def test_crew_writes_the_path_the_adapter_reads(self, tmp_path: Path) -> None:
        """The adapter resolves ``<cwd>/.claude/settings.local.json``.

        Its settings resolver lists exactly three sources for a cwd — the user
        config settings.json, ``<cwd>/.claude/settings.json`` and
        ``<cwd>/.claude/settings.local.json`` — and merges them through the Claude
        Agent SDK's own ``resolveSettings``, so what it sees matches what
        ``query()`` sees. Writing anywhere else would land in a file nothing reads
        while the verdict still reported ROUTED.
        """
        assert claude.local_settings_path(tmp_path) == (
            tmp_path / ".claude" / "settings.local.json"
        )

    def test_the_routed_mode_de_escalates_so_the_sdk_cannot_filter_it(self) -> None:
        """The adapter drops ESCALATING defaultMode values, not de-escalating ones.

        ``filterEscalatingDefaultMode`` mirrors the CLI's trust policy: a
        repo-committed source may not hand itself MORE privilege. Kiro Crew writes
        the ask-before-every-tool mode, which asks for less, so the filter has
        nothing to strip. An edit that seeded a bypass mode here would both invert
        the gate and be silently discarded by the adapter.
        """
        assert CC_PERMISSION_MODE_DEFAULT in claude.PERMISSION_ROUTED_MODES
        assert not (claude.PERMISSION_ROUTED_MODES & claude.PERMISSION_BYPASS_MODES)

    def test_claude_is_selectable_on_that_basis(self) -> None:
        """Selectability follows governability, not authentication.

        Kiro Crew never handles a credential — an unauthenticated host is the
        operator's problem and surfaces as a readable error, so it is not grounds
        to withhold the backend. Being governable IS.
        """
        from kiro_crew.acp.types import ACP_BACKENDS_SELECTABLE

        assert ACP_BACKEND_CLAUDE in ACP_BACKENDS_SELECTABLE


class TestSeeding:
    def test_seeds_when_nothing_is_configured(self, tmp_path: Path) -> None:
        assert claude.ensure_routed_settings(tmp_path)
        assert claude.configured_permission_mode(tmp_path) == CC_PERMISSION_MODE_DEFAULT

    def test_does_not_touch_a_configured_mode(self, tmp_path: Path) -> None:
        """Even to strengthen it.

        An explicitly configured mode is somebody's decision — an operator's or a
        companion edition's. Rewriting it would be Kiro Crew overruling a choice
        it can see, so the session refuses instead.
        """
        path = claude.local_settings_path(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"permissions": {"defaultMode": "auto"}}))

        assert not claude.ensure_routed_settings(tmp_path)
        assert claude.configured_permission_mode(tmp_path) == "auto"

    def test_merges_rather_than_replaces(self, tmp_path: Path) -> None:
        """A companion's model allowlist must survive the seed."""
        path = claude.local_settings_path(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"availableModels": ["opus"], "other": {"a": 1}}))

        claude.ensure_routed_settings(tmp_path)

        after = json.loads(path.read_text())
        assert after["permissions"]["defaultMode"] == CC_PERMISSION_MODE_DEFAULT
        assert after["availableModels"] == ["opus"]
        assert after["other"] == {"a": 1}

    def test_preserves_sibling_permission_keys(self, tmp_path: Path) -> None:
        path = claude.local_settings_path(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"permissions": {"allow": ["Read"]}}))

        claude.ensure_routed_settings(tmp_path)

        after = json.loads(path.read_text())
        assert after["permissions"]["allow"] == ["Read"]
        assert after["permissions"]["defaultMode"] == CC_PERMISSION_MODE_DEFAULT

    def test_creates_the_directory_when_absent(self, tmp_path: Path) -> None:
        work_dir = tmp_path / "fresh"
        claude.ensure_routed_settings(work_dir)
        assert claude.local_settings_path(work_dir).is_file()

    def test_a_failed_write_leaves_the_verdict_unroutable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A swallowed write failure must not read as success.

        The probe reads the file BACK, so a seed that silently failed surfaces as
        indeterminate and refuses the session rather than passing.
        """
        monkeypatch.setattr(
            Path, "write_text", lambda *a, **k: (_ for _ in ()).throw(OSError("nope"))
        )
        assert not claude.ensure_routed_settings(tmp_path)
        verdict, _ = claude.routing_verdict(tmp_path)
        assert verdict is Verdict.INDETERMINATE


class TestRemediation:
    def test_hint_quotes_the_exact_json(self, tmp_path: Path) -> None:
        hint = claude.remediation_hint(tmp_path)
        assert "defaultMode" in hint
        assert CC_PERMISSION_MODE_DEFAULT in hint
        assert str(claude.local_settings_path(tmp_path)) in hint

    def test_signin_hint_states_no_credential_is_stored(self) -> None:
        assert "stores no credential" in claude.signin_hint()
