"""GET /api/acp-backends — one source for the capability table.

If the frontend carried its own copy, the Settings card's disclosure and
`kirocrew doctor` could disagree about what a backend supports, and the operator
would have no way to tell which was right.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kiro_crew.acp import backends
from kiro_crew.acp.types import (
    ACP_BACKEND_CLAUDE,
    ACP_BACKEND_CODEX,
    ACP_BACKEND_GOOSE,
    ACP_BACKEND_KAS,
    ACP_BACKEND_KIRO,
    ACP_BACKEND_OPENCODE,
    ACP_BACKEND_PI,
    ACP_BACKENDS_KNOWN,
    ACP_BACKENDS_SELECTABLE,
)
from kiro_crew.dashboard.handlers import acp_backends as handler


class TestTheCardsOfferAndTheSaveAllowlistAgree:
    """Every adapter the card lets you pick must survive the whole write path.

    Found by clicking the real card in an isolated gateway. THREE independent
    allowlists govern one setting, and they had drifted apart:

      1. ACP_BACKENDS_SELECTABLE      what the endpoint advertises
      2. _EDITABLE_CONFIG             what the config PATCH will accept
      3. the AgentConfig schema enum  what survives the next config LOAD

    Only (1) had been widened. (2) rejected the write outright with "field not
    editable". Fixing that exposed (3), which was still frozen at ['', 'kas'] —
    and that failed far worse: the PATCH answered 200 and the value was then
    discarded on load, so the UI reported success and nothing changed.

    All three now read (1). These tests exist so a fourth surface cannot quietly
    appear, and so widening the set in one place can never again half-work.
    """

    def test_every_selectable_backend_is_writable(self) -> None:
        from kiro_crew.dashboard.handlers.core import _EDITABLE_CONFIG

        spec = _EDITABLE_CONFIG.get("agent.acp_backend")
        assert spec is not None, (
            "agent.acp_backend is missing from _EDITABLE_CONFIG, so the adapter "
            "card can offer a choice the API refuses to persist"
        )
        assert set(spec["values_fn"]()) == set(backends.selectable_ids()), (
            "the writable set and ACP_BACKENDS_SELECTABLE disagree; a value the "
            "card offers would be refused, or one it hides would be accepted"
        )

    def test_every_selectable_backend_survives_a_config_load(self) -> None:
        """The schema enum must not reject what the PATCH just accepted.

        This is the surface that produced a successful-looking save with no
        effect, so it is asserted against the same set rather than a literal.
        """
        from kiro_crew.config.loader import AgentConfig
        from kiro_crew.config.schema import _build_object_schema

        schema = _build_object_schema(AgentConfig)
        enum = schema["properties"]["acp_backend"].get("enum")
        assert enum is not None, "acp_backend lost its enum constraint entirely"
        assert set(enum) == set(backends.selectable_ids())

    def test_the_default_backend_is_writable(self) -> None:
        """Switching BACK to kiro-cli has to work too.

        kiro is spelled as the empty string, which is exactly the sort of value an
        allowlist check drops by truthiness.
        """
        from kiro_crew.dashboard.handlers.core import _EDITABLE_CONFIG

        values = _EDITABLE_CONFIG["agent.acp_backend"]["values_fn"]()
        assert ACP_BACKEND_KIRO in set(values)


class TestDescriptorPayload:
    @pytest.mark.parametrize("backend", sorted(ACP_BACKENDS_KNOWN))
    def test_every_backend_serialises(self, backend: str) -> None:
        payload = handler._descriptor_payload(backend)
        for key in (
            "id",
            "label",
            "experimental",
            "selectable",
            "signin_command",
            "install_command",
            "dialect",
            "routing",
            "capabilities",
            "degraded_count",
        ):
            assert key in payload, key

    @pytest.mark.parametrize("backend", sorted(ACP_BACKENDS_KNOWN))
    def test_capabilities_are_complete(self, backend: str) -> None:
        capabilities = handler._descriptor_payload(backend)["capabilities"]
        assert set(capabilities) == set(backends.ALL_CAPABILITIES)

    def test_levels_are_strings_not_booleans(self) -> None:
        """Collapsing to a boolean would render degraded, unavailable, and unverified alike.

        Which is the entire reason the level has four states.
        """
        capabilities = handler._descriptor_payload(ACP_BACKEND_CODEX)["capabilities"]
        assert capabilities["reasoning_effort"] == "supported"
        assert capabilities["session_sharing"] == "unavailable"
        assert capabilities["native_resume"] == "supported"
        kas = handler._descriptor_payload(ACP_BACKEND_KAS)["capabilities"]
        assert kas["reasoning_effort"] == "unverified"

    def test_kiro_has_no_degraded_capabilities(self) -> None:
        payload = handler._descriptor_payload(ACP_BACKEND_KIRO)
        assert payload["degraded_count"] == 0
        assert payload["experimental"] is False

    def test_degraded_count_matches_the_capability_map(self) -> None:
        """The confirm dialog quotes this number; it must not be independent."""
        for backend in sorted(ACP_BACKENDS_KNOWN):
            payload = handler._descriptor_payload(backend)
            expected = sum(1 for v in payload["capabilities"].values() if v != "supported")
            assert payload["degraded_count"] == expected

    def test_selectable_reflects_the_gate_not_the_descriptor(self) -> None:
        """Having a descriptor must not imply an operator may choose it.

        The payload's flag mirrors ACP_BACKENDS_SELECTABLE for every known
        backend, whatever that set currently contains — so this keeps holding as
        backends graduate into it.
        """
        for backend in sorted(ACP_BACKENDS_KNOWN):
            payload = handler._descriptor_payload(backend)
            assert payload["selectable"] is (backend in ACP_BACKENDS_SELECTABLE)

    def test_selectable_can_be_false_while_described(self, monkeypatch) -> None:
        """The two facts stay independent even when nothing is withheld today.

        Pinned against a CONTROLLED set. The real set has grown to cover every
        known backend, so without forcing it there is no longer an instance of
        "described but not selectable" to assert on — and that distinction still
        has to work for the registry adapters that will arrive described and
        withheld.
        """
        monkeypatch.setattr(handler.acp_backends, "selectable_ids", lambda: frozenset())
        for backend in sorted(ACP_BACKENDS_KNOWN):
            payload = handler._descriptor_payload(backend)
            assert payload["label"], backend
            assert payload["selectable"] is False, backend

    def test_goose_probe_answers_through_the_spawn_resolver(self, monkeypatch) -> None:
        """goose is found by the same resolver the spawn uses.

        This asserted "unknown" while goose had no spawn path: any probe then would
        have been a second implementation that could disagree with the launch. Two
        shortcuts were tried and rejected — ``trusted_system_bin`` excludes
        same-uid-writable dirs so it reported "missing" for a goose in
        ~/.local/bin, a false negative telling an operator to install what they
        have; ``shutil.which`` answers from a PATH the spawn may not share. Now
        there is one resolver, so the probe can be both honest and useful.
        """
        import kiro_crew.acp.goose as goose_mod

        monkeypatch.setattr(goose_mod, "resolve_argv_cached", lambda: ["/usr/bin/goose", "acp"])
        assert handler._probe_installed(ACP_BACKEND_GOOSE) == "installed"

        monkeypatch.setattr(goose_mod, "resolve_argv_cached", lambda: None)
        assert handler._probe_installed(ACP_BACKEND_GOOSE) == "missing"

    def test_goose_probe_still_never_says_missing_on_a_failed_check(self, monkeypatch) -> None:
        """The three-state rule survives: a broken check is unknown, not missing."""
        import kiro_crew.acp.goose as goose_mod

        def boom() -> list[str]:
            raise OSError("PATH unreadable")

        monkeypatch.setattr(goose_mod, "resolve_argv_cached", boom)
        assert handler._probe_installed(ACP_BACKEND_GOOSE) == "unknown"

    def test_opencode_probe_answers_through_the_spawn_resolver(self, monkeypatch) -> None:
        import kiro_crew.acp.opencode as opencode_mod

        monkeypatch.setattr(
            opencode_mod, "resolve_argv_cached", lambda: ["/usr/bin/opencode", "acp"]
        )
        assert handler._probe_installed(ACP_BACKEND_OPENCODE) == "installed"

        monkeypatch.setattr(opencode_mod, "resolve_argv_cached", lambda: None)
        assert handler._probe_installed(ACP_BACKEND_OPENCODE) == "missing"

    def test_opencode_probe_never_says_missing_on_a_failed_check(self, monkeypatch) -> None:
        import kiro_crew.acp.opencode as opencode_mod

        def boom() -> list[str]:
            raise OSError("PATH unreadable")

        monkeypatch.setattr(opencode_mod, "resolve_argv_cached", boom)
        assert handler._probe_installed(ACP_BACKEND_OPENCODE) == "unknown"

    def test_pi_probe_answers_through_the_spawn_resolver(self, monkeypatch) -> None:
        import kiro_crew.acp.pi as pi_mod

        monkeypatch.setattr(pi_mod, "resolve_argv_cached", lambda: ["/usr/bin/pi-acp"])
        assert handler._probe_installed(ACP_BACKEND_PI) == "installed"

        monkeypatch.setattr(pi_mod, "resolve_argv_cached", lambda: None)
        assert handler._probe_installed(ACP_BACKEND_PI) == "missing"

    def test_pi_probe_never_says_missing_on_a_failed_check(self, monkeypatch) -> None:
        import kiro_crew.acp.pi as pi_mod

        def boom() -> list[str]:
            raise OSError("PATH unreadable")

        monkeypatch.setattr(pi_mod, "resolve_argv_cached", boom)
        assert handler._probe_installed(ACP_BACKEND_PI) == "unknown"

    def test_registry_probe_does_not_confuse_a_runner_with_an_installed_adapter(
        self, monkeypatch
    ) -> None:
        """npx on PATH says nothing about whether one specific package is installed."""
        from kiro_crew.acp import registry

        adapter = registry.RegistryAdapter(
            id="example-acp",
            name="Example ACP",
            version="1.0.0",
            description="",
            repository="",
            license="MIT",
            icon="",
            kind="npx",
            package="example-acp@1.0.0",
            args=(),
            env=(),
        )
        monkeypatch.setattr(registry, "cached", lambda: {adapter.id: adapter})
        monkeypatch.setattr(handler.shutil, "which", lambda _name: "/usr/bin/npx")

        assert handler._probe_installed(adapter.id) == "unknown"

    def test_install_command_is_present_for_adapter_backends(self) -> None:
        """An adapter the operator must install has to say how.

        Operator-installed is the decided posture, so the instruction is part of
        the contract rather than documentation nice-to-have.
        """
        for backend in (ACP_BACKEND_CODEX, ACP_BACKEND_CLAUDE):
            command = handler._descriptor_payload(backend)["install_command"]
            assert command, backend
            assert command.startswith("npm install -g "), command

    def test_install_command_names_the_official_scoped_package(self) -> None:
        """The unscoped names do not exist on npm.

        Both official adapters publish under @agentclientprotocol. Shipping the
        unscoped spelling would send the operator to a package that is not there,
        which is worse than saying nothing because it fails AFTER they believe
        they complied.
        """
        for backend in (ACP_BACKEND_CODEX, ACP_BACKEND_CLAUDE):
            command = handler._descriptor_payload(backend)["install_command"]
            assert "@agentclientprotocol/" in command, command

    def test_host_provided_backends_carry_no_install_command(self) -> None:
        """kiro-cli and KAS ship with the host; there is no package to install.

        Empty rather than a plausible-looking command, so the UI omits the step
        instead of inventing one.
        """
        for backend in (ACP_BACKEND_KIRO, ACP_BACKEND_KAS):
            assert handler._descriptor_payload(backend)["install_command"] == ""

    def test_binary_distributed_adapters_carry_no_install_command(self) -> None:
        """goose and OpenCode ship as their own binaries, like a host install."""
        for backend in (ACP_BACKEND_GOOSE, ACP_BACKEND_OPENCODE):
            assert handler._descriptor_payload(backend)["install_command"] == ""

    def test_pi_install_command_names_the_npm_adapter(self) -> None:
        assert handler._descriptor_payload(ACP_BACKEND_PI)["install_command"] == (
            "npm install -g pi-acp"
        )

    def test_signin_commands_are_backend_specific(self) -> None:
        assert handler._descriptor_payload(ACP_BACKEND_CODEX)["signin_command"] == "codex login"
        assert handler._descriptor_payload(ACP_BACKEND_KIRO)["signin_command"] == "kiro-cli login"
        assert (
            handler._descriptor_payload(ACP_BACKEND_OPENCODE)["signin_command"]
            == "opencode auth login"
        )
        assert handler._descriptor_payload(ACP_BACKEND_PI)["signin_command"] == "pi"

    def test_both_adapters_report_the_spec_dialect(self) -> None:
        assert handler._descriptor_payload(ACP_BACKEND_CLAUDE)["dialect"] == "spec"
        assert handler._descriptor_payload(ACP_BACKEND_CODEX)["dialect"] == "spec"


class TestInstallProbe:
    def test_not_probed_by_default(self) -> None:
        """The scan is opt-in: a caller that will not show it must not pay."""
        for backend in sorted(ACP_BACKENDS_KNOWN):
            assert handler._descriptor_payload(backend)["installed"] == ""

    def test_probe_returns_one_of_three_states(self) -> None:
        for backend in sorted(ACP_BACKENDS_KNOWN):
            assert handler._descriptor_payload(backend, probe=True)["installed"] in (
                "installed",
                "missing",
                "unknown",
            )

    def test_a_failing_resolver_reports_unknown_not_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Never tell an operator to install what they may already have.

        `missing` implies a remedy (a global npm install). A probe that raised
        knows nothing, so it must not imply anything.
        """

        def _boom() -> object:
            raise RuntimeError("resolver exploded")

        monkeypatch.setattr("kiro_crew.acp.codex.resolve_argv_cached", _boom)
        assert handler._probe_installed(ACP_BACKEND_CODEX) == "unknown"

    def test_a_backend_with_no_resolver_is_unknown(self) -> None:
        """KAS is launched by the host, not found on PATH.

        `missing` would invite an install that does not exist.
        """
        assert handler._probe_installed(ACP_BACKEND_KAS) == "unknown"

    def test_probe_uses_the_same_resolver_the_spawn_uses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A second implementation could disagree with the spawn.

        Then the card says ready and the session fails, which is worse than not
        checking at all.
        """
        calls: list[str] = []

        def _fake() -> list[str]:
            calls.append("codex")
            return ["codex-acp"]

        monkeypatch.setattr("kiro_crew.acp.codex.resolve_argv_cached", _fake)
        assert handler._probe_installed(ACP_BACKEND_CODEX) == "installed"
        assert calls == ["codex"]


class TestActiveState:
    def test_reports_the_configured_backend(self) -> None:
        state = handler._active_state()
        assert state["active"] in ("", *sorted(ACP_BACKENDS_KNOWN))
        assert isinstance(state["allow_ungated_tools"], bool)

    def test_no_verdict_is_probed_on_the_default_backend(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The default path must not pay for a probe it does not need."""
        probed: list[bool] = []

        def _boom(*args: object, **kwargs: object) -> None:
            probed.append(True)
            raise AssertionError("must not probe on the default backend")

        monkeypatch.setattr("kiro_crew.acp.tool_gate.routing_verdict", _boom)
        state = handler._active_state()
        if not state["active"]:
            assert not probed
            assert state["routing_verdict"] == ""

    @pytest.mark.parametrize("backend", [ACP_BACKEND_CLAUDE, ACP_BACKEND_OPENCODE])
    def test_does_not_seed_settings_files(
        self, backend: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Settings/Services GET must not write Claude or OpenCode config.

        The card is a probe; the seed that makes ``SEEDED_SETTINGS`` backends
        ROUTED belongs to enforce / spawn, not ``config_dir()/workspace``.
        """
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        class _Agent:
            acp_backend = backend
            acp_backend_allow_ungated_tools = False

        class _Cfg:
            agent = _Agent()

        monkeypatch.setattr(
            "kiro_crew.config.loader.KiroCrewConfig.load",
            classmethod(lambda cls: _Cfg()),
        )
        monkeypatch.setattr("kiro_crew.config.paths.config_dir", lambda: tmp_path)

        state = handler._active_state()
        assert state["active"] == backend
        assert state["routing_verdict"] == "indeterminate"
        assert not (workspace / "opencode.json").exists()
        assert not (workspace / ".opencode" / "opencode.json").exists()
        assert not (workspace / ".claude" / "settings.local.json").exists()

    def test_a_config_failure_degrades_rather_than_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A broken read must not leave the card with no data at all."""
        monkeypatch.setattr(
            "kiro_crew.config.loader.KiroCrewConfig.load",
            classmethod(lambda cls: (_ for _ in ()).throw(RuntimeError("nope"))),
        )
        state = handler._active_state()
        assert state["active"] == ""
        assert state["allow_ungated_tools"] is False
