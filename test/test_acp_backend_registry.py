"""Tests for the ACP backend descriptor table."""

from __future__ import annotations

import dataclasses

import pytest

from kiro_crew.acp import backends
from kiro_crew.acp.backends import (
    ALL_CAPABILITIES,
    CAP_SESSION_SHARING,
    CAP_TOOL_SEARCH,
    Dialect,
    Level,
    Routing,
    UnknownAcpBackend,
)
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


def test_descriptors_and_known_ids_agree_in_both_directions() -> None:
    """The descriptor table and the membership gate cannot drift apart.

    Checked both ways deliberately: a one-directional check passes when a
    descriptor exists for an id nobody may pass, and also when an id is
    accepted with no descriptor behind it.
    """
    assert backends.known_ids() == ACP_BACKENDS_KNOWN


def test_every_selectable_backend_has_a_descriptor() -> None:
    """An operator can never persist a value with no descriptor behind it."""
    for backend in ACP_BACKENDS_SELECTABLE:
        assert backends.descriptor_for(backend).id == backend


@pytest.mark.parametrize("backend", sorted(ACP_BACKENDS_KNOWN))
def test_descriptor_declares_every_capability(backend: str) -> None:
    """A missing capability must be a hard error, never a silent False."""
    descriptor = backends.descriptor_for(backend)
    assert set(descriptor.capabilities) == set(ALL_CAPABILITIES)


@pytest.mark.parametrize("backend", sorted(ACP_BACKENDS_KNOWN))
def test_descriptor_fields_are_populated(backend: str) -> None:
    """Every non-optional field carries a real value.

    ``credential_leaves`` is legitimately empty for a backend whose credential
    store Kiro Crew does not name, so it is excluded rather than asserted.
    """
    descriptor = backends.descriptor_for(backend)
    assert descriptor.label
    assert descriptor.signin_command
    assert descriptor.process_markers
    assert isinstance(descriptor.dialect, Dialect)
    assert isinstance(descriptor.routing, Routing)
    assert isinstance(descriptor.experimental, bool)


def test_descriptor_is_frozen() -> None:
    """A descriptor is data; a call site must not be able to mutate it."""
    descriptor = backends.descriptor_for(ACP_BACKEND_KIRO)
    with pytest.raises(dataclasses.FrozenInstanceError):
        descriptor.label = "mutated"  # type: ignore[misc]


def test_unknown_backend_raises_rather_than_defaulting() -> None:
    """An unrecognised id must not resolve to kiro.

    Falling back would spawn a different agent than the operator asked for,
    which is the failure the membership gate in AcpProvider already guards.
    """
    with pytest.raises(UnknownAcpBackend):
        backends.descriptor_for("not-a-backend")
    with pytest.raises(UnknownAcpBackend):
        backends.level("not-a-backend", CAP_TOOL_SEARCH)


def test_unknown_capability_raises() -> None:
    with pytest.raises(UnknownAcpBackend):
        backends.level(ACP_BACKEND_KIRO, "not-a-capability")


def test_kiro_supports_everything() -> None:
    """The default backend is the reference implementation."""
    for capability in ALL_CAPABILITIES:
        assert backends.supports(ACP_BACKEND_KIRO, capability)


def test_codex_effort_is_supported_and_unverified_stays_fail_closed() -> None:
    """Codex has a real selector; unknown behavior still cannot open a gate."""
    assert backends.level(ACP_BACKEND_CODEX, backends.CAP_REASONING_EFFORT) is Level.SUPPORTED
    assert backends.supports(ACP_BACKEND_CODEX, backends.CAP_REASONING_EFFORT)
    assert backends.level(ACP_BACKEND_KAS, backends.CAP_REASONING_EFFORT) is Level.UNVERIFIED
    assert not backends.supports(ACP_BACKEND_KAS, backends.CAP_REASONING_EFFORT)


def test_dialects() -> None:
    """KAS speaks kiro's dialect; the two adapters speak the public spec."""
    assert backends.dialect_of(ACP_BACKEND_KIRO) is Dialect.KIRO
    assert backends.dialect_of(ACP_BACKEND_KAS) is Dialect.KIRO
    assert backends.dialect_of(ACP_BACKEND_CLAUDE) is Dialect.SPEC
    assert backends.dialect_of(ACP_BACKEND_CODEX) is Dialect.SPEC
    assert backends.dialect_of(ACP_BACKEND_GOOSE) is Dialect.SPEC
    assert backends.dialect_of(ACP_BACKEND_OPENCODE) is Dialect.SPEC
    assert backends.dialect_of(ACP_BACKEND_PI) is Dialect.SPEC

    assert not backends.is_spec_dialect(ACP_BACKEND_KIRO)
    assert not backends.is_spec_dialect(ACP_BACKEND_KAS)
    assert backends.is_spec_dialect(ACP_BACKEND_CLAUDE)
    assert backends.is_spec_dialect(ACP_BACKEND_CODEX)
    assert backends.is_spec_dialect(ACP_BACKEND_GOOSE)
    assert backends.is_spec_dialect(ACP_BACKEND_OPENCODE)
    assert backends.is_spec_dialect(ACP_BACKEND_PI)


def test_session_sharing_matches_the_advertised_set_not_the_runtime_arm() -> None:
    """Sharing is narrower than "runs on the multiplexed runtime".

    This test previously asserted KAS claims the capability because it takes the
    runtime arm. That conflated two different facts:
    ``ACP_BACKENDS_ACP_RUNTIME`` is a deliberate SUPERSET of
    ``ACP_BACKENDS_SESSION_SHARING`` — running there is necessary for sharing but
    not sufficient, and KAS is held out until keep-aware teardown lands. The
    table must agree with the set the provider actually consults, so it is
    asserted against that set rather than restated by hand.
    """
    from kiro_crew.acp.types import ACP_BACKENDS_SESSION_SHARING

    for backend in sorted(ACP_BACKENDS_KNOWN):
        assert backends.supports(backend, CAP_SESSION_SHARING) is (
            backend in ACP_BACKENDS_SESSION_SHARING
        ), backend
    # Both spec adapters run one process per session on the legacy client path.
    assert not backends.supports(ACP_BACKEND_CLAUDE, CAP_SESSION_SHARING)
    assert not backends.supports(ACP_BACKEND_CODEX, CAP_SESSION_SHARING)


def test_kas_distinguishes_measured_absence_from_unverified_inheritance() -> None:
    """KAS must not turn a shared code path into a verified backend claim."""
    measured = {
        backends.CAP_SESSION_SHARING: Level.UNAVAILABLE,
        backends.CAP_AGENT_PROFILES: Level.DEGRADED,
        backends.CAP_MID_TURN_STEER: Level.SUPPORTED,
    }
    for capability in ALL_CAPABILITIES:
        level = backends.level(ACP_BACKEND_KAS, capability)
        if capability in measured:
            assert level is measured[capability]
        else:
            assert level is Level.UNVERIFIED


def test_only_kiro_is_non_experimental() -> None:
    assert not backends.descriptor_for(ACP_BACKEND_KIRO).experimental
    for backend in (ACP_BACKEND_CLAUDE, ACP_BACKEND_CODEX, ACP_BACKEND_KAS):
        assert backends.descriptor_for(backend).experimental


def test_signin_commands_are_backend_specific() -> None:
    """A Codex host must never be told to run kiro-cli login."""
    assert backends.descriptor_for(ACP_BACKEND_CODEX).signin_command == "codex login"
    assert backends.descriptor_for(ACP_BACKEND_KIRO).signin_command == "kiro-cli login"


def test_codex_credential_leaf_is_the_file_not_the_directory() -> None:
    """config.toml must stay readable while auth.json is protected.

    An operator diagnosing a routing verdict reads approval_policy out of
    config.toml, so protecting the whole $CODEX_HOME directory would block the
    very diagnosis the refusal message asks for.
    """
    leaves = backends.descriptor_for(ACP_BACKEND_CODEX).credential_leaves
    assert leaves == (".codex/auth.json",)
    assert ".codex" not in leaves


def test_credential_leaves_are_aggregated_and_deduped() -> None:
    aggregated = backends.credential_leaves()
    assert ".codex/auth.json" in aggregated
    assert len(aggregated) == len(set(aggregated))


def test_process_markers_cover_every_backend_and_dedupe() -> None:
    """KAS and kiro share a binary, so the marker list must not duplicate it."""
    markers = backends.process_markers()
    assert "kiro-cli" in markers
    assert "claude" in markers
    assert "codex" in markers
    assert len(markers) == len(set(markers))


def test_routing_records_how_each_backend_reaches_the_gate() -> None:
    """Routing is what the tool-gate enforcement branches on.

    Codex is SESSION_CONFIG rather than EXTERNAL_POLICY: its ACP sessions ignore
    the adapter's own config file and default to a mode that writes inside the
    workspace without asking, so probing that file resolved ROUTED for a session
    that was ungated in practice. The enforceable fact is the mode the session
    itself advertises, applied and verified before the first prompt.
    """
    assert backends.descriptor_for(ACP_BACKEND_KIRO).routing is Routing.AGENT_SPEC
    assert backends.descriptor_for(ACP_BACKEND_KAS).routing is Routing.AGENT_SPEC
    assert backends.descriptor_for(ACP_BACKEND_CLAUDE).routing is Routing.SEEDED_SETTINGS
    assert backends.descriptor_for(ACP_BACKEND_CODEX).routing is Routing.SESSION_CONFIG
    assert backends.descriptor_for(ACP_BACKEND_GOOSE).routing is Routing.PERMISSION_REQUEST
    assert backends.descriptor_for(ACP_BACKEND_OPENCODE).routing is Routing.SEEDED_SETTINGS
    assert backends.descriptor_for(ACP_BACKEND_PI).routing is Routing.PERMISSION_REQUEST


def test_session_config_routing_names_an_option_and_an_exact_value() -> None:
    """A SESSION_CONFIG backend is unenforceable without both halves.

    ``session_config_issue`` requires the session to advertise this exact option
    id carrying this exact value, so an empty half would make every session
    refuse (or, with the opt-out on, start ungated) rather than arm the route.
    """
    for backend in sorted(ACP_BACKENDS_KNOWN):
        descriptor = backends.descriptor_for(backend)
        if descriptor.routing is Routing.SESSION_CONFIG:
            assert descriptor.permission_config_id, backend
            assert descriptor.permission_config_value, backend
        else:
            # A value on a backend that does not route through it would never be
            # applied, so it can only mislead a reader into thinking it is.
            assert not descriptor.permission_config_id, backend
            assert not descriptor.permission_config_value, backend


def test_selectability_is_a_separate_axis_from_being_described() -> None:
    """Selectability is owned by ACP_BACKENDS_SELECTABLE alone.

    Asserts the invariant that survives membership changes, rather than naming a
    withheld backend: this test named KAS, then codex, then derived the example
    from the sets, and each graduated in turn until nothing was withheld. Every
    selectable backend must be fully described, and selectable can never contain
    something unknown — which is what keeps the two concepts from collapsing into
    one when a registry adapter arrives described but not yet selectable.
    """
    assert ACP_BACKENDS_SELECTABLE <= ACP_BACKENDS_KNOWN
    for backend in sorted(ACP_BACKENDS_SELECTABLE):
        descriptor = backends.descriptor_for(backend)
        assert descriptor.label, backend
        assert descriptor.id == backend


class TestCachedRegistryAdapters:
    @pytest.mark.parametrize(
        ("kind", "want"),
        [
            ("npx", ["npx", "--no-install", "example-acp@1.0.0", "--acp"]),
            ("uvx", ["uvx", "--offline", "example-acp@1.0.0", "--acp"]),
        ],
    )
    def test_launch_argv_never_downloads_an_adapter(self, kind: str, want: list[str]) -> None:
        adapter = self._adapter(kind=kind)
        assert adapter.launch_argv == want

    @staticmethod
    def _adapter(*, kind: str = "npx"):
        from kiro_crew.acp import registry

        return registry.RegistryAdapter(
            id="example-acp",
            name="Example ACP",
            version="1.0.0",
            description="",
            repository="",
            license="MIT",
            icon="",
            kind=kind,
            package="example-acp@1.0.0",
            args=("--acp",),
            env=(("EXAMPLE_MODE", "acp"),),
        )

    def test_launchable_cached_adapter_is_selectable_and_described(self, monkeypatch) -> None:
        from kiro_crew.acp import registry

        adapter = self._adapter()
        monkeypatch.setattr(registry, "cached", lambda: {adapter.id: adapter})

        descriptor = backends.descriptor_for(adapter.id)
        assert descriptor.id == adapter.id
        assert descriptor.registry_id == adapter.id
        assert descriptor.routing is Routing.UNVERIFIED
        assert descriptor.dialect is Dialect.SPEC
        assert set(descriptor.capabilities.values()) == {Level.UNVERIFIED}
        assert adapter.id in backends.selectable_ids()

    def test_hand_written_registry_id_is_not_a_second_trust_path(self, monkeypatch) -> None:
        from kiro_crew.acp import registry
        from kiro_crew.acp.backends import Routing, descriptor_for, selectable_ids

        adapter = registry.RegistryAdapter(
            id="codex-acp",
            name="Codex",
            version="1.4.0",
            description="",
            repository="",
            license="Apache-2.0",
            icon="",
            kind="npx",
            package="@agentclientprotocol/codex-acp@1.4.0",
            args=(),
            env=(),
        )
        monkeypatch.setattr(registry, "cached", lambda: {adapter.id: adapter})

        descriptor = descriptor_for(adapter.id)
        assert descriptor.id == "codex"
        assert descriptor.routing is Routing.SESSION_CONFIG
        assert "codex-acp" not in selectable_ids()
        assert "codex" in selectable_ids()

    def test_hand_written_pi_is_not_a_second_unverified_path(self, monkeypatch) -> None:
        """``pi-acp`` is the registry spelling of the hand-written ``pi`` backend."""
        from kiro_crew.acp import registry
        from kiro_crew.acp.backends import Routing, descriptor_for, selectable_ids

        adapter = registry.RegistryAdapter(
            id="pi-acp",
            name="Pi ACP",
            version="1.0.0",
            description="",
            repository="",
            license="MIT",
            icon="",
            kind="npx",
            package="pi-acp@1.0.0",
            args=(),
            env=(),
        )
        monkeypatch.setattr(registry, "cached", lambda: {adapter.id: adapter})

        descriptor = descriptor_for(adapter.id)
        assert descriptor.id == ACP_BACKEND_PI
        assert descriptor.routing is Routing.PERMISSION_REQUEST
        assert "pi-acp" not in selectable_ids()
        assert ACP_BACKEND_PI in selectable_ids()


def test_canonical_backend_id_maps_registry_ids() -> None:
    from kiro_crew.acp.backends import canonical_backend_id
    from kiro_crew.acp.types import ACP_BACKEND_CLAUDE, ACP_BACKEND_CODEX

    assert canonical_backend_id("codex-acp") == ACP_BACKEND_CODEX
    assert canonical_backend_id("claude-acp") == ACP_BACKEND_CLAUDE
    assert canonical_backend_id("codex") == ACP_BACKEND_CODEX
    assert canonical_backend_id("pi-acp") == ACP_BACKEND_PI
    assert canonical_backend_id("opencode") == ACP_BACKEND_OPENCODE
    assert canonical_backend_id("example-acp") == "example-acp"
