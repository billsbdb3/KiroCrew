"""Warm-table tests: the loop/filesystem invariant, alias key shape, lifecycle."""

from __future__ import annotations

import ast
import inspect
from typing import Any

import pytest
from test_connections_mint import _FS_ATTRS, _FS_NAMES, _called_names

from kiro_crew.connections import tool_aliases, warm
from kiro_crew.connections.mint import _mints
from kiro_crew.connections.registry import Provider


@pytest.fixture(autouse=True)
def _clean_mint_table():
    _mints.clear()
    yield
    _mints.clear()


def _provider(slug: str, url: str = "") -> Provider:
    return {  # type: ignore[typeddict-item]
        "slug": slug,
        "mcp_url": url or f"https://{slug}.example/mcp",
        "l0_expectations": {"dcr": True},
    }


# ── the loop/filesystem invariant (mirrors the mint engine's own guard) ──
#
# Reuses the mint guard's primitive sets so the two cannot drift apart, plus the names that
# reach the filesystem only from THIS module: the MCP inventory read and the grant stat.
_WARM_FS_NAMES = _FS_NAMES | {"list_servers", "grant_present"}


def test_no_coroutine_in_the_warm_module_touches_the_filesystem_directly():
    tree = ast.parse(inspect.getsource(warm))
    sync: dict[str, Any] = {}
    coros: dict[str, Any] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            sync[node.name] = node
        elif isinstance(node, ast.AsyncFunctionDef):
            coros[node.name] = node
    assert sync and coros, "module shape changed; this guard is reading the wrong tree"

    touches = {
        name: bool(_called_names(node) & (_FS_ATTRS | _WARM_FS_NAMES))
        for name, node in sync.items()
    }
    changed = True
    while changed:
        changed = False
        for name, node in sync.items():
            if touches[name]:
                continue
            if any(touches.get(callee) for callee in _called_names(node)):
                touches[name] = changed = True
    fs_helpers = {name for name, hit in touches.items() if hit}
    # The known set, so a helper silently losing its filesystem work -- and with it
    # this guard's coverage -- is visible rather than a quietly weaker test.
    assert fs_helpers == {
        "_log_warm_event",
        "_disabled_provider_slugs",
        "warm_spec_providers",
        "_warm_activation_candidates",
        "_warm_candidate_scan",
        "mintable_providers",
        "_warm_spec_plan",
        "_write_warm_mint_specs",
        "_remove_warm_mint_specs",
        "_warm_work_dir",
    }

    offenders = {
        f"{coro} -> {callee}"
        for coro, node in coros.items()
        for callee in _called_names(node) & (fs_helpers | _FS_ATTRS | _WARM_FS_NAMES)
    }
    assert not offenders, (
        "filesystem work on the event loop: "
        + ", ".join(sorted(offenders))
        + " -- route it through asyncio.to_thread"
    )


# ── defect: tool-alias key shape ──
#
# The resolver de-collides by registry SLUG and keys ``@slug/tool``, but a warm spec mounts
# servers under ``mcp_server_alias(slug)``. Where the two differ a slug-keyed entry names a
# server the spec never mounted, so kiro-cli applies no rename and the collision returns.


@pytest.fixture
def _slash_bearing_registry(monkeypatch: pytest.MonkeyPatch):
    """Two providers whose slugs contain a slash, so slug and mounted alias differ."""
    declared = {
        "ns/alpha": {"shared_tool": "alpha_shared_tool"},
        "ns/beta": {"shared_tool": "beta_shared_tool"},
    }
    monkeypatch.setattr(tool_aliases, "declared_tool_aliases", lambda: declared)
    monkeypatch.setattr(warm, "declared_tool_aliases", lambda: declared)
    return declared


def test_alias_keys_name_the_server_the_spec_actually_mounts(_slash_bearing_registry):
    """RED before the re-key: the emitted keys were ``@ns/alpha/...``, a server the
    spec -- which mounts ``ns-alpha`` -- never declared, so no rename applied."""
    aliases = warm.connections_tool_aliases(["ns-alpha", "ns-beta"])
    assert aliases == {
        "@ns-alpha/shared_tool": "alpha_shared_tool",
        "@ns-beta/shared_tool": "beta_shared_tool",
    }
    mounted = {"ns-alpha", "ns-beta"}
    assert {key.lstrip("@").rpartition("/")[0] for key in aliases} == mounted


def test_the_spec_a_warm_plan_writes_only_mounts_aliased_servers(_slash_bearing_registry):
    body = warm._warm_spec_body(
        "probe", {"ns-alpha": {"url": "https://a"}, "ns-beta": {"url": "https://b"}}, "probe"
    )
    assert set(body["toolAliases"]) <= {f"@{alias}/shared_tool" for alias in body["mcpServers"]}


# ── defect: alias semantics are #3260's, not the pre-#3260 first-server rule ──
#
# The draft asserted that the FIRST mounted server keeps the bare name and only later ones are
# renamed. #3260 shipped rename-EVERY-claimant, slug-keyed: when two mounted servers claim a
# tool, both are renamed and neither keeps the bare name.


def test_every_claimant_of_a_collision_is_renamed_not_just_the_later_one():
    aliases = warm.connections_tool_aliases(["linear", "vercel"])
    assert aliases == {
        "@linear/get_project": "linear_get_project",
        "@linear/list_projects": "linear_list_projects",
        "@linear/list_teams": "linear_list_teams",
        "@vercel/get_project": "vercel_get_project",
        "@vercel/list_projects": "vercel_list_projects",
        "@vercel/list_teams": "vercel_list_teams",
    }
    # Tools only one of the mounted pair declares keep their natural names.
    assert not any(key.endswith(("list_issues", "get_issue")) for key in aliases)


def test_a_single_mounted_provider_needs_no_aliases():
    assert warm.connections_tool_aliases(["linear"]) == {}
    assert warm.connections_tool_aliases(["vercel"]) == {}


def test_a_warm_spec_declares_tool_aliases_only_when_a_collision_is_mounted():
    single = warm._warm_spec_body("m", {"vercel": {"url": "https://v"}}, "probe")
    assert "toolAliases" not in single
    both = warm._warm_spec_body(
        "m", {"linear": {"url": "https://l"}, "vercel": {"url": "https://v"}}, "probe"
    )
    assert both["toolAliases"]["@linear/list_teams"] == "linear_list_teams"
    assert both["toolAliases"]["@vercel/list_teams"] == "vercel_list_teams"


# ── spec sweep: never unlink a live COLD mint's spec ──


def test_the_warm_sweep_refuses_a_cold_mint_spec_that_shares_the_prefix():
    """A cold spec for a server named ``warm-*`` matches the warm prefix. Deleting it
    would strand a user mid-consent, so the cold ``-<pid>-<8hex>`` shape is refused --
    including a MIXED-CASE alias, which only a shared character class catches."""
    for cold in ("kirocrew-mint-warm-foo-4821-9ab3c1de", "kirocrew-mint-warm-Foo-4821-9ab3c1de"):
        assert warm._is_stale_warm_spec(cold, frozenset()) is False


def test_the_warm_sweep_drops_a_warm_spec_absent_from_the_plan_and_keeps_the_rest():
    assert warm._is_stale_warm_spec("kirocrew-mint-warm-notion", frozenset()) is True
    assert (
        warm._is_stale_warm_spec(
            "kirocrew-mint-warm-notion", frozenset({"kirocrew-mint-warm-notion"})
        )
        is False
    )
    assert warm._is_stale_warm_spec("some-user-agent", frozenset()) is False


# ── servability: a set that SHRANK is still servable ──


def _plan(entries: dict[str, dict[str, Any]]) -> warm._WarmSpecPlan:
    return warm._WarmSpecPlan(
        all_agent="all" if entries else "",
        per_provider={alias: f"spec-{alias}" for alias in entries},
        specs={},
        entries=entries,
        digest=repr(sorted(entries.items())),
    )


def test_a_shrunk_candidate_set_is_served_by_the_running_process():
    resident = _plan({"linear": {"url": "https://l"}, "vercel": {"url": "https://v"}})
    assert warm._plan_is_servable(resident, _plan({"linear": {"url": "https://l"}})) is True


def test_a_changed_authorization_ask_is_not_servable():
    resident = _plan({"linear": {"url": "https://l"}})
    assert warm._plan_is_servable(resident, _plan({"linear": {"url": "https://other"}})) is False
    assert warm._plan_is_servable(resident, _plan({"notion": {"url": "https://n"}})) is False


def test_a_process_that_enumerated_nothing_serves_nothing():
    assert warm._plan_is_servable(_plan({}), _plan({"linear": {"url": "https://l"}})) is False


# ── candidates: a granted provider is warmed into the spec but asked for no URL ──


def test_a_granted_provider_is_not_an_activation_candidate(monkeypatch: pytest.MonkeyPatch):
    universe = [_provider("granted"), _provider("fresh")]
    monkeypatch.setattr(warm, "grant_present", lambda url: "granted" in url)
    assert [p["slug"] for p in warm._warm_activation_candidates(universe)] == ["fresh"]


def test_an_unreadable_inventory_warms_nothing_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        warm, "warm_spec_providers", lambda: (_ for _ in ()).throw(OSError("config unreadable"))
    )
    assert warm._warm_candidate_scan() == ([], [])


# ── one activation fills the whole table ──


@pytest.fixture
def _stub_activation(monkeypatch: pytest.MonkeyPatch):
    """Neutralize the process, the audit log and the grant watcher."""

    async def _no_watcher(slug: str, mcp_url: str, token: str) -> None:
        return None

    async def _no_settle(activation: int, in_use: set[int]) -> None:
        return None

    monkeypatch.setattr(warm, "_mint_watcher", _no_watcher)
    monkeypatch.setattr(warm, "_log_warm_event", lambda *a, **k: None)
    monkeypatch.setattr(warm._warm_mint, "settle_activation", _no_settle)


@pytest.mark.asyncio
async def test_one_activation_stamps_every_row_with_its_generation_and_activation(
    monkeypatch: pytest.MonkeyPatch, _stub_activation
):
    providers = [_provider("linear"), _provider("vercel")]
    result = warm._WarmMintResult(
        generation=7,
        activation=3,
        providers=providers,
        requests=[
            {"serverName": "linear", "oauthUrl": "https://l/consent"},
            {"serverName": "vercel", "oauthUrl": "https://v/consent"},
        ],
    )

    async def _activate(*, slug: str = "", started: float | None = None):
        return result

    monkeypatch.setattr(warm, "_warm_activate", _activate)

    minted = await warm.warm_mint_all(providers)

    assert sorted(minted) == ["linear", "vercel"]
    for slug in ("linear", "vercel"):
        row = _mints[slug]
        assert row["state"] == "waiting"
        assert row["generation"] == 7 and row["activation"] == 3
        assert row["shared"] is True
        # Every row carries the cold engine's row identity, which is what the grant
        # watcher re-checks before it writes a verdict.
        assert row["token"]
    assert len({_mints["linear"]["token"], _mints["vercel"]["token"]}) == 2


@pytest.mark.asyncio
async def test_a_claim_the_activation_did_not_cover_is_released_not_left_minting(
    monkeypatch: pytest.MonkeyPatch, _stub_activation
):
    claimed = [_provider("linear"), _provider("stranded")]
    result = warm._WarmMintResult(
        generation=1,
        activation=1,
        providers=[claimed[0]],
        requests=[{"serverName": "linear", "oauthUrl": "https://l/consent"}],
    )

    async def _activate(*, slug: str = "", started: float | None = None):
        return result

    monkeypatch.setattr(warm, "_warm_activate", _activate)

    assert await warm.warm_mint_all(claimed) == ["linear"]
    assert "stranded" not in _mints, "an uncovered claim must not sit in the table forever"


@pytest.mark.asyncio
async def test_a_failed_activation_releases_every_claim(
    monkeypatch: pytest.MonkeyPatch, _stub_activation
):
    async def _activate(*, slug: str = "", started: float | None = None):
        return None

    monkeypatch.setattr(warm, "_warm_activate", _activate)
    assert await warm.warm_mint_all([_provider("linear")]) == []
    assert _mints == {}


@pytest.mark.asyncio
async def test_a_cold_held_row_is_never_replaced_by_a_warm_claim():
    _mints["linear"] = {"state": "waiting", "client": object(), "oauth_url": "https://cold"}
    assert await warm._claim_shared_mints(["linear"], 100.0) == []
    assert _mints["linear"]["oauth_url"] == "https://cold"


# ── withdrawal is keyed on the FACT that the holder is gone ──


@pytest.mark.asyncio
async def test_a_row_whose_generation_is_gone_is_withdrawn():
    _mints["linear"] = {
        "state": "waiting",
        "oauth_url": "https://l/consent",
        "shared": True,
        "generation": 99,
        "activation": 1,
    }
    assert await warm.expire_dead_mints() == ["linear"]
    assert _mints["linear"]["state"] == "expired"
    assert _mints["linear"]["reason"] == "mint_process_gone"


@pytest.mark.asyncio
async def test_a_cold_row_is_left_to_the_cold_engine():
    """``_mint_holder_alive`` answers False for a shared row, so the warm chokepoint
    must judge only shared rows -- and leave a cold row's own verdict alone."""
    _mints["linear"] = {"state": "waiting", "oauth_url": "https://cold", "client": object()}
    assert await warm.expire_dead_mints() == []
    assert _mints["linear"]["state"] == "waiting"


@pytest.mark.asyncio
async def test_expiry_can_be_narrowed_to_one_generation_and_spare_a_retry():
    _mints["a"] = {"state": "waiting", "shared": True, "generation": 1, "started": 10.0}
    _mints["b"] = {"state": "waiting", "shared": True, "generation": 2, "started": 11.0}
    assert await warm._expire_shared_mints("mint_process_gone", generation=1) == ["a"]
    assert _mints["b"]["state"] == "waiting"
    # The retry's own claim survives, because its rows are the ones it will fill.
    assert await warm._expire_shared_mints("mint_process_gone", keep_started=11.0) == []
    assert _mints["b"]["state"] == "waiting"


def test_a_warm_session_never_injects_mcp_servers():
    """A remote server through ``session/new`` kills the process and every verifier."""
    assert warm._warm_session_mcp_servers() == []
