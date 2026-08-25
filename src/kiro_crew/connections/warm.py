"""The shared warm-process mint: one kiro-cli process, every card's approval URL.

The cold path (:mod:`kiro_crew.connections.mint`) pays a full kiro-cli spawn PER
provider. Mode activation costs a FIXED ~5.18s whether the spec carries one remote
server or six, so a spec holding every mintable provider yields every
``oauth_request`` in a SINGLE activation.

Four rules are load-bearing, each written against an observed failure, and all four are
recorded with their failures in
``docs/architecture/design-notes/connections-warm-table.md``: the SESSION is HELD (see
``_warm_row_alive``), specs are enumerated ONCE at spawn (``_WarmSpecPlan.digest``, and a
process still holding a consent is PARKED rather than killed), the spec universe is
registry-derived and BLIND to grant and cancel state, and a warm session injects an EMPTY
``mcp_servers`` list because remote servers passed through ``session/new`` kill the
process with every pending verifier in it.

INVARIANT: no coroutine here touches the filesystem directly. Every flow reads the
user's config, the shared agents dir, or kiro-cli's OAuth cache -- any of which can
sit on a network mount where a stat is unbounded -- so the synchronous helpers are
reached through ``asyncio.to_thread``. Enforced by a fixed-point drift guard in
``test/test_connections_warm.py``, not merely described here.

SEAMS left open: revocation is PR #5899's (a revoke that should re-warm triggers
through ``_expire_shared_mints``, already keyed on cause), and proactive refresh is
slice N3's, attaching in ``_warm_mint_reaper``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kiro_crew import agent as _agent
from kiro_crew.acp.runtime import AcpRuntime
from kiro_crew.agent_files import AGENT_FILENAME
from kiro_crew.config.loader import data_home
from kiro_crew.connections.mint import (
    _MINT_AGENT_PREFIX,
    _MINT_GRANT_POLL_SECONDS,
    _MINT_NAME_RE,
    _MINT_TTL_SECONDS,
    MintState,
    _dispose_mint,
    _mint_spec_body,
    _mint_watcher,
    _mints,
    _mints_lock,
    _new_mint_token,
)
from kiro_crew.connections.registry import Provider, get_visible_providers
from kiro_crew.connections.tool_aliases import declared_tool_aliases, resolve_tool_aliases
from kiro_crew.mcp_discovery import list_servers
from kiro_crew.mcp_grant import grant_presence as grant_present
from kiro_crew.mcp_utils import (
    kiro_entry_client_id,
    kiro_entry_scopes,
    kiro_oauth_wire_entry,
    mcp_server_alias,
)
from kiro_crew.sel import sel

logger = logging.getLogger(__name__)

#: Warm specs are FIXED names under the cold mint's prefix, so one glob finds them all. They
#: carry no ``-<pid>-<8hex>`` suffix, which keeps them out of the cold engine's manifest sweep
#: -- and is the only thing telling a warm spec from a cold one whose server is literally named
#: ``warm-*`` (see ``_is_stale_warm_spec``). The character class MUST match the cold engine's: a
#: case only ONE pattern accepts reads as ours and gets its live spec unlinked.
_WARM_AGENT_PREFIX = f"{_MINT_AGENT_PREFIX}warm-"
_WARM_NAME_RE = re.compile(rf"^{re.escape(_WARM_AGENT_PREFIX)}[a-z0-9_.-]+$")
_WARM_BASE_AGENT = f"{_WARM_AGENT_PREFIX}base"
_WARM_ALL_AGENT = f"{_WARM_AGENT_PREFIX}all"
_WARM_SPAWN_TIMEOUT_SECONDS = 90.0
_WARM_SESSION_TIMEOUT_SECONDS = 90.0
_WARM_SESSION_DESTROY_TIMEOUT_SECONDS = 10.0
_WARM_KILL_TIMEOUT_SECONDS = 20.0
#: The oauth_request frame lands a beat AFTER set_mode returns (~0.35s measured),
#: beyond drain_init's idle window for a slow provider. Poll rather than race it.
_WARM_OAUTH_SETTLE_SECONDS = 0.5
_WARM_OAUTH_SETTLE_ROUNDS = 6
#: A tenth of the mint TTL: long enough that reopening the gallery reuses the
#: process, short enough that an abandoned visit leaves no kiro-cli resident.
_WARM_IDLE_GRACE_SECONDS = _MINT_TTL_SECONDS / 10
#: One respawn, then the cold path -- a second death means the process cannot stay
#: up, and a Connect is better served by its own dedicated spawn.
_WARM_ACTIVATION_ATTEMPTS = 2

_LIVE_STATES = ("minting", "waiting")


class _WarmMintUnsafe(RuntimeError):
    """A warm mint was about to be issued in a way that kills the shared process."""


class _WarmMintDied(RuntimeError):
    """The shared process was gone by the end of an activation."""

    def __init__(self, cause: str) -> None:
        super().__init__(cause)
        self.cause = cause


def _acp_runtime_factory() -> Any:
    """Indirection so tests can substitute a fake runtime class."""
    return AcpRuntime


def _warm_session_mcp_servers() -> list[dict[str, Any]]:
    """The session-injected MCP servers for a warm mint: ALWAYS empty."""
    return []


def _log_warm_event(operation: str, resources: str) -> None:
    """Record a warm-table event. Never carries a URL or an exception message."""
    sel().log_api_access(
        caller="dashboard",
        operation=operation,
        outcome="ok",
        source="dashboard",
        resources=resources,
    )


def connections_tool_aliases(server_aliases: list[str]) -> dict[str, str]:
    """``toolAliases`` for a spec mounting ``server_aliases``, or ``{}``.

    kiro-cli exposes MCP tool names RAW, so two mounted servers exporting the same
    name leave only one reachable. The collision set is DECLARED by the registry and
    resolved by :func:`resolve_tool_aliases`, so it is known before consent -- the
    MCP inventory carries no tool list for a server that never authorized.

    KEY SHAPE. The resolver keys by registry SLUG (``@slug/tool``) while this spec mounts
    servers under ``mcp_server_alias(slug)``, and where the two differ kiro-cli applies no
    rename and the collision comes back silently -- so keys are re-pointed at the MOUNTED
    alias here. Every registry slug is slash-free today, making this an identity map that
    holds the shape contract of the spec we WRITE rather than fixing a reachable bug; the
    design note's "Tool-alias key shape" carries the full reasoning.
    """
    declared = declared_tool_aliases()
    wanted = set(server_aliases)
    mounted = {slug: alias for slug in declared if (alias := mcp_server_alias(slug)) in wanted}
    resolved = resolve_tool_aliases(
        {slug: set(tools) for slug, tools in declared.items() if slug in mounted}
    )
    aliased: dict[str, str] = {}
    for ref, alias in resolved.items():
        # rpartition, not partition: a registry slug may itself contain a slash while a tool
        # name never does, so the LAST separator reliably splits server from tool.
        slug, _, tool = ref.lstrip("@").rpartition("/")
        aliased[f"@{mounted.get(slug, slug)}/{tool}"] = alias
    return dict(sorted(aliased.items()))


def _warm_spec_body(name: str, servers: dict[str, Any], description: str) -> dict[str, Any]:
    """A mint spec body plus the ``toolAliases`` its mounted set needs."""
    body = _mint_spec_body(name, servers, description)
    aliases = connections_tool_aliases(list(servers))
    if aliases:
        body["toolAliases"] = aliases
    return body


def _registry_server_entry(provider: Provider) -> dict[str, Any] | None:
    """The remote MCP entry the registry implies for ``provider``, in wire shape."""
    entry: dict[str, Any] = {"url": provider["mcp_url"]}
    scopes = provider.get("recommended_scopes") or []
    if scopes:
        entry["scopes"] = list(scopes)
    client_id = provider.get("client_id")
    if client_id:
        entry["clientId"] = client_id
    # store_entry=None: registry-derived, so no store owns it.
    return kiro_oauth_wire_entry(entry, store_entry=None, server=str(provider["slug"]))


def _disabled_provider_slugs() -> set[str]:
    """Registry slugs whose configured MCP entry the user turned OFF."""
    disabled = {server.name for server in list_servers() if server.disabled}
    return {
        provider["slug"]
        for provider in get_visible_providers()
        if provider["slug"] in disabled or mcp_server_alias(provider["slug"]) in disabled
    }


def warm_spec_providers() -> list[Provider]:
    """The spec UNIVERSE: every provider the shared process ENUMERATES at spawn."""
    disabled = _disabled_provider_slugs()
    return [
        provider
        for provider in get_visible_providers()
        if provider["slug"] not in disabled and _warm_mintable_entry(provider, None) is not None
    ]


def _warm_activation_candidates(universe: list[Provider]) -> list[Provider]:
    """The subset of ``universe`` an activation should actually ask a URL for."""
    return [provider for provider in universe if not grant_present(provider["mcp_url"])]


def _warm_candidate_scan() -> tuple[list[Provider], list[Provider]]:
    """``(spec universe, activation candidates)`` from one pass over the registry."""
    try:
        universe = warm_spec_providers()
    except Exception:  # noqa: BLE001 — reads user config; degrade to warming nothing
        logger.debug("warm mint inventory read failed", exc_info=True)
        return [], []
    return universe, _warm_activation_candidates(universe)


def mintable_providers() -> list[Provider]:
    """Providers an activation should warm right now, registry order."""
    return _warm_candidate_scan()[1]


def _wanted_aliases(providers: list[Provider]) -> frozenset[str]:
    """The server aliases an activation must produce a challenge for."""
    return frozenset(mcp_server_alias(provider["slug"]) for provider in providers)


def _auth_shape(entry: dict[str, Any]) -> tuple[str, tuple[str, ...], str]:
    """The fields of an MCP entry that decide what an authorization asks for."""
    return (
        str(entry.get("url") or ""),
        tuple(kiro_entry_scopes(entry)),
        kiro_entry_client_id(entry),
    )


def _warm_mintable_entry(
    provider: Provider, configured: dict[str, Any] | None
) -> dict[str, Any] | None:
    """The REGISTRY entry the warm process would activate, or None if it cannot.

    Registry-derived on purpose: a plan built from the user's config changed on every
    Connect click, respawning a process holding other cards' live listeners.

    None in two cases: no usable auth configuration (no DCR and no pre-registered public
    client id -- GitHub is the standing example), or a CONFIGURED entry asking for
    something different from the registry, which only the cold path can honour without
    handing back a grant the user did not ask for.
    """
    entry = _registry_server_entry(provider)
    if entry is None:
        return None
    expectations: dict[str, Any] = dict(provider.get("l0_expectations") or {})
    # Through the accessor: the wire shape nests the client id under ``oauth``, so a
    # bare ``clientId`` lookup reads every registered non-DCR provider as unregistered.
    if not bool(expectations.get("dcr")) and not kiro_entry_client_id(entry):
        return None
    if isinstance(configured, dict) and _auth_shape(configured) != _auth_shape(entry):
        return None
    return entry


@dataclass(frozen=True)
class _WarmSpecPlan:
    """Every agent spec the warm process needs, plus a digest of their contents."""

    all_agent: str
    per_provider: dict[str, str]
    specs: dict[str, dict[str, Any]]
    entries: dict[str, dict[str, Any]]
    digest: str


def _plan_is_servable(resident: _WarmSpecPlan, wanted: _WarmSpecPlan) -> bool:
    """True when the RUNNING process's specs can still serve ``wanted``.

    Digest equality is the wrong test alone: it reads a set that SHRANK as a set that
    changed. The only thing a respawn can fix is a server the process was never told
    about, so a plan whose every entry is already resident with an identical authorization
    ask is servable -- and replacing the process would strand its peers' listeners for
    nothing. A changed url/scopes/client id is genuine incompatibility: authorizing the
    resident ask would hand back the wrong grant.
    """
    if not resident.all_agent:
        return False
    return all(resident.entries.get(alias) == entry for alias, entry in wanted.entries.items())


def _warm_spec_plan(providers: list[Provider]) -> _WarmSpecPlan:
    """Build (but do not write) the warm process's spec set."""
    agents_dir = _agent.kiro_agents_dir_path()
    configured = _agent._load_json(agents_dir / AGENT_FILENAME).get("mcpServers") or {}
    entries: dict[str, dict[str, Any]] = {}
    per_provider: dict[str, str] = {}
    for provider in providers:
        alias = mcp_server_alias(provider["slug"])
        entry = _warm_mintable_entry(provider, configured.get(alias))
        if entry is None:
            continue
        entries[alias] = entry
        per_provider[provider["slug"]] = f"{_WARM_AGENT_PREFIX}{alias}"

    # The BASE spec carries zero servers on purpose: it is what the process spawns on, so
    # anything it declared would be initialized -- and challenged for -- before any mint.
    specs: dict[str, dict[str, Any]] = {
        _WARM_BASE_AGENT: _warm_spec_body(
            _WARM_BASE_AGENT, {}, "Zero-server base spec for the shared approval-URL mint."
        )
    }
    if entries:
        specs[_WARM_ALL_AGENT] = _warm_spec_body(
            _WARM_ALL_AGENT, entries, "Every mintable provider: one activation warms every card."
        )
    for slug, name in per_provider.items():
        alias = mcp_server_alias(slug)
        specs[name] = _warm_spec_body(
            name, {alias: entries[alias]}, f"Single-provider approval-URL mint for {alias}."
        )
    digest = hashlib.sha256(
        json.dumps(specs, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return _WarmSpecPlan(
        all_agent=_WARM_ALL_AGENT if entries else "",
        per_provider=per_provider,
        specs=specs,
        entries=entries,
        digest=digest,
    )


def _is_stale_warm_spec(stem: str, plan_names: frozenset[str]) -> bool:
    """Whether ``stem`` is a warm spec from a previous plan, safe to unlink.

    Three conjuncts, and the third is not redundant: a COLD mint spec for a server
    literally named ``warm-*`` shares this module's prefix
    (``kirocrew-mint-warm-foo-4821-9ab3c1de``), so prefix plus not-in-plan alone would
    delete a live cold mint's spec and strand a user mid-consent. Only the
    ``-<pid>-<8hex>`` suffix separates the two, over one shared character class.
    """
    return (
        stem not in plan_names
        and _WARM_NAME_RE.match(stem) is not None
        and _MINT_NAME_RE.match(f"{stem}.json") is None
    )


def _write_warm_mint_specs(plan: _WarmSpecPlan) -> None:
    """Write the whole spec set, removing warm specs no longer in it."""
    agents_dir = _agent.kiro_agents_dir_path()
    agents_dir.mkdir(parents=True, exist_ok=True)
    plan_names = frozenset(plan.specs)
    try:
        for path in agents_dir.glob(f"{_WARM_AGENT_PREFIX}*.json"):
            if _is_stale_warm_spec(path.stem, plan_names):
                path.unlink(missing_ok=True)
    except OSError:
        logger.debug("warm mint spec sweep failed", exc_info=True)
    for name, spec in plan.specs.items():
        _agent._atomic_json_write(agents_dir / f"{name}.json", spec)


def _remove_warm_mint_specs() -> None:
    """Unlink every warm spec. Called when the shared process is retired."""
    try:
        for path in _agent.kiro_agents_dir_path().glob(f"{_WARM_AGENT_PREFIX}*.json"):
            if _is_stale_warm_spec(path.stem, frozenset()):
                path.unlink(missing_ok=True)
    except Exception:  # noqa: BLE001 — spec files; the write-time sweep catches leftovers
        logger.debug("warm mint spec removal failed", exc_info=True)


def _warm_work_dir() -> Path:
    """The shared process's working directory."""
    return data_home() / "connections" / "warm-mint"


def _runtime_alive(runtime: Any) -> bool:
    """Liveness of one warm process. Never raises into a mint."""
    if runtime is None:
        return False
    try:
        return bool(runtime.is_alive())
    except Exception:  # noqa: BLE001 — liveness must never raise into a mint
        logger.debug("warm mint liveness check failed", exc_info=True)
        return False


def _live_row_count(generation: int) -> int:
    """How many cards are still mid-consent on ``generation``."""
    return sum(
        1
        for entry in _mints.values()
        if entry.get("shared")
        and entry.get("generation") == generation
        and entry.get("state") in _LIVE_STATES
    )


def _generation_holds_live_rows(generation: int) -> bool:
    """True while killing ``generation`` would strand a redeemable code."""
    return _live_row_count(generation) > 0


def _activations_in_use() -> set[int]:
    """Activation ids a live shared row still points at -- the sweep's keep-set."""
    return {
        int(entry["activation"])
        for entry in _mints.values()
        if entry.get("shared") and entry.get("activation") and entry.get("state") in _LIVE_STATES
    }


@dataclass
class _WarmSession:
    """One live ACP session on the shared process, and what it owns.

    Held because the session owns the loopback callback servers for its challenges.
    ``settled`` flips once the URLs are absorbed into the mint table, which is what makes
    the sweep safe -- an activation still in flight is referenced by no row. ``expires_at``
    is why a session outlives the rows that pointed at it: a replaced URL may still be open
    on the provider's consent page, and one mint TTL is exactly the window in which that
    code is still redeemable.
    """

    generation: int
    handle: Any
    expires_at: float
    settled: bool = False


@dataclass(frozen=True)
class _WarmMintResult:
    """One activation's product, plus the snapshot and process it ran on."""

    generation: int
    activation: int
    providers: list[Provider]
    requests: list[dict[str, str]]


class _WarmMintRuntime:
    """One kiro-cli process shared by every card's approval-URL mint."""

    def __init__(self) -> None:
        self._runtime: Any = None
        self._plan: _WarmSpecPlan | None = None
        self._digest = ""
        #: Bumped on every spawn. Rows record the generation that minted them, letting a
        #: stand-down tell "nothing needs this" from "killing it strands a user mid-consent".
        self._generation = 0
        #: Generations kept alive ONLY because a card still holds one of their URLs.
        #: New mints never route here; the reaper kills each once its rows are gone.
        self._retiring: list[tuple[int, Any]] = []
        #: Live sessions by activation id -- each owns the loopback servers for its
        #: challenges, so one is held while a card points at one of its URLs.
        self._sessions: dict[int, _WarmSession] = {}
        self._activation_seq = 0
        self._lock = asyncio.Lock()
        self._reaper: Any = None

    def is_alive(self) -> bool:
        return _runtime_alive(self._runtime)

    def generation_is_live(self, generation: int) -> bool:
        """True while the process that minted ``generation`` can still redeem."""
        if generation <= 0:
            return False
        if generation == self._generation:
            return self.is_alive()
        return any(
            parked == generation and _runtime_alive(runtime) for parked, runtime in self._retiring
        )

    def activation_is_live(self, activation: int) -> bool:
        """True while the SESSION that minted ``activation`` still listens."""
        if activation <= 0:
            return False
        return activation in self._sessions

    async def settle_activation(self, activation: int, in_use: set[int]) -> None:
        """Mark ``activation`` absorbed, then collect the sessions nothing needs."""
        async with self._lock:
            record = self._sessions.get(activation)
            if record is not None:
                record.settled = True
            await self._sweep_sessions_locked(in_use)

    async def sweep_sessions(self, in_use: set[int]) -> None:
        """Collect settled sessions no live row points at."""
        async with self._lock:
            await self._sweep_sessions_locked(in_use)

    async def _sweep_sessions_locked(self, in_use: set[int]) -> None:
        """Collect settled sessions no row needs AND whose TTL has run out."""
        now = time.monotonic()
        doomed = [
            activation
            for activation, record in self._sessions.items()
            if record.settled and activation not in in_use and record.expires_at <= now
        ]
        for activation in doomed:
            record = self._sessions.pop(activation, None)
            if record is not None:
                await _destroy_session_quietly(record.handle)

    def _drop_generation_sessions(self, generation: int) -> None:
        """Forget one generation's sessions. Its process death already reaped them."""
        for activation in [
            activation
            for activation, record in self._sessions.items()
            if record.generation == generation
        ]:
            self._sessions.pop(activation, None)

    async def mint_for(self, *, slug: str = "") -> _WarmMintResult | None:
        """Ensure a live process, activate it, return its challenges."""
        async with self._lock:
            await self._sweep_retiring_locked()
            universe, candidates = await asyncio.to_thread(_warm_candidate_scan)
            if slug and not any(provider["slug"] == slug for provider in candidates):
                return None
            # The UNIVERSE decides what the process must have enumerated; the CANDIDATES
            # decide what this activation asks for. Apart, a grant moves the second only.
            if not await self._ensure_locked(universe):
                return None
            plan = self._plan
            if plan is None:
                return None
            agent = plan.per_provider.get(slug, "") if slug else plan.all_agent
            if not agent:
                return None
            wanted = [
                provider
                for provider in candidates
                if provider["slug"] in plan.per_provider and (not slug or provider["slug"] == slug)
            ]
            if not wanted:
                return None
            generation = self._generation
            try:
                activation, requests = await self._activate_locked(agent, _wanted_aliases(wanted))
            except Exception as exc:
                if self.is_alive():
                    # One activation failed but the process still serves: its other verifiers
                    # are intact, so killing it here destroys still-completable consent flows.
                    raise
                await self._park_or_kill_locked()
                raise _WarmMintDied(type(exc).__name__) from exc
            return _WarmMintResult(
                generation=generation,
                activation=activation,
                providers=wanted,
                requests=requests,
            )

    async def _ensure_locked(self, providers: list[Provider]) -> bool:
        """Guarantee a process whose specs can serve ``providers``."""
        try:
            plan = await asyncio.to_thread(_warm_spec_plan, providers)
        except Exception:  # noqa: BLE001 — reads user-editable JSON; never fail a mint
            logger.debug("warm mint spec plan failed", exc_info=True)
            return False
        if not plan.all_agent:
            return False

        if self.is_alive() and self._digest == plan.digest:
            return True
        resident = self._plan
        if self.is_alive() and resident is not None and _plan_is_servable(resident, plan):
            logger.info(
                "Shared mint generation %d already serves the new candidate set; "
                "re-activating instead of respawning",
                self._generation,
            )
            return True
        if self._runtime is not None:
            logger.info(
                "Starting a new shared mint generation (%s)",
                "specs are incompatible" if self.is_alive() else "process is gone",
            )
        await self._park_or_kill_locked()

        runtime: Any = None
        try:
            await asyncio.to_thread(_write_warm_mint_specs, plan)
            runtime = _acp_runtime_factory()(
                work_dir=await asyncio.to_thread(_warm_work_dir),
                agent=_WARM_BASE_AGENT,
                sandbox_mode="auto",
            )
            await asyncio.wait_for(runtime.spawn(), timeout=_WARM_SPAWN_TIMEOUT_SECONDS)
        except Exception as exc:  # noqa: BLE001 — degrade to the cold path
            logger.warning("Shared mint process spawn failed: %s", type(exc).__name__)
            if runtime is not None:
                await _kill_quietly(runtime)
            if not self._retiring:
                await asyncio.to_thread(_remove_warm_mint_specs)
            return False

        self._runtime, self._plan, self._digest = runtime, plan, plan.digest
        self._generation += 1
        self._reaper = asyncio.get_running_loop().create_task(_warm_mint_reaper(self._generation))
        await asyncio.to_thread(
            _log_warm_event,
            "connections_warm_mint_spawn",
            f"providers:{len(plan.per_provider)} generation:{self._generation}",
        )
        return True

    async def _activate_locked(
        self, agent: str, wanted: frozenset[str]
    ) -> tuple[int, list[dict[str, str]]]:
        """Activate ``agent`` on the shared process and return its challenges."""
        runtime = self._runtime
        if runtime is None or not self.is_alive():
            raise _WarmMintUnsafe("the shared mint process is not alive")
        servers = _warm_session_mcp_servers()
        if servers:
            # Never reachable from our own code -- the guard exists because the failure is
            # silent and total: session/new-injected servers kill the process and its verifiers.
            raise _WarmMintUnsafe("session-injected MCP servers would kill the shared process")

        handle = await asyncio.wait_for(
            runtime.create_session(agent=agent, mcp_servers=servers),
            timeout=_WARM_SESSION_TIMEOUT_SECONDS,
        )
        self._activation_seq += 1
        activation = self._activation_seq
        self._sessions[activation] = _WarmSession(
            generation=self._generation,
            handle=handle,
            expires_at=time.monotonic() + _MINT_TTL_SECONDS,
        )
        collected: dict[str, dict[str, str]] = {}
        try:
            for round_index in range(_WARM_OAUTH_SETTLE_ROUNDS):
                for request in handle.pop_pending_oauth_requests():
                    name = str(request.get("serverName") or "")
                    if name and request.get("oauthUrl"):
                        collected[name] = request
                if wanted and wanted <= collected.keys():
                    break
                if round_index + 1 < _WARM_OAUTH_SETTLE_ROUNDS:
                    await asyncio.sleep(_WARM_OAUTH_SETTLE_SECONDS)
        except BaseException:
            # Nothing will ever be stamped with this activation, so the session it
            # registered would leak past the sweep's settled-only rule.
            self._sessions.pop(activation, None)
            await _destroy_session_quietly(handle)
            raise
        return activation, list(collected.values())

    async def shutdown(self) -> None:
        async with self._lock:
            await self._retire_locked()

    async def sweep_retiring(self) -> None:
        """Kill parked generations nothing is waiting on any more."""
        async with self._lock:
            await self._sweep_retiring_locked()

    async def _sweep_retiring_locked(self) -> None:
        keep: list[tuple[int, Any]] = []
        drop: list[tuple[int, Any]] = []
        for pair in self._retiring:
            generation, runtime = pair
            needed = _runtime_alive(runtime) and _generation_holds_live_rows(generation)
            (keep if needed else drop).append(pair)
        self._retiring = keep
        for generation, runtime in drop:
            logger.info("Retiring parked shared mint generation %d", generation)
            await self._kill_generation(generation, runtime)

    async def _park_or_kill_locked(self) -> None:
        """Stand the current process down: PARKED when a card still needs it."""
        runtime, generation = self._runtime, self._generation
        reaper, self._reaper = self._reaper, None
        self._runtime, self._plan, self._digest = None, None, ""
        # The reaper is the caller on the idle path; cancelling the current task
        # would abandon the kill it is in the middle of awaiting.
        if reaper is not None and reaper is not asyncio.current_task():
            reaper.cancel()
        if runtime is None:
            return
        if _runtime_alive(runtime) and _generation_holds_live_rows(generation):
            self._retiring.append((generation, runtime))
            logger.info(
                "Parking shared mint generation %d: %d card(s) still mid-consent on it",
                generation,
                _live_row_count(generation),
            )
            return
        await self._kill_generation(generation, runtime)

    async def _kill_generation(self, generation: int, runtime: Any) -> None:
        """Kill one process and expire the links only it could have redeemed."""
        await _kill_quietly(runtime)
        self._drop_generation_sessions(generation)
        await _expire_shared_mints("mint_process_gone", generation=generation)
        if self._runtime is None and not self._retiring:
            await asyncio.to_thread(_remove_warm_mint_specs)

    async def _retire_locked(self) -> None:
        """Hard teardown: every generation, parked ones included."""
        reaper, runtime, generation = self._reaper, self._runtime, self._generation
        parked, self._retiring = self._retiring, []
        self._reaper = self._runtime = None
        self._plan, self._digest = None, ""
        self._sessions.clear()
        if reaper is not None and reaper is not asyncio.current_task():
            reaper.cancel()
        for parked_generation, parked_runtime in parked:
            await _kill_quietly(parked_runtime)
            await _expire_shared_mints("mint_process_gone", generation=parked_generation)
        if runtime is not None:
            await _kill_quietly(runtime)
            await _expire_shared_mints("mint_process_gone", generation=generation)
        if runtime is not None or parked:
            await asyncio.to_thread(_remove_warm_mint_specs)


async def _destroy_session_quietly(handle: Any) -> None:
    """Terminate one warm session. Only ever called once nothing points at it."""
    try:
        await asyncio.wait_for(handle.destroy(), timeout=_WARM_SESSION_DESTROY_TIMEOUT_SECONDS)
    except Exception:  # noqa: BLE001 — best-effort teardown of our own session
        logger.debug("warm mint session destroy failed", exc_info=True)


async def _kill_quietly(runtime: Any) -> None:
    try:
        await asyncio.wait_for(runtime.kill(), timeout=_WARM_KILL_TIMEOUT_SECONDS)
    except Exception:  # noqa: BLE001 — best-effort teardown of our own child
        logger.debug("warm mint runtime kill failed", exc_info=True)


_warm_mint = _WarmMintRuntime()


def _warm_row_alive(entry: MintState) -> bool:
    """Whether a SHARED row's URL can still actually be redeemed.

    Two things must be alive and they die independently: the PKCE verifier in the PROCESS,
    and the loopback listener in the SESSION. Process liveness alone passed a
    terminated-session row, which is how a card kept serving an unredeemable URL -- which
    is also why the cold engine's ``_mint_holder_alive`` is deliberately NOT reused: it
    reads the row's own ``client``, which a shared row does not own.
    """
    if not _warm_mint.generation_is_live(int(entry.get("generation") or 0)):
        return False
    return _warm_mint.activation_is_live(int(entry.get("activation") or 0))


def _shared_mints_pending() -> bool:
    """True while any card still needs the shared process alive."""
    return any(
        entry.get("shared") and entry.get("state") in _LIVE_STATES for entry in _mints.values()
    )


async def _expire_shared_mints(
    reason: str, *, keep_started: float | None = None, generation: int | None = None
) -> list[str]:
    """Flip live shared mints stale. Called when a process is gone."""
    flipped: list[str] = []
    async with _mints_lock:
        for slug, entry in _mints.items():
            if not entry.get("shared") or entry.get("state") not in _LIVE_STATES:
                continue
            if generation is not None and entry.get("generation") != generation:
                continue
            if keep_started is not None and entry.get("started") == keep_started:
                continue
            entry["state"] = "expired"
            entry["reason"] = reason
            await _dispose_mint(entry)
            flipped.append(slug)
    if flipped:
        logger.info("Shared mint process gone; %d pending mint(s) flipped stale", len(flipped))
    return flipped


async def expire_dead_mints() -> list[str]:
    """Withdraw every shared row whose holding process is gone. THE chokepoint."""
    doomed: list[str] = []
    async with _mints_lock:
        for slug, entry in _mints.items():
            if not entry.get("shared") or entry.get("state") != "waiting":
                continue
            if _warm_row_alive(entry):
                continue
            entry["state"] = "expired"
            entry["reason"] = "mint_process_gone"
            await _dispose_mint(entry)
            doomed.append(slug)
    if doomed:
        logger.info("Withdrew %d approval URL(s) whose minting process is gone", len(doomed))
    return doomed


async def _warm_activate(*, slug: str = "", started: float | None = None) -> _WarmMintResult | None:
    """Activate the shared process, surviving one death of it."""
    for attempt in range(_WARM_ACTIVATION_ATTEMPTS):
        try:
            return await _warm_mint.mint_for(slug=slug)
        except _WarmMintDied as died:
            last = attempt + 1 >= _WARM_ACTIVATION_ATTEMPTS
            logger.warning(
                "Shared mint process died mid-activation (%s); %s",
                died.cause,
                "falling back to the cold path" if last else "respawning it",
            )
            await _expire_shared_mints("mint_process_gone", keep_started=started)
        except Exception as exc:  # noqa: BLE001 — the process lives; degrade to cold
            logger.warning(
                "Shared mint activation failed on a live process (%s); "
                "falling back to the cold path",
                type(exc).__name__,
            )
            return None
    return None


async def _warm_mint_reaper(generation: int) -> None:
    """Retire the shared process once no card is waiting on it."""
    idle_since = 0.0
    try:
        while True:
            await asyncio.sleep(_MINT_GRANT_POLL_SECONDS)
            await _warm_mint.sweep_retiring()
            # Every generation, parked ones included: a card pointing at a process that is
            # gone must not keep its URL until this reaper's own generation is the dead one.
            await expire_dead_mints()
            # Sessions outlive the rows that needed them on every path ending a mint without
            # a new activation (grant, cancel, TTL). Collected here, not for the process life.
            async with _mints_lock:
                in_use = _activations_in_use()
            await _warm_mint.sweep_sessions(in_use)
            if not _warm_mint.is_alive():
                await _expire_shared_mints("mint_process_gone", generation=generation)
                return
            if _shared_mints_pending():
                idle_since = 0.0
                continue
            now = time.monotonic()
            if idle_since == 0.0:
                idle_since = now
            elif now - idle_since >= _WARM_IDLE_GRACE_SECONDS:
                logger.info("Retiring the idle shared mint process")
                await _warm_mint.shutdown()
                return
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 — the reaper must never take the gateway down
        logger.debug("warm mint reaper failed", exc_info=True)


def _mint_is_cold_held(entry: MintState | None) -> bool:
    """True when a dedicated client -- not the shared process -- holds this URL."""
    return entry is not None and entry.get("state") == "waiting" and entry.get("client") is not None


async def _claim_shared_mints(slugs: list[str], started: float) -> list[str]:
    """Mark ``slugs`` as minting on the shared process; returns the ones claimed."""
    claimed: list[str] = []
    async with _mints_lock:
        for slug in slugs:
            prior = _mints.get(slug)
            if _mint_is_cold_held(prior):
                # A dedicated client owns this provider's verifier. Leave its URL on
                # the card rather than replace a working link.
                continue
            if prior is not None:
                # Dispose, don't just overwrite: the replaced row may own a watcher, and a
                # watcher outliving its row expires the NEW mint on the OLD mint's deadline.
                await _dispose_mint(prior)
            _mints[slug] = {
                "state": "minting",
                "started": started,
                "shared": True,
                "token": _new_mint_token(),
            }
            claimed.append(slug)
    return claimed


async def _release_shared_claims(slugs: list[str], started: float) -> None:
    """Drop unfulfilled claims so the card asks for a fresh mint."""
    async with _mints_lock:
        for slug in slugs:
            entry = _mints.get(slug)
            if entry is not None and entry.get("started") == started and entry.get("shared"):
                await _dispose_mint(entry)
                _mints.pop(slug, None)


async def _absorb_warm_requests(result: _WarmMintResult, started: float) -> list[str]:
    """Move popped challenges into the mint table. Returns the slugs now waiting."""
    urls = {
        str(request.get("serverName") or ""): str(request.get("oauthUrl") or "")
        for request in result.requests
    }
    minted: list[str] = []
    unfulfilled: list[str] = []
    loop = asyncio.get_running_loop()
    async with _mints_lock:
        for provider in result.providers:
            slug = provider["slug"]
            entry = _mints.get(slug)
            if entry is None or entry.get("started") != started or not entry.get("shared"):
                # Superseded while the activation ran. Its challenge stays alive in the session
                # that produced it and nothing points at it; the sweep collects that session.
                continue
            url = urls.get(mcp_server_alias(slug)) or urls.get(slug)
            if not url:
                unfulfilled.append(slug)
                continue
            entry.update(
                {
                    "state": "waiting",
                    "oauth_url": url,
                    "generation": result.generation,
                    "activation": result.activation,
                    "watcher": loop.create_task(
                        _mint_watcher(slug, provider["mcp_url"], str(entry.get("token") or ""))
                    ),
                }
            )
            minted.append(slug)
        in_use = _activations_in_use()
    # Settling is what lets the sweep run at all: until this activation is known to be
    # absorbed, collecting an unreferenced session could take out the Connect still filling it.
    await _warm_mint.settle_activation(result.activation, in_use)
    if unfulfilled:
        await _release_shared_claims(unfulfilled, started)
    return minted


async def warm_mint_all(providers: list[Provider] | None = None) -> list[str]:
    """Warm every mintable provider's approval URL in ONE activation.

    Returns the slugs now holding a URL. Never raises -- a failure leaves the cards
    exactly as they were, asking for a mint.

    The claim is taken BEFORE the process is ensured, because ensuring and activating are
    one locked step (see ``mint_for``) and nothing may run between them. ``providers``
    therefore only decides which rows are CLAIMED; what gets activated is the snapshot the
    lock holder computes, so a claim the activation did not cover is released rather than
    left minting forever.
    """
    candidates = (
        await asyncio.to_thread(mintable_providers) if providers is None else list(providers)
    )
    if not candidates:
        return []

    started = time.monotonic()
    claimed = await _claim_shared_mints([provider["slug"] for provider in candidates], started)
    if not claimed:
        return []
    result = await _warm_activate(started=started)
    if result is None:
        await _release_shared_claims(claimed, started)
        return []

    minted = await _absorb_warm_requests(result, started)
    activated = {provider["slug"] for provider in result.providers}
    stranded = [slug for slug in claimed if slug not in activated]
    if stranded:
        await _release_shared_claims(stranded, started)
    await asyncio.to_thread(
        _log_warm_event, "connections_warm_mint", f"activated:{len(claimed)} minted:{len(minted)}"
    )
    logger.info("Shared mint activation warmed %d of %d card(s)", len(minted), len(claimed))
    return minted
