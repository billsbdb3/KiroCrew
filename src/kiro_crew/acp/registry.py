"""Upstream ACP Registry — discovery and distribution for ACP adapters.

The registry (``https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json``)
is the ecosystem's curated index of ACP adapters. It answers "which adapters exist,
what are they called, and how do I launch one". It deliberately does NOT answer
"can Kiro Crew govern this adapter's tool calls" — there is no permission,
approval or capability data in the schema — so this module owns exactly the half
the registry covers and nothing more. The trust half stays in
:mod:`kiro_crew.acp.backends`, keyed by the registry ``id``.

That split is the whole point of consuming the registry rather than hand-listing
adapters: the ecosystem is ~38 entries and growing, so a table of hand-written
rows goes stale by construction, while a routing verdict is a judgement Kiro Crew
must make itself and cannot inherit from anyone.

Schema (registry v1), one entry per adapter::

    id            "codex-acp"          registry identity; our descriptor key
    name          "Codex"              display name
    version       "1.4.0"              pinned release
    description   "ACP adapter for …"
    repository    "https://github.com/…"
    authors       ["OpenAI", …]
    license       "Apache-2.0"         "proprietary" for claude-acp
    distribution  {"npx": {"package": "@agentclientprotocol/codex-acp@1.4.0"}}
    icon          "https://cdn…/codex-acp.svg"

``distribution.npx.package`` carries an EXACT pinned version, which is the
ecosystem's canonical launch form. Kiro Crew adds the runner's offline flag so
session startup can use an operator-installed copy but can never download and
execute an adapter implicitly.

Fetching is OPT-IN and cached on disk. Nothing here runs on the default kiro-cli
path: an operator who never opens the adapter surface never pays a network call,
and a gateway with no outbound access degrades to the bundled snapshot rather
than failing a session.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

REGISTRY_URL = "https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json"

#: How long a cached copy is served before a refresh is attempted. The registry
#: changes on adapter releases, not minutes, and a stale entry is far cheaper
#: than a fetch on every settings render.
CACHE_TTL_SECS = 6 * 60 * 60

#: Ceiling on the downloaded document. The real one is ~49 KB; this bounds a
#: hostile or misconfigured endpoint rather than trusting Content-Length.
_MAX_BYTES = 2 * 1024 * 1024

_FETCH_TIMEOUT_SECS = 10

#: The CDN answers 403 to the default ``Python-urllib/3.x`` User-Agent, so this is
#: required rather than cosmetic — and identifying the client is the right thing
#: to do anyway, since it lets the registry maintainers see which clients fetch.
_USER_AGENT = "Kiro Crew (+https://github.com/kirodotdev/KiroCrew)"


@dataclass(frozen=True)
class RegistryAdapter:
    """One adapter as the upstream registry describes it.

    Carries no capability or routing data ON PURPOSE — see the module docstring.
    A caller that wants to know whether Kiro Crew can govern this adapter asks
    :mod:`kiro_crew.acp.backends`, not this record.
    """

    id: str
    name: str
    version: str
    description: str
    repository: str
    license: str
    icon: str
    #: ``npx`` | ``uvx`` | ``binary``. Measured across registry v1: 19 npx-only,
    #: 15 binary-only, 2 uvx-only, 2 offering both binary and npx.
    kind: str
    #: Pinned package for npx/uvx. Empty for a binary distribution.
    package: str
    #: Extra argv the registry says this adapter needs — several require one
    #: (``agoragentic-mcp`` needs ``--acp``), so dropping it launches the wrong
    #: mode and the handshake fails for a reason nothing explains.
    args: tuple[str, ...]
    #: Environment the registry pins for this adapter (``fast-agent`` sets a
    #: model). Applied on top of the spawn env, never replacing it.
    env: tuple[tuple[str, str], ...]

    @property
    def is_launchable(self) -> bool:
        """Can Kiro Crew start this adapter without installing software itself?

        True for npx/uvx, which can run a pinned, operator-installed package
        without network access. False for a binary distribution: that means
        downloading and extracting an archive from a release URL, and a gateway
        that fetches and executes arbitrary binaries is a far larger trust
        surface than one that shells out to a package runner. Those adapters are
        still LISTED — the operator installs them and Kiro Crew resolves them on
        PATH like any other.
        """
        return self.kind in ("npx", "uvx")

    @property
    def launch_argv(self) -> list[str]:
        """Canonical launch argv, or empty when Kiro Crew cannot launch it.

        Download-disabling flags are mandatory: selecting an adapter authorizes
        use of installed code, not installing code from the network. The pinned
        version is kept deliberately so the launch cannot float.
        """
        if self.kind == "npx":
            return ["npx", "--no-install", self.package, *self.args]
        if self.kind == "uvx":
            return ["uvx", "--offline", self.package, *self.args]
        return []

    @property
    def install_command(self) -> str:
        """A global install of the SAME pinned version, for npx/uvx adapters.

        Offered alongside the launch form because a global install resolves
        without touching the network at spawn time, which is what an operator
        running a long-lived gateway usually wants.
        """
        if self.kind == "npx":
            return f"npm install -g {self.package}"
        if self.kind == "uvx":
            return f"uv tool install {self.package}"
        return ""


def _dist_fields(dist: dict[str, Any]) -> tuple[str, str, tuple[str, ...], dict]:
    """Pick one distribution and normalise it.

    npx is preferred over binary when an adapter offers both (2 do), because a
    package runner is the cheaper and more auditable path.
    """
    for kind in ("npx", "uvx"):
        block = dist.get(kind)
        if isinstance(block, dict) and isinstance(block.get("package"), str):
            raw_args = block.get("args")
            args = tuple(str(a) for a in raw_args) if isinstance(raw_args, list) else ()
            raw_env = block.get("env")
            env = raw_env if isinstance(raw_env, dict) else {}
            return kind, block["package"], args, env
    if isinstance(dist.get("binary"), dict):
        return "binary", "", (), {}
    return "", "", (), {}


def _parse(document: Any) -> dict[str, RegistryAdapter]:
    """Convert a registry document into adapters, skipping anything malformed.

    Skipping rather than raising: one bad entry upstream must not remove every
    other adapter from the surface. An entry with no npx distribution is dropped
    because Kiro Crew has no other way to launch it, and listing an adapter it
    cannot start would be worse than omitting it.
    """
    out: dict[str, RegistryAdapter] = {}
    agents = document.get("agents") if isinstance(document, dict) else None
    if not isinstance(agents, list):
        logger.debug("ACP registry document has no agents list")
        return out

    for entry in agents:
        if not isinstance(entry, dict):
            continue
        ident = entry.get("id")
        if not isinstance(ident, str) or not ident:
            continue
        dist = entry.get("distribution")
        kind, package, args, env = _dist_fields(dist if isinstance(dist, dict) else {})
        if not kind:
            # No distribution Kiro Crew recognises. Keep it out rather than
            # listing an adapter with no way to obtain it at all.
            continue
        out[ident] = RegistryAdapter(
            id=ident,
            name=str(entry.get("name") or ident),
            version=str(entry.get("version") or ""),
            description=str(entry.get("description") or ""),
            repository=str(entry.get("repository") or ""),
            license=str(entry.get("license") or ""),
            icon=str(entry.get("icon") or ""),
            kind=kind,
            package=package,
            args=args,
            env=tuple((str(k), str(v)) for k, v in env.items()),
        )
    return out


def _cache_path() -> Path:
    from kiro_crew.config.paths import config_dir

    return config_dir() / "acp-registry.json"


def _read_cache(max_age_secs: int) -> dict[str, RegistryAdapter] | None:
    path = _cache_path()
    try:
        stat = path.stat()
    except OSError:
        return None
    if max_age_secs >= 0 and (time.time() - stat.st_mtime) > max_age_secs:
        return None
    try:
        return _parse(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        logger.debug("Unreadable ACP registry cache at %s", path, exc_info=True)
        return None


def fetch(force: bool = False) -> dict[str, RegistryAdapter]:
    """Adapters from the registry, cache-first.

    Never raises. A network failure, a timeout, an oversized body or unparseable
    JSON all fall back to whatever cache exists, and to an empty mapping if there
    is none. The adapter surface degrades to "we could not reach the registry",
    which is a legible state; a raised exception here would take out a settings
    page over a transient DNS failure.
    """
    if not force:
        cached = _read_cache(CACHE_TTL_SECS)
        if cached is not None:
            return cached

    try:
        request = urllib.request.Request(  # noqa: S310 - fixed https CDN URL
            REGISTRY_URL,
            headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
        )
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT_SECS) as response:  # noqa: S310
            raw = response.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            logger.warning("ACP registry document exceeded %d bytes", _MAX_BYTES)
            return _read_cache(-1) or {}
        document = json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, UnicodeDecodeError):
        logger.debug("Could not fetch the ACP registry", exc_info=True)
        # Serve a stale cache rather than nothing: an adapter list from this
        # morning is far more useful than an empty surface.
        return _read_cache(-1) or {}

    adapters = _parse(document)
    if adapters:
        try:
            path = _cache_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        except OSError:
            logger.debug("Could not cache the ACP registry", exc_info=True)
    return adapters


def lookup(registry_id: str) -> RegistryAdapter | None:
    """One adapter by registry id, cache-first and never raising."""
    return fetch().get(registry_id)


def cached() -> dict[str, RegistryAdapter]:
    """Adapters already cached on disk, without performing network I/O."""
    return _read_cache(-1) or {}


__all__ = [
    "CACHE_TTL_SECS",
    "REGISTRY_URL",
    "RegistryAdapter",
    "cached",
    "fetch",
    "lookup",
]
