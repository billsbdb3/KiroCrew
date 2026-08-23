"""Agent-profile enforcement for public-ACP-spec backends.

kiro-cli activates a named agent with ``session/set_mode``, so a spec whose
``tools`` list withholds the shell is actually enforced on the wire. A spec
adapter has no ``set_mode`` equivalent: the agent name is not sent, the adapter
runs with its OWN built-in tool set, and a shell-less agent would silently gain
full shell access.

That is a privilege escalation for exactly the agents that matter — restricted
app and subagent agents whose narrowed tool set IS their security boundary — so
the combination is refused rather than downgraded.

Kiro Crew's own agents are exempt. Their narrowed tool sets are Kiro Crew's own
scope choice rather than a boundary against Kiro Crew, and refusing them bricked
the background session on the reference implementation's first live deploy.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Tool names that grant shell execution. ``*`` grants everything, so it counts.
_SHELL_TOOLS = frozenset({"execute_bash", "shell", "*"})

# The default agent is Kiro Crew's own and is never restricted in this sense.
_DEFAULT_AGENT = "kirocrew"


class SpecAdapterAgentRefused(Exception):
    """The agent cannot be honoured on a backend with no ``set_mode``."""


def _grants_shell(spec: dict) -> bool:
    """Whether a resolved spec's ``tools`` list grants shell execution.

    A spec with NO ``tools`` key does not restrict tools at all, so it grants
    shell by omission — that is kiro-cli's own reading, and treating absence as a
    restriction would refuse most third-party agents for no reason.
    """
    tools = spec.get("tools")
    if tools is None:
        return True
    if not isinstance(tools, list):
        # Malformed: cannot establish that shell is withheld, so do not claim it.
        return True
    return any(isinstance(tool, str) and tool in _SHELL_TOOLS for tool in tools)


def _candidate_paths(agent: str, work_dir: Path | str) -> list[Path]:
    """Every spec file that could resolve ``agent``, project scope first.

    Mirrors kiro-cli's own resolution order: a project-scoped spec shadows a
    user-level one of the same name. Both are returned rather than just the
    winner, because the tie is broken fail-closed by the caller — if ANY
    same-named candidate withholds shell, the refusal stands.
    """
    from kiro_crew.config.paths import kiro_agents_dir, project_agents_dir

    paths: list[Path] = []
    try:
        project = project_agents_dir(work_dir) / f"{agent}.json"
        if project.is_file():
            paths.append(project)
    except (OSError, ValueError):
        pass
    try:
        user = kiro_agents_dir() / f"{agent}.json"
        if user.is_file():
            paths.append(user)
    except OSError:
        pass
    return paths


def shell_restriction(agent: str, work_dir: Path | str) -> str:
    """Describe why ``agent`` cannot run on a spec adapter, or ``""``.

    ``""`` means "no positive finding": the agent is Kiro Crew's own, has no spec
    on disk, or its spec grants shell. Only a spec that demonstrably withholds
    shell produces a refusal reason, so a host with no third-party agents is
    never blocked by this.

    A spec Kiro Crew's own reader refuses (over the size cap, a symlink resolving
    somewhere sensitive) yields "unverifiable" rather than "fine". Treating
    unreadable as permissive would let an attacker bypass the check by making the
    spec unreadable.
    """
    if not agent or agent == _DEFAULT_AGENT:
        return ""

    from kiro_crew.agent_discovery import _read_agent_spec
    from kiro_crew.agent_files import OWNED_KIRO_AGENT_FILES

    for path in _candidate_paths(agent, work_dir):
        if path.name in OWNED_KIRO_AGENT_FILES:
            continue
        spec = _read_agent_spec(path)
        if spec is None:
            return (
                f"its spec at {path} could not be read, so whether it withholds "
                "shell access cannot be established"
            )
        if not _grants_shell(spec):
            return f"its spec at {path} withholds shell access (tools=" f"{spec.get('tools')!r})"
    return ""


def assert_agent_permitted(agent: str, backend_label: str, work_dir: Path | str) -> None:
    """Refuse an agent whose restriction the backend cannot enforce."""
    restriction = shell_restriction(agent, work_dir)
    if not restriction:
        return
    raise SpecAdapterAgentRefused(
        f"Agent {agent!r} cannot be activated on the {backend_label} backend: "
        f"{restriction}, but this backend has no session/set_mode equivalent to "
        "enforce it — running the session here would silently grant full shell "
        "access. Clear agent.acp_backend to use the default kiro-cli backend for "
        "this agent, or run it as the default kirocrew agent."
    )


__all__ = [
    "SpecAdapterAgentRefused",
    "assert_agent_permitted",
    "shell_restriction",
]
