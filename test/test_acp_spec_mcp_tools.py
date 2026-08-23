"""Crew MCP tools on a spec-adapter session: delivery, identity, and directives.

kiro-cli advertises ``kirocrew-core`` through its agent spec and tags every
MCP tool call with ``_meta.kiro``. A spec adapter gets the same server only
on ``session/new``, and it names the call ``mcp__<server>__<tool>`` in
``title`` with no ``_meta``. Follow-up cards and workflow POSTs both depend
on those two facts being true at once — delivery without identity drops
``ask_question`` / ``suggest_followup`` silently, and identity without a
gateway pin makes ``workflow_run`` miss the loopback.
"""

from __future__ import annotations

import pytest

from kiro_crew.acp import spec_servers
from kiro_crew.acp._dispatch import parse_session_update
from kiro_crew.acp.types import (
    ACP_BACKEND_CLAUDE,
    ACP_BACKEND_CODEX,
    ACP_BACKEND_GOOSE,
    ACP_BACKEND_KAS,
    ACP_BACKEND_KIRO,
    ACP_BACKEND_OPENCODE,
    ACP_BACKEND_PI,
    EVENT_TOOL_CALL,
)
from kiro_crew.mcp_tools import build_tool_list
from kiro_crew.session_directive import decode, match_tool


def _client(backend: str, work_dir):
    from kiro_crew.acp.client import AcpClient

    return AcpClient(work_dir=str(work_dir), acp_backend=backend)


def _tool_call_update(*, title: str, kind: str, meta: dict | None = None) -> dict:
    update: dict = {
        "sessionUpdate": "tool_call",
        "toolCallId": "tc-1",
        "title": title,
        "kind": kind,
        "rawInput": {"questions": []},
    }
    if meta is not None:
        update["_meta"] = meta
    return update


class TestRoutedAdaptersReceiveCoreTools:
    def test_codex_session_config_is_routed_so_core_is_delivered(self, tmp_path) -> None:
        """SESSION_CONFIG Layer 1 is a handshake contract, not a file probe."""
        names = {
            e["name"] for e in _client(ACP_BACKEND_CODEX, tmp_path)._spec_session_mcp_servers()
        }
        assert "kirocrew-core" in names
        assert "kirocrew-cron" in names

    def test_claude_seeded_settings_deliver_core(self, tmp_path) -> None:
        from kiro_crew.acp import tool_gate

        tool_gate.enforce(ACP_BACKEND_CLAUDE, tmp_path, allow_ungated=False)
        names = {
            e["name"] for e in _client(ACP_BACKEND_CLAUDE, tmp_path)._spec_session_mcp_servers()
        }
        assert "kirocrew-core" in names

    def test_goose_is_routed_and_receives_crew_servers(self, tmp_path) -> None:
        """PERMISSION_REQUEST is ROUTED, so Crew's control plane is delivered."""
        names = {
            e["name"] for e in _client(ACP_BACKEND_GOOSE, tmp_path)._spec_session_mcp_servers()
        }
        assert "kirocrew-core" in names
        assert "kirocrew-cron" in names

    def test_opencode_is_routed_and_receives_crew_servers(self, tmp_path) -> None:
        from kiro_crew.acp import tool_gate

        tool_gate.enforce(ACP_BACKEND_OPENCODE, tmp_path, allow_ungated=False)
        names = {
            e["name"] for e in _client(ACP_BACKEND_OPENCODE, tmp_path)._spec_session_mcp_servers()
        }
        assert "kirocrew-core" in names
        assert "kirocrew-cron" in names

    def test_pi_is_routed_and_receives_crew_servers(self, tmp_path) -> None:
        """We still deliver when ROUTED. The adapter may leave them inert."""
        names = {e["name"] for e in _client(ACP_BACKEND_PI, tmp_path)._spec_session_mcp_servers()}
        assert "kirocrew-core" in names
        assert "kirocrew-cron" in names

    def test_kiro_does_not_pay_this_seam(self, tmp_path) -> None:
        assert _client(ACP_BACKEND_KIRO, tmp_path)._spec_session_mcp_servers() == []

    def test_kas_does_not_pay_this_seam(self, tmp_path) -> None:
        """KAS speaks the kiro dialect and is served by AcpRuntime.

        This client seam is for spec adapters. Empty here is correct, not a
        hole in the adapter path — KAS session MCP is a runtime concern.
        """
        assert _client(ACP_BACKEND_KAS, tmp_path)._spec_session_mcp_servers() == []


class TestCoreAdvertisesWorkflowsAndFollowups:
    def test_tools_list_includes_the_prompt_facing_control_plane(self) -> None:
        names = {tool["name"] for tool in build_tool_list()}
        assert {
            "workflow_run",
            "workflow_status",
            "workflow_list",
            "ask_question",
            "suggest_followup",
        } <= names


class TestSpecAdapterToolIdentity:
    """Without this, chat_runner never registers a directive tool.

    It keys on ``event.mcp_server_name == kirocrew-core`` and
    ``match_tool(event.tool_name)``. Both were empty for every spec-adapter
    MCP call because identity lived only on ``_meta.kiro``.
    """

    def test_mcp_title_without_meta_is_core_ask_question(self) -> None:
        events = parse_session_update(
            _tool_call_update(title="mcp__kirocrew-core__ask_question", kind="other")
        )
        assert events[0].kind == EVENT_TOOL_CALL
        assert events[0].mcp_server_name == "kirocrew-core"
        assert events[0].tool_name == "ask_question"
        assert match_tool(events[0].tool_name) == "ask_question"

    def test_mcp_title_without_meta_is_core_suggest_followup(self) -> None:
        events = parse_session_update(
            _tool_call_update(title="mcp__kirocrew-core__suggest_followup", kind="other")
        )
        assert events[0].mcp_server_name == "kirocrew-core"
        assert match_tool(events[0].tool_name) == "suggest_followup"

    def test_mcp_title_without_meta_is_core_workflow_run(self) -> None:
        events = parse_session_update(
            _tool_call_update(title="mcp__kirocrew-core__workflow_run", kind="other")
        )
        assert events[0].mcp_server_name == "kirocrew-core"
        assert events[0].tool_name == "workflow_run"

    def test_a_forged_mcp_title_on_a_shell_kind_is_not_an_identity(self) -> None:
        events = parse_session_update(
            _tool_call_update(title="mcp__kirocrew-core__ask_question", kind="execute")
        )
        assert events[0].mcp_server_name == ""
        assert events[0].tool_name == ""
        assert match_tool(events[0].tool_name) == ""

    def test_a_title_without_the_mcp_prefix_is_not_an_identity(self) -> None:
        """kiro-cli titles are LLM prose. They must stay unparsed."""
        events = parse_session_update(
            _tool_call_update(title="Asking the user which approach", kind="other")
        )
        assert events[0].mcp_server_name == ""
        assert events[0].tool_name == ""

    def test_meta_kiro_wins_over_a_conflicting_title(self) -> None:
        events = parse_session_update(
            _tool_call_update(
                title="mcp__evil__ask_question",
                kind="other",
                meta={"kiro": {"toolName": "ask_question", "mcpServerName": "kirocrew-core"}},
            )
        )
        assert events[0].mcp_server_name == "kirocrew-core"
        assert events[0].tool_name == "ask_question"

    def test_missing_kind_does_not_parse_a_title(self) -> None:
        """Fail closed: no kind means we cannot tell a shell from an MCP call."""
        update = _tool_call_update(title="mcp__kirocrew-core__ask_question", kind="other")
        del update["kind"]
        events = parse_session_update(update)
        assert events[0].mcp_server_name == ""
        assert events[0].tool_name == ""


class TestSessionCallbackEnv:
    def test_pin_writes_session_and_port_onto_every_entry(self) -> None:
        entries = spec_servers.pin_session_callback_env(
            [{"name": "kirocrew-core", "command": "c", "args": [], "env": []}],
            session_key="dashboard:slot-1",
            channel_id="",
            bound_port="18789",
        )
        env = {pair["name"]: pair["value"] for pair in entries[0]["env"]}
        assert env["KIROCREW_SESSION_KEY"] == "dashboard:slot-1"
        assert env["KIROCREW_PORT"] == "18789"
        assert env["KIROCREW_BOUND_PORT"] == "18789"
        assert "KIROCREW_CHANNEL_ID" not in env

    def test_pin_overwrites_a_stale_port_and_keeps_other_keys(self) -> None:
        entries = spec_servers.pin_session_callback_env(
            [
                {
                    "name": "kirocrew-core",
                    "command": "c",
                    "args": [],
                    "env": [
                        {"name": "KIROCREW_HOME", "value": "/tmp/crew"},
                        {"name": "KIROCREW_PORT", "value": "1"},
                    ],
                }
            ],
            session_key="dashboard:s",
            bound_port="9",
        )
        env = {pair["name"]: pair["value"] for pair in entries[0]["env"]}
        assert env["KIROCREW_HOME"] == "/tmp/crew"
        assert env["KIROCREW_PORT"] == "9"

    @pytest.mark.asyncio
    async def test_codex_session_new_array_carries_the_pin(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KIROCREW_BOUND_PORT", "18789")
        client = _client(ACP_BACKEND_CODEX, tmp_path)
        client._session_key = "dashboard:slot-9"
        servers = await client._session_mcp_servers()
        core = next(entry for entry in servers if entry["name"] == "kirocrew-core")
        env = {pair["name"]: pair["value"] for pair in core["env"]}
        assert env["KIROCREW_SESSION_KEY"] == "dashboard:slot-9"
        assert env["KIROCREW_BOUND_PORT"] == "18789"
        assert env["KIROCREW_PORT"] == "18789"

    @pytest.mark.asyncio
    async def test_kiro_session_array_is_not_rewritten(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The kiro path must stay byte-identical: servers arrive via --agent."""
        monkeypatch.setenv("KIROCREW_BOUND_PORT", "18789")
        client = _client(ACP_BACKEND_KIRO, tmp_path)
        client._session_key = "dashboard:slot-9"
        pooled = [{"name": "stub", "command": "c", "args": [], "env": []}]
        from unittest.mock import patch

        with patch.object(client, "_pooled_mcp_servers", return_value=pooled):
            assert await client._session_mcp_servers() == pooled


class TestDirectiveRoundTrip:
    def test_ask_question_directive_still_decodes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import kiro_crew.mcp_core as mcp_core
        from kiro_crew.mcp_core import _call_tool_inner

        monkeypatch.setattr(mcp_core, "_resolve_session_key_strict", lambda: "")
        result = _call_tool_inner(
            "ask_question",
            {
                "questions": [
                    {
                        "question": "Which approach?",
                        "options": [{"label": "A"}, {"label": "B"}],
                    }
                ]
            },
        )
        args = decode(result, "ask_question")
        assert args is not None
        assert args["questions"][0]["question"] == "Which approach?"

    def test_suggest_followup_directive_still_decodes(self) -> None:
        from kiro_crew.mcp_core import _call_tool_inner

        result = _call_tool_inner(
            "suggest_followup",
            {
                "items": [
                    {
                        "title": "Run the workflow",
                        "description": "Author and start the next slice.",
                        "prompt": "Run a workflow that lists recent runs.",
                    }
                ]
            },
        )
        args = decode(result, "suggest_followup")
        assert args is not None
        assert args["items"][0]["title"] == "Run the workflow"
