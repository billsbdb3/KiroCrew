"""An ACP backend's credential store must be unreadable to the agent.

Each experimental backend authenticates through its own vendor CLI, which
persists a live OAuth token under the user's home. The agent must not be able to
read the credential that authorises its own backend.

The parity test here is what keeps ``security._SENSITIVE_HOME_DIRS`` honest:
``security`` cannot import the backend registry (that is an import cycle), so the
list is written literally and this test is the contract that stops the two
drifting. Adding a backend with a credential path and forgetting the security
entry fails here rather than shipping an exposed token.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kiro_crew import security
from kiro_crew.acp.backends import credential_leaves


def test_acp_backend_credentials_are_protected() -> None:
    """Every registered backend's credential leaf is on the sensitive list."""
    missing = [leaf for leaf in credential_leaves() if leaf not in security._SENSITIVE_HOME_DIRS]
    assert not missing, (
        f"ACP backend credential paths absent from _SENSITIVE_HOME_DIRS: {missing}. "
        "security.py cannot import the registry (import cycle), so add the leaf "
        "literally next to the other backend entries."
    )


def test_at_least_one_backend_declares_a_credential_path() -> None:
    """Guards the parity test above against passing vacuously.

    If every descriptor stopped declaring credential paths, the loop would have
    nothing to check and would pass with the protection removed.
    """
    assert credential_leaves()


class TestCodexAuthJson:
    """The Codex token store, through both enforcement paths."""

    @property
    def auth(self) -> str:
        return str(Path.home() / ".codex" / "auth.json")

    @property
    def config(self) -> str:
        return str(Path.home() / ".codex" / "config.toml")

    def test_fs_gate_blocks_the_token_store(self) -> None:
        assert security.is_sensitive_path(self.auth)

    def test_fs_gate_still_allows_the_ordinary_config(self) -> None:
        """config.toml must stay readable.

        The tool-gate refusal message tells the operator to inspect
        approval_policy in this file, so blocking it would make the remedy
        impossible to follow.
        """
        assert not security.is_sensitive_path(self.config)

    @pytest.mark.parametrize(
        "command",
        [
            "cat ~/.codex/auth.json",
            "head -c 100 ~/.codex/auth.json",
            "base64 ~/.codex/auth.json",
            "cp ~/.codex/auth.json /tmp/stolen",
            "python3 -c \"print(open('~/.codex/auth.json').read())\"",
        ],
    )
    def test_bash_matcher_blocks_reads_by_any_verb(self, command: str) -> None:
        """The catch-all is verb-independent on purpose.

        A per-verb denied-command rule would need an entry per reader; naming the
        path blocks the readers nobody enumerated too.
        """
        assert security.is_sensitive_bash_command(command)

    def test_relative_traversal_is_covered_for_leaf_entries(self) -> None:
        """A leaf credential file is protected however its path is respelled.

        A ``cd`` into the directory, a ``;`` separator, and a ``$HOME`` variable
        all resolve to the same file, so each form is blocked. This is general to
        every FILE-shaped entry in _SENSITIVE_HOME_DIRS rather than specific to
        this backend — ``~/.docker/config.json`` and ``~/.kube/config`` are
        covered on the same tree, as are DIRECTORY entries (``.ssh``, ``.aws``).
        """
        assert security.is_sensitive_bash_command("cd ~/.codex && cat auth.json")
        assert security.is_sensitive_bash_command("cd ~/.codex; cat auth.json")
        assert security.is_sensitive_bash_command("cd $HOME/.codex && cat auth.json")

    def test_a_directory_entry_does_block_relative_traversal(self) -> None:
        """Pins that directory entries are covered alike, not just leaf files."""
        assert security.is_sensitive_bash_command("cd ~/.ssh && cat id_rsa")

    def test_bash_matcher_allows_reading_the_config(self) -> None:
        assert not security.is_sensitive_bash_command("cat ~/.codex/config.toml")
