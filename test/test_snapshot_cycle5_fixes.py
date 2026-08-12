"""Tests for the cycle-5 review findings.

Two of these close holes in the design's central claim rather than in its details: the
recorded destination was made unwritable, but the COMMAND that writes it was not gated,
and exposure was verified at setup but never re-checked at the moment of writing.
"""

from __future__ import annotations

import argparse
import json
import re
import tarfile

import pytest

from kiro_crew import backup_cli
from kiro_crew import snapshot as snap
from kiro_crew import snapshot_remote as remote
from kiro_crew.deploy import engine
from kiro_crew.security import is_sensitive_path

ACCOUNT = "123456789012"


class TestSetupNeedsAnAuthorizationTheCallerCannotForge:
    """Protecting the record while leaving the writer ungated protects nothing, and a
    terminal check does not gate the writer.

    `destination.json` is behind the sensitive-path floor, so an agent cannot author it.
    But `backup setup` writes it through this program's own code, so the command itself
    needs a gate. An earlier revision used `sys.stdin.isatty()` and called that a
    human-presence check; it is not, because a pty is something any process can
    allocate. The gate is now a file in a keystone directory that NAMES the destination it
    authorizes: the operator can create it, nothing the agent can drive can, and a
    token approved for one account cannot be spent on another.
    """

    def _args(self, **kw) -> argparse.Namespace:
        base = dict(aws_profile="default", region="us-west-2", bucket=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def _prepared(self, home, monkeypatch):
        monkeypatch.setenv("KIROCREW_HOME", str(home))
        monkeypatch.setattr(backup_cli, "_resolve_aws_profile", lambda _n: ("p", "us-west-2"))
        monkeypatch.setattr(remote, "caller_account", lambda _p: ACCOUNT)
        calls: list[str] = []

        def fake_setup(profile, region, bucket=None):
            calls.append("ran")
            # Stubs the AWS work, NOT the authorization. The gate lives inside the real
            # `setup_destination`, so a double that skipped it would let this suite pass
            # while the property under test (single use) was broken in production.
            remote.consume_authorization(
                ACCOUNT, region, bucket or remote.default_bucket_name(ACCOUNT, region)
            )
            dest = remote.Destination(
                bucket="my-backups",
                region="us-west-2",
                account=ACCOUNT,
                created_at="now",
            )
            report = {
                "block_public_access": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "sse": "AES256",
                "versioning": "Enabled",
            }
            return dest, True, report

        monkeypatch.setattr(remote, "setup_destination", fake_setup)
        return calls

    def test_without_the_authorization_setup_refuses(self, tmp_path, monkeypatch, capsys):
        calls = self._prepared(tmp_path, monkeypatch)
        rc = backup_cli.setup_main(self._args())
        out = capsys.readouterr().out
        assert rc == 1
        assert calls == [], "setup ran unauthorized"
        assert "authorized out of band" in out
        assert "setup-authorized" in out, "the refusal must name the file to create"

    def test_a_pseudo_terminal_alone_is_not_enough(self, tmp_path, monkeypatch, capsys):
        """The exact bypass this replaced: `script -qec ... /dev/null` (or pty.fork)
        makes isatty() true and can answer the prompt, so a terminal cannot be the
        thing that authorizes a redirection."""
        calls = self._prepared(tmp_path, monkeypatch)
        monkeypatch.setattr(backup_cli.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda _p="": "yes")
        rc = backup_cli.setup_main(self._args())
        assert rc == 1, "a pty plus a scripted 'yes' must not authorize setup"
        assert calls == []
        assert "authorized out of band" in capsys.readouterr().out

    def test_with_the_authorization_setup_proceeds(self, tmp_path, monkeypatch):
        calls = self._prepared(tmp_path, monkeypatch)
        token = remote.authorization_token_path()
        token.parent.mkdir(parents=True, exist_ok=True)
        token.write_text(json.dumps({"account": ACCOUNT, "region": "us-west-2"}))
        rc = backup_cli.setup_main(self._args())
        assert rc == 0
        assert calls == ["ran"]

    def test_the_authorization_is_single_use(self, tmp_path, monkeypatch):
        """One authorization must not be replayable into a later redirection."""
        calls = self._prepared(tmp_path, monkeypatch)
        token = remote.authorization_token_path()
        token.parent.mkdir(parents=True, exist_ok=True)
        token.write_text(json.dumps({"account": ACCOUNT, "region": "us-west-2"}))
        assert backup_cli.setup_main(self._args()) == 0
        assert not token.exists(), "the authorization survived its use"
        assert backup_cli.setup_main(self._args()) == 1
        assert calls == ["ran"], "a second setup ran on a consumed authorization"

    def test_the_authorization_lives_where_the_agent_cannot_write(self, tmp_path, monkeypatch):
        """The mechanism IS the path. If the token were writable by the agent's tools,
        it would authorize nothing."""
        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path))
        token = remote.authorization_token_path()
        assert is_sensitive_path(
            str(token)
        ), "the authorization file must be behind the sensitive-path floor"
        assert is_sensitive_path(str(token.parent))

    def test_a_declined_confirmation_records_nothing(self, tmp_path, monkeypatch, capsys):
        calls = self._prepared(tmp_path, monkeypatch)
        token = remote.authorization_token_path()
        token.parent.mkdir(parents=True, exist_ok=True)
        token.write_text(json.dumps({"account": ACCOUNT, "region": "us-west-2"}))
        monkeypatch.setattr(backup_cli.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda _p="": "no")
        rc = backup_cli.setup_main(self._args())
        assert rc == 1
        assert calls == []
        assert "Cancelled" in capsys.readouterr().out

    def test_the_confirmation_names_the_account_the_memory_would_go_to(
        self, tmp_path, monkeypatch, capsys
    ):
        """ "Wrong profile" is the mistake most worth catching, and an account number is
        what makes it visible."""
        self._prepared(tmp_path, monkeypatch)
        token = remote.authorization_token_path()
        token.parent.mkdir(parents=True, exist_ok=True)
        token.write_text(json.dumps({"account": ACCOUNT, "region": "us-west-2"}))
        monkeypatch.setattr(backup_cli.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda _p="": "no")
        backup_cli.setup_main(self._args())
        out = capsys.readouterr().out
        assert ACCOUNT in out
        assert "us-west-2" in out

    def test_there_is_no_flag_that_skips_the_gate(self):
        """A --yes/--force flag is exactly what an automated caller would pass.

        Scoped to the `backup setup` parser block and matched on argument DEFINITIONS:
        `cli.py` legitimately carries `--force` (restore) and `-y` (cloud launch), and
        the source here explains why no bypass exists, so a plain substring search over
        either would fail for the wrong reason.
        """
        import inspect

        from kiro_crew import cli

        pattern = re.compile(
            r"""add_argument\(\s*["'](--yes|-y|--force|--non-interactive|--batch)["']"""
        )
        cli_src = inspect.getsource(cli)
        blk = cli_src[
            cli_src.index("b_setup = backup_sub.add_parser(") : cli_src.index(
                "b_status = backup_sub.add_parser("
            )
        ]
        for name, src in (
            ("the backup setup parser", blk),
            ("backup_cli", inspect.getsource(backup_cli)),
        ):
            hits = pattern.findall(src)
            assert hits == [], f"a gate bypass is defined in {name}: {hits}"

    def test_the_refusal_is_reached_before_any_aws_write(self, tmp_path, monkeypatch):
        """The gate has to sit ahead of provisioning, not inside it."""
        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path))
        monkeypatch.setattr(backup_cli, "_resolve_aws_profile", lambda _n: ("p", "us-west-2"))
        monkeypatch.setattr(remote, "caller_account", lambda _p: ACCOUNT)
        calls: list[list[str]] = []

        def record(args, profile, timeout=30):
            calls.append(list(args))
            return 0, "{}", ""

        monkeypatch.setattr(engine, "run_aws", record)
        rc = backup_cli.setup_main(self._args())
        assert rc == 1
        mutating = [
            c for c in calls if any(v.startswith("put-") or v == "create-bucket" for v in c)
        ]
        assert mutating == [], f"AWS was mutated before the gate: {mutating}"


class TestAContainedLinkRootDoesNotHalfRestore:
    """A live tree root can pass containment and still be a LINK.

    A symlink pointing somewhere else *inside* the data home resolves within it, so the
    containment predicate allows it -- and `shutil.rmtree` then refuses a symlink with
    OSError. In the current design a link root reached by REPLACE/MERGE is refused up
    front by `_refuse_unsafe_destination_roots` (pinned in cycle9), so the one place that
    still clears a possibly-linked live root is rollback recovery
    (`_restore_everything_from_rollback`): it removes the live target before refilling it
    from the saved copy. If that clearing followed the link -- or rmtree'd it and raised --
    the recovery would strand itself (worst outcome) and delete data outside the home.
    The old standalone `_clear_tree_root` helper is gone; its link-as-link property lives
    here, so these tests drive recovery directly.
    """

    def test_recovery_removes_a_linked_live_root_as_a_link(self, tmp_path):
        """The saved copy is put back, and the link target OUTSIDE the home is untouched."""
        backup = tmp_path / "rollback"
        (backup / "skills").mkdir(parents=True)
        (backup / "skills" / "saved.md").write_text("saved")
        home = tmp_path / "home"
        home.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "keep.md").write_text("must survive")
        link = home / "skills"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("cannot create a directory symlink on this platform")

        failed = snap._restore_everything_from_rollback(backup, home, ["skills"], {"skills"})

        assert failed == [], f"recovery could not clear the linked root: {failed}"
        assert not link.is_symlink(), "the link survived instead of being removed as a link"
        assert (outside / "keep.md").is_file(), "clearing the link deleted the target"
        assert (home / "skills" / "saved.md").read_text() == "saved", "saved copy not put back"

    def test_recovery_still_removes_a_real_directory_root(self, tmp_path):
        """A real live directory is cleared before the saved copy replaces it."""
        backup = tmp_path / "rollback"
        (backup / "skills").mkdir(parents=True)
        (backup / "skills" / "saved.md").write_text("saved")
        home = tmp_path / "home"
        (home / "skills" / "sub").mkdir(parents=True)
        (home / "skills" / "sub" / "stale.md").write_text("stale")

        failed = snap._restore_everything_from_rollback(backup, home, ["skills"], {"skills"})

        assert failed == [], failed
        assert not (home / "skills" / "sub" / "stale.md").exists(), "the stale live tree survived"
        assert (home / "skills" / "saved.md").read_text() == "saved"

    def test_recovery_does_not_raise_when_the_live_root_is_missing(self, tmp_path):
        """No pre-existing live tree, but a saved copy -- recovery creates it, no crash."""
        backup = tmp_path / "rollback"
        (backup / "skills").mkdir(parents=True)
        (backup / "skills" / "saved.md").write_text("saved")
        home = tmp_path / "home"
        home.mkdir()  # no `skills` under it

        failed = snap._restore_everything_from_rollback(backup, home, ["skills"], {"skills"})

        assert failed == [], failed
        assert (home / "skills" / "saved.md").read_text() == "saved"

    def test_recovery_clears_a_linked_root_as_a_link_before_rmtree(self):
        """Structural: the naive `if target.is_dir(): shutil.rmtree(target)` is wrong for a
        link, because `is_dir()` follows it and rmtree then raises on the symlink. Every site
        in recovery that clears a possibly-linked live target must therefore remove a link AS
        a link before it can reach an rmtree.

        Checked PER SITE rather than by first-occurrence order. Recovery has more than one
        clearing site now (a saved link is reinstated ahead of the dereferencing branches),
        and an ordering assertion over the whole function cannot express "each one is
        guarded" -- worse, it was blind in the direction that matters: a SECOND, unguarded
        rmtree added later still satisfied it, because only the FIRST occurrence of each
        string was ever looked at.
        """
        import inspect

        recovery = inspect.getsource(snap._restore_everything_from_rollback)
        raw = recovery.splitlines()
        sites = [i for i, ln in enumerate(raw) if ln.strip() == "shutil.rmtree(str(target))"]
        assert sites, "recovery no longer clears a live directory target at all"

        def _indent(line: str) -> int:
            return len(line) - len(line.lstrip())

        for i in sites:
            gate = raw[i - 1]
            assert "target.is_dir()" in gate, (
                f"an rmtree of the live target at line {i} is not gated on the target being "
                f"a directory at all -- found {gate.strip()!r}"
            )
            if "is_link_or_junction(target)" in gate:
                continue  # self-guarded: `is_dir() and not is_link_or_junction(...)`
            # Otherwise this must be an `elif` whose CHAIN HEAD excludes a link. The head is
            # the nearest preceding line at the SAME indentation opening with `if` -- found
            # by indentation rather than by a fixed line window, because a window lets an
            # unrelated link check a few lines up vouch for an unguarded site, which is how
            # this assertion first passed against a deliberately broken version.
            assert gate.strip().startswith("elif "), (
                f"the rmtree at line {i} is gated by {gate.strip()!r}, which neither excludes "
                "a link itself nor continues a chain that does"
            )
            depth = _indent(gate)
            head = None
            for j in range(i - 2, -1, -1):
                if not raw[j].strip():
                    continue
                if _indent(raw[j]) < depth:
                    break  # left the block without finding the chain head
                if _indent(raw[j]) == depth and raw[j].strip().startswith("if "):
                    head = raw[j]
                    break
            assert head is not None and "is_link_or_junction(target)" in head, (
                f"the rmtree at line {i} can be reached for a LINK: its chain head is "
                f"{(head.strip() if head else None)!r}, which does not test for one, so "
                "rmtree would raise on the symlink and strand the whole recovery"
            )


class TestTheMergeCannotWriteOutsideTheDataHome:
    def test_a_nested_destination_link_is_not_followed(self, tmp_path):
        """safe_tree_root validates the destination ROOT, but the merge walks below it
        and the write target is the dangerous end: a nested link under the destination
        would deposit restored files wherever it aimed."""
        home = tmp_path / "home"
        (home / "workspace" / "memory").mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        dest = home / "workspace" / "memory"
        try:
            (dest / "history").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("cannot create a directory symlink on this platform")

        src = tmp_path / "snap" / "workspace" / "memory"
        (src / "history").mkdir(parents=True)
        (src / "history" / "leak.md").write_text("must not escape")
        (src / "keep.md").write_text("fine")

        snap._copy_tree_no_overwrite(src, dest)

        assert (dest / "keep.md").is_file(), "the legitimate file should still merge"
        assert not (outside / "leak.md").exists(), "the merge wrote outside the data home"

    def test_a_fresh_temporary_tree_still_merges(self, tmp_path):
        """No planted link, so nothing to refuse: the ordinary merge path still copies.

        (Was `test_without_a_home_the_check_is_skipped`: the old `home` parameter is gone
        -- containment is now enforced unconditionally inside the descriptor-pinned
        primitive rather than gated on a home argument -- so this only pins that a clean
        merge keeps working.)
        """
        src = tmp_path / "s"
        src.mkdir()
        (src / "f.md").write_text("x")
        dst = tmp_path / "d"
        dst.mkdir()
        snap._copy_tree_no_overwrite(src, dst)
        assert (dst / "f.md").is_file()


class TestAMalformedRemoteBundleIsRefusedNotCrashed:
    def test_a_corrupt_download_is_removed_and_reported(self, tmp_path, monkeypatch, capsys):
        """A downloaded object is untrusted input even from a bucket we own: versioning
        means an older object may be corrupt, and a truncated transfer only fails when
        opened. tarfile raising out of the extract path is indistinguishable from a
        crash and leaves the bad file behind."""
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("KIROCREW_HOME", str(home))
        snaps = tmp_path / "snapshots"
        snaps.mkdir()
        bad = snaps / "kirocrew-snapshot-20260811T000000Z.tar.gz"
        bad.write_bytes(b"this is not a tarball")

        monkeypatch.setattr(snap, "_default_snapshot_dir", lambda: str(snaps))
        monkeypatch.setattr(snap, "_resolve_aws_profile", lambda _n: ("p", "us-west-2"))
        monkeypatch.setattr(remote, "download", lambda *_a, **_k: bad)

        rc = snap.restore_main(["s3://my-backups/backups/h/snap.tar.gz", "--force"])
        out = capsys.readouterr().out
        assert rc == 1
        assert "not a readable snapshot archive" in out
        assert not bad.exists(), "the invalid download was retained"


class TestConcurrentDownloadsCannotOverwriteEachOther:
    def test_a_name_is_claimed_atomically(self, tmp_path):
        """A plain exists() test then a move is a race: both processes see the name free,
        both move, and the loser's bundle is silently replaced by the winner's."""
        first = remote._claim_free_name(tmp_path, "snap.tar.gz")
        second = remote._claim_free_name(tmp_path, "snap.tar.gz")
        third = remote._claim_free_name(tmp_path, "snap.tar.gz")
        assert first.name == "snap.tar.gz"
        assert len({first, second, third}) == 3, "the same name was handed out twice"
        # Each claim is a real reservation on disk, which is what makes it exclusive.
        for p in (first, second, third):
            assert p.is_file()

    def test_the_claim_uses_an_exclusive_create(self):
        import inspect

        src = inspect.getsource(remote._claim_free_name)
        assert "O_EXCL" in src
        assert "exists()" not in src, "an exists() probe is the race this replaced"

    def test_a_failed_download_leaves_no_placeholder(self, tmp_path, monkeypatch):
        """The reservation is ours, so a failure must not leave a zero-byte file that
        looks like a bundle to `backup list` or to the next name claim."""

        def boom(args, profile, timeout=30):
            return 1, "", "NoSuchKey"

        monkeypatch.setattr(engine, "run_aws", boom)
        into = tmp_path / "snapshots"
        into.mkdir()
        with pytest.raises(remote.DestinationError):
            remote.download("s3://my-backups/backups/h/snap.tar.gz", into, "p")
        assert list(into.iterdir()) == [], "a placeholder survived the failure"


class TestTheArchiveProbeAcceptsAGoodBundle:
    def test_a_valid_archive_passes_the_probe(self, tmp_path):
        """The guard must not reject bundles it is meant to admit."""
        good = tmp_path / "good.tar.gz"
        payload = tmp_path / "f.txt"
        payload.write_text("hi")
        with tarfile.open(good, "w:gz") as tf:
            tf.add(payload, arcname="f.txt")
        with tarfile.open(good) as tf:
            assert [m.name for m in tf.getmembers()] == ["f.txt"]
