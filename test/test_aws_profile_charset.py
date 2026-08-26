"""Regression tests for the four sibling AWS-profile character classes (#6055).

IAM Identity Center derives profile names shaped ``<account>+<permission-set>``
(e.g. ``AdminAccess+dev``), so ``+`` must be accepted. The SSM/instances pair
was fixed by #6051; these tests pin the four remaining hand-copied patterns:

* ``kiro_crew.cloud.ec2._PROFILE_SPEC`` (EC2 wizard — aliases
  ``profiles.PROFILE_SPEC``)
* ``kiro_crew.deploy.profiles._PROFILE_RE`` (deploy profile registry + the
  ``aws configure list-profiles`` discovery filter)
* ``kiro_crew.deploy.handlers._PROFILE_SPEC`` (deploy-web HTTP boundary —
  aliases ``profiles.PROFILE_SPEC``)
* ``kiro_crew.validation._WM_PROFILE_RE`` (workspace-manager webapp_metadata)

All four values only ever reach a subprocess as a discrete ``--profile <value>``
argv element (never a shell string), so the widened class must still exclude
whitespace and shell metacharacters, must reject option-shaped (leading ``-``)
values, and must anchor with ``\\Z`` so a trailing newline cannot slip past
``$``'s end-of-line leniency.
"""

from __future__ import annotations

import os

import pytest

from kiro_crew import validation as validation_mod
from kiro_crew.cloud import aws as cloud_aws
from kiro_crew.cloud import ec2
from kiro_crew.deploy import engine as engine_mod
from kiro_crew.deploy import handlers
from kiro_crew.deploy import profiles as profiles_mod
from kiro_crew.validation import (
    ARTIFACT_SAVE_SCHEMA,
    ValidationError,
    validate_field,
    validate_tool_args,
)

_POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt", reason="deploy profile discovery is POSIX-only by design"
)

_PATTERNS = {
    # ec2 and handlers alias profiles.PROFILE_SPEC (same idiom as handlers'
    # _REGION_SPEC); pin each boundary's ACTUAL pattern so a future divergent
    # local copy is still caught here.
    "cloud.ec2": ec2._PROFILE_SPEC.pattern,
    "deploy.profiles": profiles_mod._PROFILE_RE,
    "deploy.handlers": handlers._PROFILE_SPEC.pattern,
    "workspace-manager": validation_mod._WM_PROFILE_RE,
}

_ACCEPTED = [
    "AdminAccess+dev",  # the IAM Identity Center shape from the report
    "123456789012+PowerUserAccess",
    "p",  # single char (quantifier still means >= 1)
    "a.b_c-d",  # the full legacy charset keeps working
    "dev+test.2-x_9",
]

_REJECTED = [
    "-leading-dash",  # option-shaped: must never reach --profile argv
    "--profile",
    "+extra trailing junk",  # whitespace stays excluded even around '+'
    "has space",
    "semi;colon",
    "pipe|pipe",
    "dollar$(x)",
    "back`tick",
    "newline\ninside",
    "trailing\n",  # \Z regression: $ matched just before a trailing newline
    "tab\t",
    "",
]


class TestProfilePatternCharset:
    """The compiled patterns themselves, exercised via .match like production."""

    @pytest.mark.parametrize("site", sorted(_PATTERNS))
    @pytest.mark.parametrize("value", _ACCEPTED)
    def test_accepts_legal_profiles(self, site: str, value: str) -> None:
        assert _PATTERNS[site].match(value), f"{site} rejected legal profile {value!r}"

    @pytest.mark.parametrize("site", sorted(_PATTERNS))
    @pytest.mark.parametrize("value", _REJECTED)
    def test_rejects_unsafe_values(self, site: str, value: str) -> None:
        assert not _PATTERNS[site].match(value), f"{site} accepted unsafe value {value!r}"


class TestEc2ValidateProfile:
    def test_plus_profile_accepted(self) -> None:
        assert ec2.validate_profile("AdminAccess+dev") == "AdminAccess+dev"

    @pytest.mark.parametrize("bad", ["-foo", "evil;rm -rf", "a b"])
    def test_unsafe_profiles_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            ec2.validate_profile(bad)

    def test_empty_profile_still_allowed(self) -> None:
        # Empty means "no --profile" downstream; the pattern is only enforced
        # on non-empty values (pre-existing semantics, must not change).
        assert ec2.validate_profile("") == ""

    def test_trailing_newline_normalized_by_sanitizer(self) -> None:
        # validate_field strips via sanitize_string BEFORE the pattern check,
        # so a trailing newline is normalized away rather than rejected here;
        # the \Z anchor is the defense for the raw-match call sites.
        assert ec2.validate_profile("AdminAccess+dev\n") == "AdminAccess+dev"


class TestDeployProfilesSpec:
    def test_plus_profile_accepted(self) -> None:
        assert validate_field("AdminAccess+dev", profiles_mod.PROFILE_SPEC) == "AdminAccess+dev"

    @pytest.mark.parametrize("bad", ["-foo", "evil;rm -rf"])
    def test_unsafe_profiles_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            validate_field(bad, profiles_mod.PROFILE_SPEC)

    @_POSIX_ONLY
    def test_discovery_keeps_plus_profiles_and_drops_option_shaped(self, monkeypatch) -> None:
        # `aws configure list-profiles` output lines are stripped before the
        # filter, so the \Z anchor is behavior-neutral here; the widened class
        # is what lets SSO-derived names show up in discovery at all.
        out = "default\nAdminAccess+dev\n-cursed\nbad name!\nok.two\n"
        monkeypatch.setattr(profiles_mod.engine, "run_aws", lambda *a, **k: (0, out, ""))
        assert profiles_mod.discover_aws_profiles() == ["default", "AdminAccess+dev", "ok.two"]


class TestDeployHandlersSpec:
    def test_plus_profile_accepted(self) -> None:
        assert validate_field("AdminAccess+dev", handlers._PROFILE_SPEC) == "AdminAccess+dev"

    @pytest.mark.parametrize("bad", ["-foo", "evil;rm -rf"])
    def test_unsafe_profiles_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            validate_field(bad, handlers._PROFILE_SPEC)

    def test_empty_profile_still_allowed(self) -> None:
        # "" clears the profile (falls back to default) — pre-existing
        # empty-value semantics that the charset change must not disturb.
        assert validate_field("", handlers._PROFILE_SPEC) == ""


class TestWorkspaceManagerProfile:
    @staticmethod
    def _args(profile: str) -> dict:
        return {
            "name": "t",
            "content": "x",
            "kind": "webapp",
            "webapp_metadata": {"deploy_target": {"profile": profile}},
        }

    def test_plus_profile_accepted(self) -> None:
        result = validate_tool_args(self._args("AdminAccess+dev"), ARTIFACT_SAVE_SCHEMA)
        assert result["webapp_metadata"]["deploy_target"]["profile"] == "AdminAccess+dev"

    @pytest.mark.parametrize("bad", ["-foo", "evil;rm -rf"])
    def test_unsafe_profiles_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="invalid profile"):
            validate_tool_args(self._args(bad), ARTIFACT_SAVE_SCHEMA)

    def test_trailing_newline_rejected_raw(self) -> None:
        # This call site matches the raw stored value (no strip), so the old $
        # anchor let "p\n" through — \Z is a real tightening here.
        assert not validation_mod._WM_PROFILE_RE.match("AdminAccess+dev\n")

    def test_empty_profile_still_allowed(self) -> None:
        result = validate_tool_args(self._args(""), ARTIFACT_SAVE_SCHEMA)
        assert result["webapp_metadata"]["deploy_target"]["profile"] == ""


class TestPatternLengthBound:
    """The quantifier bounds length to 128 inside the pattern itself, matching
    the max_len=128 caps the FieldSpec sites enforce (and #6051's sibling)."""

    @pytest.mark.parametrize("site", sorted(_PATTERNS))
    def test_128_chars_accepted_129_rejected(self, site: str) -> None:
        assert _PATTERNS[site].match("a" * 128)
        assert not _PATTERNS[site].match("a" * 129)


class TestDiscreteArgvIntegration:
    """The safety argument for the widened charset rests on the profile only
    ever reaching the aws CLI as a discrete ``--profile <value>`` argv pair —
    pin that end-to-end for both subprocess chokepoints."""

    def test_cloud_build_argv_keeps_plus_profile_discrete(self) -> None:
        argv = cloud_aws._build_argv(["sts", "get-caller-identity"], "AdminAccess+dev", "")
        assert argv[-2:] == ["--profile", "AdminAccess+dev"]

    def test_deploy_engine_aws_keeps_plus_profile_discrete(self) -> None:
        argv = engine_mod._aws(["s3", "ls"], "AdminAccess+dev")
        assert argv[-2:] == ["--profile", "AdminAccess+dev"]
