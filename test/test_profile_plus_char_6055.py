"""Regression tests for issue #6055: AWS profile regexes accept '+'.

IAM Identity Center derived profiles use '+' (e.g. ``AdminAccess+dev``).
PR #6051 fixed the SSM/instances path; this covers the four sibling sites:
- cloud/ec2.py _PROFILE_RE / _PROFILE_SPEC
- deploy/profiles.py _PROFILE_RE / PROFILE_SPEC
- deploy/handlers.py _PROFILE_RE / _PROFILE_SPEC
- validation.py _WM_PROFILE_RE

Each regex must accept '+' in profile names and use \\Z (not $) so a
trailing newline is not silently accepted.
"""

from __future__ import annotations

import re


import pytest


# ---- Import the regexes from each module. Some modules have heavy deps
# (aiohttp, etc.) that may not be installed in all environments; import
# only what we need (the regex objects), falling back to extracting the
# pattern string from source if needed.


def _import_ec2_profile_re():
    from kiro_crew.cloud import ec2
    return ec2._PROFILE_RE, ec2._PROFILE_SPEC


def _import_profiles_profile_re():
    from kiro_crew.deploy import profiles as profiles_mod
    return profiles_mod._PROFILE_RE, profiles_mod.PROFILE_SPEC


def _import_handlers_profile_re():
    from kiro_crew.deploy import handlers
    return handlers._PROFILE_RE, handlers._PROFILE_SPEC


def _import_wm_profile_re():
    from kiro_crew import validation as validation_mod
    return validation_mod._WM_PROFILE_RE


# We test the expected pattern directly to guarantee correctness even if
# some imports fail due to missing third-party dependencies.  The source
# of truth is the pattern string embedded in each module.
_EXPECTED_PATTERN = r"^[A-Za-z0-9_.+-]+\Z"


# --- Direct pattern tests (always run, no third-party deps) ------------------


class TestExpectedPatternAcceptsPlus:
    """The canonical pattern must accept IAM Identity Center profile names."""

    _re = re.compile(_EXPECTED_PATTERN)

    def test_simple_profile(self):
        assert self._re.match("default")

    def test_dotted_profile(self):
        assert self._re.match("my.profile")

    def test_hyphenated_profile(self):
        assert self._re.match("my-profile_1.x")

    def test_iam_identity_center_profile(self):
        assert self._re.match("AdminAccess+dev")

    def test_multi_plus_profile(self):
        assert self._re.match("123456789012+PowerUserAccess")

    def test_complex_sso_profile(self):
        assert self._re.match("Acct+PermSet+extra")

    def test_trailing_newline_rejected(self):
        """\\Z anchor rejects trailing newline that $ would accept."""
        assert self._re.match("valid\n") is None

    def test_empty_string_rejected(self):
        assert self._re.match("") is None

    def test_shell_metacharacters_rejected(self):
        for bad in ("a;b", "a b", "a$(x)", "a`b`", "a|b", "a&b"):
            assert self._re.match(bad) is None, f"should reject {bad!r}"

    def test_option_injection_with_space_rejected(self):
        """Option-injection with embedded spaces is rejected by the regex.
        A bare '-oProxyCommand' has no whitespace or metachar so the regex
        alone accepts it; each call site has a separate leading-dash guard."""
        assert self._re.match("-o ProxyCommand") is None
        assert self._re.match("--profile; rm") is None


# --- Source-level verification (parse the .py files to confirm the pattern) ---


class TestSourcePatternsMatch:
    """Verify each source file contains the expected widened pattern."""

    def _read_source(self, relpath: str) -> str:
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        return (root / relpath).read_text(encoding="utf-8")

    def test_ec2_pattern(self):
        src = self._read_source("src/kiro_crew/cloud/ec2.py")
        assert '_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.+-]+\\Z")' in src

    def test_profiles_pattern(self):
        src = self._read_source("src/kiro_crew/deploy/profiles.py")
        assert '_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.+-]+\\Z")' in src

    def test_handlers_pattern(self):
        src = self._read_source("src/kiro_crew/deploy/handlers.py")
        assert '_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.+-]+\\Z")' in src

    def test_validation_pattern(self):
        src = self._read_source("src/kiro_crew/validation.py")
        assert '_WM_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.+-]+\\Z")' in src


# --- Live import tests (skipped if deps are missing) -------------------------


def _try_import(func):
    """Decorator: skip the test if the import raises ModuleNotFoundError."""
    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ModuleNotFoundError as exc:
            pytest.skip(f"dependency not installed: {exc.name}")
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


class TestEc2ProfileAcceptsPlus:
    """cloud/ec2.py _PROFILE_RE / _PROFILE_SPEC (live import)."""

    @_try_import
    def test_iam_identity_center_profile_accepted(self):
        profile_re, _ = _import_ec2_profile_re()
        assert profile_re.match("AdminAccess+dev")

    @_try_import
    def test_validate_field_accepts_plus(self):
        from kiro_crew.validation import validate_field
        _, spec = _import_ec2_profile_re()
        assert validate_field("AdminAccess+dev", spec) == "AdminAccess+dev"

    @_try_import
    def test_trailing_newline_rejected(self):
        profile_re, _ = _import_ec2_profile_re()
        assert profile_re.match("valid\n") is None

    @_try_import
    def test_still_rejects_shell_metacharacters(self):
        profile_re, _ = _import_ec2_profile_re()
        for bad in ("a;b", "a b", "a$(x)"):
            assert profile_re.match(bad) is None


class TestDeployProfilesAcceptsPlus:
    """deploy/profiles.py _PROFILE_RE / PROFILE_SPEC (live import)."""

    @_try_import
    def test_iam_identity_center_profile_accepted(self):
        profile_re, _ = _import_profiles_profile_re()
        assert profile_re.match("AdminAccess+dev")

    @_try_import
    def test_validate_field_accepts_plus(self):
        from kiro_crew.validation import validate_field
        _, spec = _import_profiles_profile_re()
        assert validate_field("AdminAccess+dev", spec) == "AdminAccess+dev"

    @_try_import
    def test_trailing_newline_rejected(self):
        profile_re, _ = _import_profiles_profile_re()
        assert profile_re.match("valid\n") is None

    @_try_import
    def test_still_rejects_shell_metacharacters(self):
        profile_re, _ = _import_profiles_profile_re()
        for bad in ("a;b", "a b", "a$(x)"):
            assert profile_re.match(bad) is None


class TestDeployHandlersAcceptsPlus:
    """deploy/handlers.py _PROFILE_RE / _PROFILE_SPEC (live import)."""

    @_try_import
    def test_iam_identity_center_profile_accepted(self):
        profile_re, _ = _import_handlers_profile_re()
        assert profile_re.match("AdminAccess+dev")

    @_try_import
    def test_validate_field_accepts_plus(self):
        from kiro_crew.validation import validate_field
        _, spec = _import_handlers_profile_re()
        assert validate_field("AdminAccess+dev", spec) == "AdminAccess+dev"

    @_try_import
    def test_trailing_newline_rejected(self):
        profile_re, _ = _import_handlers_profile_re()
        assert profile_re.match("valid\n") is None

    @_try_import
    def test_still_rejects_shell_metacharacters(self):
        profile_re, _ = _import_handlers_profile_re()
        for bad in ("a;b", "a b", "a$(x)"):
            assert profile_re.match(bad) is None


class TestWmProfileAcceptsPlus:
    """validation.py _WM_PROFILE_RE (live import)."""

    @_try_import
    def test_iam_identity_center_profile_accepted(self):
        wm_re = _import_wm_profile_re()
        assert wm_re.match("AdminAccess+dev")

    @_try_import
    def test_multi_plus_profile_accepted(self):
        wm_re = _import_wm_profile_re()
        assert wm_re.match("123456789012+PowerUserAccess")

    @_try_import
    def test_trailing_newline_rejected(self):
        wm_re = _import_wm_profile_re()
        assert wm_re.match("valid\n") is None

    @_try_import
    def test_still_rejects_shell_metacharacters(self):
        wm_re = _import_wm_profile_re()
        for bad in ("a;b", "a b", "a$(x)"):
            assert wm_re.match(bad) is None
