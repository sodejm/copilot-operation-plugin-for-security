"""Typed failures and stable command exit codes."""

from __future__ import annotations


EXIT_OK = 0
EXIT_CONTENT = 2
EXIT_COMPATIBILITY = 3
EXIT_TEST = 4
EXIT_UNAVAILABLE = 5
EXIT_INTERNAL = 6


class HuntWorkbenchError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = EXIT_CONTENT


class ContentError(HuntWorkbenchError):
    """A hunt, profile, parameter, or contract is invalid."""


class CompatibilityError(HuntWorkbenchError):
    """The requested surface is unsupported or unverified."""

    exit_code = EXIT_COMPATIBILITY


class TestFailure(HuntWorkbenchError):
    """A deterministic fixture, mutation, or adversarial gate failed."""

    exit_code = EXIT_TEST


class ToolUnavailable(HuntWorkbenchError):
    """A requested optional tool or evidence source is unavailable."""

    exit_code = EXIT_UNAVAILABLE
