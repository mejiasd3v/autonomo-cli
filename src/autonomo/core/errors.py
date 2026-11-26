from __future__ import annotations


class AutonomoError(Exception):
    """Error with an optional hint for the agent or user. Exit code 1."""

    exit_code = 1

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.message = message
        self.hint = hint


class UsageError(AutonomoError):
    exit_code = 2


class ConfigError(AutonomoError):
    exit_code = 3


class ReadOnlyViolation(AutonomoError):
    """A request tried to change remote state without an explicit unlock."""

    exit_code = 4


class RemoteError(AutonomoError):
    exit_code = 5

    def __init__(self, message: str, hint: str = "", status: int | None = None, body: str = ""):
        super().__init__(message, hint)
        self.status = status
        self.body = body
