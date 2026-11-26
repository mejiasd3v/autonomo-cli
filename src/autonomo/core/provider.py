"""Provider contract.

A provider is one data source (FacturaDirecta, AEAT, Seguridad Social...).
It declares its resources and knows how to fetch them. The CLI and the agent
skill only talk to this contract, so a new source is a new module plus an
entry point in pyproject.toml (group "autonomo.providers").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Access = Literal["read", "write"]
Status = Literal["stable", "experimental"]


@dataclass(frozen=True)
class Param:
    name: str
    help: str = ""
    required: bool = False


@dataclass(frozen=True)
class Resource:
    """Something an agent can read (or, in the future, change).

    `access="write"` resources are refused by `autonomo get`. They will need an
    explicit confirmation command before any provider declares one.
    `status="experimental"` marks endpoints that are not verified end to end.
    """

    name: str
    summary: str
    params: tuple[Param, ...] = ()
    access: Access = "read"
    status: Status = "stable"
    # Extra key=value pairs are passed through as filters when True.
    open_filters: bool = False


@dataclass
class Binary:
    """Non-JSON result (PDF, XML...). The CLI writes it to --out."""

    content: bytes
    content_type: str
    filename: str | None = None


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    hint: str = ""


@dataclass
class FetchOptions:
    all_pages: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


class Provider:
    """Base class for providers. Subclasses set the class attributes."""

    name: str = ""
    title: str = ""
    description: str = ""

    def __init__(self, settings: dict[str, Any]):
        # Non-secret settings from the config file section [<name>].
        self.settings = settings

    def resources(self) -> list[Resource]:
        raise NotImplementedError

    def resource(self, name: str) -> Resource:
        for res in self.resources():
            if res.name == name:
                return res
        from .errors import UsageError

        known = ", ".join(r.name for r in self.resources())
        raise UsageError(f"Unknown resource '{name}' for {self.name}.", hint=f"Known: {known}")

    def fetch(self, resource: str, params: dict[str, str], options: FetchOptions) -> Any:
        """Return JSON-serializable data or a Binary."""
        raise NotImplementedError

    def doctor(self, online: bool = False) -> list[Check]:
        """Configuration and credential checks. Network calls only when online=True."""
        return []

    def close(self) -> None:
        pass
