"""Provider discovery through the "autonomo.providers" entry point group.

Built-in providers register in this package's pyproject.toml. External
packages register the same way, so they need no change here.
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from .config import load_config
from .errors import UsageError
from .provider import Provider

GROUP = "autonomo.providers"


def provider_classes() -> dict[str, type[Provider]]:
    return {ep.name: ep.load() for ep in sorted(entry_points(group=GROUP), key=lambda e: e.name)}


def get_provider(name: str, config: dict[str, Any] | None = None) -> Provider:
    classes = provider_classes()
    if name not in classes:
        raise UsageError(f"Unknown provider '{name}'.", hint=f"Known: {', '.join(classes)}")
    config = load_config() if config is None else config
    cls = classes[name]
    return cls(_settings_for(name, config))


def _settings_for(name: str, config: dict[str, Any]) -> dict[str, Any]:
    settings = dict(config.get(name, {}))
    # Shared certificate settings, available to every provider.
    settings.setdefault("certificate", config.get("certificate", {}))
    return settings
