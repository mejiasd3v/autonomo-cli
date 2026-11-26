"""Configuration.

Non-secret settings live in a TOML file (default ~/.config/autonomo/config.toml,
override with AUTONOMO_CONFIG). One table per provider, plus [certificate]
shared by the providers that use the digital certificate.

Secrets (API keys, certificate password) are read only from environment
variables, never from the config file. Use `prun autonomo ...` with a .env
that holds pass:// references, or any other secret manager that exports env.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from .errors import ConfigError

CONFIG_ENV = "AUTONOMO_CONFIG"


def config_path() -> Path:
    if explicit := os.environ.get(CONFIG_ENV):
        return Path(explicit).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "autonomo" / "config.toml"


def load_config(path: Path | None = None) -> dict[str, Any]:
    path = path or config_path()
    if not path.exists():
        return {}
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc


def setting(section: dict[str, Any], key: str, env: str | None = None, default: Any = None) -> Any:
    """Env var wins over the config file, so agents can override per call."""
    if env and (value := os.environ.get(env)):
        return value
    return section.get(key, default)


def require_setting(section: dict[str, Any], key: str, env: str, table: str) -> Any:
    value = setting(section, key, env)
    if value in (None, ""):
        raise ConfigError(
            f"Missing setting '{key}'.",
            hint=f"Set {env} or add `{key} = ...` under [{table}] in {config_path()}.",
        )
    return value


# Secrets that `autonomo secret set` may store in the OS keyring.
KNOWN_SECRETS = {
    "AUTONOMO_FD_API_KEY": "FacturaDirecta API key (create it with :read scopes only)",
}


def secret(env: str, purpose: str) -> str:
    """Env var first (secret managers, CI, prun), then the OS keyring."""
    if value := os.environ.get(env):
        return value
    if value := keyring_secret(env):
        return value
    raise ConfigError(
        f"Missing secret {env} ({purpose}).",
        hint=f"Run `autonomo secret set {env}` (hidden prompt, stored in the OS keyring), or export {env} from your secret manager.",
    )


def secret_source(env: str) -> str | None:
    if os.environ.get(env):
        return "env"
    return "OS keyring" if keyring_secret(env) else None


def keyring_secret(env: str) -> str | None:
    try:
        import keyring
        from keyring.errors import KeyringError

        return keyring.get_password("autonomo", f"secret:{env}")
    except (ImportError, KeyringError):
        return None


# -- writing ------------------------------------------------------------------
# tomllib cannot write. autonomo only writes flat tables of strings, so a small
# text edit keeps comments and the user's other tables intact.

_TABLE_RE = r"(?ms)^\[{name}\][ \t]*\n.*?(?=^\[|\Z)"


def _toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_table(name: str, values: dict[str, str], path: Path | None = None) -> Path:
    import re

    path = path or config_path()
    text = path.read_text() if path.exists() else ""
    block = f"[{name}]\n" + "".join(f"{k} = {_toml_str(v)}\n" for k, v in values.items()) + "\n"
    pattern = _TABLE_RE.format(name=re.escape(name))
    if re.search(pattern, text):
        text = re.sub(pattern, lambda _: block, text, count=1)
    else:
        text = (text.rstrip() + "\n\n" if text.strip() else "") + block
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def remove_table(name: str, path: Path | None = None) -> None:
    import re

    path = path or config_path()
    if path.exists():
        path.write_text(re.sub(_TABLE_RE.format(name=re.escape(name)), "", path.read_text(), count=1))
