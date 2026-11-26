"""autonomo: read-only CLI for agents.

Output is JSON on stdout. Errors are JSON on stderr with a non-zero exit code:
1 generic, 2 usage, 3 configuration, 4 read-only violation, 5 remote error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .core import certstore
from .core.config import CONFIG_ENV, KNOWN_SECRETS, config_path, load_config, secret_source
from .core.errors import AutonomoError, RemoteError, UsageError
from .core.provider import Binary, FetchOptions, Provider, Resource
from .core.registry import get_provider, provider_classes


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
    except AutonomoError as exc:
        _emit_error(exc)
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
    _emit(result)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autonomo",
        description="Read data from AEAT, Seguridad Social and FacturaDirecta. Read-only. JSON output.",
    )
    parser.add_argument("--version", action="version", version=f"autonomo {__version__}")
    sub = parser.add_subparsers(required=True, metavar="command")

    p = sub.add_parser("providers", help="List providers and whether they are configured")
    p.set_defaults(handler=cmd_providers)

    p = sub.add_parser("resources", help="List the resources of a provider and their parameters")
    p.add_argument("provider")
    p.set_defaults(handler=cmd_resources)

    p = sub.add_parser("get", help="Read a resource: autonomo get PROVIDER RESOURCE [key=value ...]")
    p.add_argument("provider")
    p.add_argument("resource")
    p.add_argument("params", nargs="*", metavar="key=value", help="Resource parameters and filters")
    p.add_argument("--all", action="store_true", help="Follow pagination and return every item")
    p.add_argument("--out", type=Path, help="File or directory for binary results (PDF, XML...)")
    p.set_defaults(handler=cmd_get)

    p = sub.add_parser("doctor", help="Check configuration, secrets and certificate")
    p.add_argument("provider", nargs="?")
    p.add_argument("--online", action="store_true", help="Also call each service with the credentials")
    p.set_defaults(handler=cmd_doctor)

    p = sub.add_parser("config", help="Show the config file location and the expected env vars")
    p.set_defaults(handler=cmd_config)

    cert = sub.add_parser("cert", help="Find, import and manage the digital certificate").add_subparsers(required=True, metavar="action")
    p = cert.add_parser("find", help="List candidate certificates: .p12/.pfx files and OS store identities")
    p.add_argument("--dir", type=Path, action="append", default=[], help="Extra directory to scan (repeatable)")
    p.set_defaults(handler=lambda a: certstore.find(a.dir))
    p = cert.add_parser(
        "import",
        help="Import a .p12/.pfx: re-encrypt with AES-256 and keep its random password in the OS keyring",
        description="The password is read from a hidden prompt (default in a terminal), --password-file, or --password-stdin. It is never accepted as an argument.",
    )
    p.add_argument("path", type=Path)
    src = p.add_mutually_exclusive_group()
    src.add_argument("--password-file", type=Path, help="File that contains only the password")
    src.add_argument("--password-stdin", action="store_true", help="Read the password from stdin")
    p.add_argument("--replace", action="store_true", help="Replace an already imported certificate")
    p.set_defaults(handler=cmd_cert_import)
    secret = sub.add_parser("secret", help="Store API keys in the OS keyring").add_subparsers(required=True, metavar="action")
    p = secret.add_parser("set", help="Store a secret. Value from a hidden prompt, --value-file or --value-stdin, never an argument")
    p.add_argument("name", help="For example AUTONOMO_FD_API_KEY")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--value-file", type=Path)
    src.add_argument("--value-stdin", action="store_true")
    p.set_defaults(handler=cmd_secret_set)
    p = secret.add_parser("delete", help="Remove a stored secret")
    p.add_argument("name")
    p.set_defaults(handler=lambda a: certstore.secret_delete(a.name))

    p = cert.add_parser("status", help="Show the configured certificate and where its password comes from")
    p.set_defaults(handler=lambda a: certstore.status())
    p = cert.add_parser("remove", help="Delete autonomo's copy and keyring entry (never the original file)")
    p.set_defaults(handler=lambda a: certstore.remove())
    return parser


# -- commands -----------------------------------------------------------------


def cmd_providers(args: argparse.Namespace) -> Any:
    config = load_config()
    out = []
    for name in provider_classes():
        provider = get_provider(name, config)
        checks = provider.doctor(online=False)
        out.append({
            "name": name,
            "title": provider.title,
            "description": provider.description,
            "configured": all(c.ok for c in checks),
            "resources": len(provider.resources()),
        })
    return out


def cmd_resources(args: argparse.Namespace) -> Any:
    provider = get_provider(args.provider)
    return [_resource_json(r) for r in provider.resources()]


def cmd_get(args: argparse.Namespace) -> Any:
    provider = get_provider(args.provider)
    try:
        resource = provider.resource(args.resource)
        if resource.access != "read":
            raise UsageError(
                f"{args.provider}/{resource.name} changes data. `autonomo get` only reads.",
                hint="Write commands with explicit confirmation are not available yet.",
            )
        params = _validate_params(resource, _parse_params(args.params))
        result = provider.fetch(resource.name, params, FetchOptions(all_pages=args.all))
    finally:
        provider.close()
    if isinstance(result, Binary):
        return _save_binary(result, args.out)
    return result


def cmd_cert_import(args: argparse.Namespace) -> Any:
    password = certstore.read_password(args.password_file, args.password_stdin, sys.stdin, interactive=sys.stdin.isatty())
    return certstore.import_certificate(args.path, password, replace=args.replace)


def cmd_secret_set(args: argparse.Namespace) -> Any:
    value = certstore.read_password(
        args.value_file, args.value_stdin, sys.stdin, interactive=sys.stdin.isatty(), prompt=f"{args.name} (hidden): "
    )
    return certstore.secret_set(args.name, value)


def cmd_doctor(args: argparse.Namespace) -> Any:
    names = [args.provider] if args.provider else list(provider_classes())
    out = {"config_file": str(config_path()), "config_exists": config_path().exists(), "providers": {}}
    for name in names:
        provider = get_provider(name)
        try:
            out["providers"][name] = [c.__dict__ for c in provider.doctor(online=args.online)]
        finally:
            provider.close()
    return out


def cmd_config(args: argparse.Namespace) -> Any:
    path = config_path()
    return {
        "config_file": str(path),
        "exists": path.exists(),
        "override_env": CONFIG_ENV,
        "sections": sorted(load_config().keys()),
        "secrets": {name: {"purpose": purpose, "source": secret_source(name)} for name, purpose in KNOWN_SECRETS.items()},
        "env": {
            "AUTONOMO_FD_API_KEY": "FacturaDirecta API key (secret; or `autonomo secret set`)",
            "AUTONOMO_FD_COMPANY_ID": "FacturaDirecta company id (overrides [facturadirecta].company_id)",
            "AUTONOMO_CERT_PATH": "Path to the .p12/.pfx certificate (overrides [certificate].path)",
            "AUTONOMO_CERT_PASSWORD": "Certificate password (secret)",
        },
        "example": EXAMPLE_CONFIG,
    }


EXAMPLE_CONFIG = """\
[facturadirecta]
company_id = "com_..."

[certificate]
path = "~/Documents/certificados/fnmt.p12"
"""


# -- helpers ------------------------------------------------------------------


def _parse_params(raw: list[str]) -> dict[str, str]:
    params: dict[str, str] = {}
    for item in raw:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise UsageError(f"Bad parameter '{item}'.", hint="Use key=value, for example minDate=2026-01-01.")
        params[key] = value
    return params


def _validate_params(resource: Resource, params: dict[str, str]) -> dict[str, str]:
    missing = [p.name for p in resource.params if p.required and not params.get(p.name, "").strip()]
    if missing:
        raise UsageError(f"Missing required parameter(s): {', '.join(missing)}.", hint=_usage(resource))
    if not resource.open_filters:
        known = {p.name for p in resource.params}
        unknown = [k for k in params if k not in known]
        if unknown:
            raise UsageError(f"Unknown parameter(s): {', '.join(unknown)}.", hint=_usage(resource))
    return params


def _usage(resource: Resource) -> str:
    parts = [f"{p.name}=..." if p.required else f"[{p.name}=...]" for p in resource.params]
    return f"{resource.name} {' '.join(parts)}".strip()


def _resource_json(r: Resource) -> dict[str, Any]:
    return {
        "name": r.name,
        "summary": r.summary,
        "access": r.access,
        "status": r.status,
        "params": [{"name": p.name, "required": p.required, "help": p.help} for p in r.params],
        "accepts_extra_filters": r.open_filters,
    }


def _save_binary(result: Binary, out: Path | None) -> dict[str, Any]:
    if out is None:
        raise UsageError(
            f"The result is binary ({result.content_type}).",
            hint="Repeat the command with --out FILE_OR_DIR.",
        )
    out = out.expanduser()
    if out.is_dir():
        out = out / (result.filename or "download.bin")
    out.write_bytes(result.content)
    return {"saved": str(out), "bytes": len(result.content), "content_type": result.content_type}


def _emit(data: Any) -> None:
    json.dump(data, sys.stdout, ensure_ascii=False, indent=2, default=str)
    sys.stdout.write("\n")


def _emit_error(exc: AutonomoError) -> None:
    payload: dict[str, Any] = {"error": exc.message, "type": type(exc).__name__}
    if exc.hint:
        payload["hint"] = exc.hint
    if isinstance(exc, RemoteError):
        payload["status"] = exc.status
        if exc.body:
            payload["body"] = exc.body
    json.dump(payload, sys.stderr, ensure_ascii=False, indent=2)
    sys.stderr.write("\n")


if __name__ == "__main__":
    sys.exit(main())
