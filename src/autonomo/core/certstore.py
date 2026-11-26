"""Certificate import, storage and discovery.

Import model:
* The user's .p12/.pfx is opened once with the user's password.
* autonomo writes its own copy, re-encrypted with PBES2 (PBKDF2-SHA256 + AES-256-CBC)
  under a random 256-bit password. Many exported .p12 files use 40-bit RC2,
  which is weak; the stored copy does not.
* The random password goes to the OS keyring (macOS Keychain, Windows
  Credential Manager, Secret Service). The user's password is not stored.
* The copy lives in <config dir>/certs/ with 0700/0600 permissions.

The user's password never travels in argv: it comes from a hidden prompt, a
file, or stdin.
"""

from __future__ import annotations

import datetime as dt
import os
import platform
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import PrivateFormat, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID

from .certificate import Certificate, cn
from .redact import mask_ids
from .config import config_path, load_config, remove_table, write_table
from .errors import ConfigError, UsageError

KEYRING_SERVICE = "autonomo"
KDF_ROUNDS = 200_000
SPANISH_CA_MARKERS = ("FNMT", "ACCV", "CAMERFIRMA", "DNIE", "IZENPE", "ANF", "FIRMAPROFESIONAL", "AC CATCERT", "ACA ")
SCAN_DIRS = ("Documents", "Downloads", "Desktop", "OneDrive", "")
SKIP_DIRS = {"node_modules", "Library", "AppData", ".git", ".venv", "venv", "site-packages", "Pictures", "Music", "Movies"}
MAX_DEPTH = 4


def store_dir() -> Path:
    return config_path().parent / "certs"


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


# -- keyring -----------------------------------------------------------------


def _keyring():
    import keyring
    from keyring.errors import KeyringError

    return keyring, KeyringError


def keyring_account(fp: str) -> str:
    return f"cert:{fp}"


def keyring_get(fp: str) -> str | None:
    keyring, KeyringError = _keyring()
    try:
        return keyring.get_password(KEYRING_SERVICE, keyring_account(fp))
    except KeyringError as exc:
        raise ConfigError(f"OS keyring unavailable: {exc}", hint=_no_keyring_hint()) from exc


def keyring_set(fp: str, password: str) -> None:
    keyring_set_raw(keyring_account(fp), password)


def keyring_delete(fp: str) -> bool:
    keyring, KeyringError = _keyring()
    try:
        keyring.delete_password(KEYRING_SERVICE, keyring_account(fp))
        return True
    except KeyringError:
        return False


def _no_keyring_hint() -> str:
    return (
        "No OS keyring (common on headless Linux). Skip `cert import` and set "
        "[certificate].path plus AUTONOMO_CERT_PASSWORD from your secret manager instead."
    )


# -- generic secrets (API keys) ---------------------------------------------------


def secret_set(env: str, value: bytes) -> dict[str, Any]:
    from .config import KNOWN_SECRETS

    if env not in KNOWN_SECRETS:
        raise UsageError(f"Unknown secret {env}.", hint=f"Known: {', '.join(KNOWN_SECRETS)}")
    text = value.decode().strip()
    if not text:
        raise UsageError("Empty value.")
    keyring_set_raw(f"secret:{env}", text)
    return {"stored": env, "where": "OS keyring", "note": f"An exported {env} still takes precedence."}


def secret_delete(env: str) -> dict[str, Any]:
    keyring, KeyringError = _keyring()
    try:
        keyring.delete_password(KEYRING_SERVICE, f"secret:{env}")
        return {"deleted": env}
    except KeyringError:
        return {"deleted": None, "detail": f"{env} was not in the keyring."}


def keyring_set_raw(account: str, value: str) -> None:
    keyring, KeyringError = _keyring()
    try:
        keyring.set_password(KEYRING_SERVICE, account, value)
    except KeyringError as exc:
        raise ConfigError(f"OS keyring unavailable: {exc}", hint=_no_keyring_hint()) from exc


# -- import / status / remove --------------------------------------------------


def read_password(password_file: Path | None, from_stdin: bool, stdin: Any, interactive: bool, prompt: str = "Certificate password (hidden): ") -> bytes:
    if password_file:
        data = Path(password_file).expanduser().read_bytes()
        return _strip_newline(data)
    if from_stdin:
        return _strip_newline(stdin.buffer.read() if hasattr(stdin, "buffer") else stdin.read().encode())
    if interactive:
        import getpass

        return getpass.getpass(prompt).encode()
    raise UsageError(
        "No password source.",
        hint="Run the command in a terminal for a hidden prompt, or use the --*-file / --*-stdin option. Never pass a secret as an argument.",
    )


def _strip_newline(data: bytes) -> bytes:
    return data[:-2] if data.endswith(b"\r\n") else data[:-1] if data.endswith(b"\n") else data


def import_certificate(source: Path, password: bytes, *, replace: bool = False) -> dict[str, Any]:
    source = source.expanduser()
    if not source.is_file():
        raise UsageError(f"File not found: {source}")
    try:
        key, cert, chain = pkcs12.load_key_and_certificates(source.read_bytes(), password)
    except ValueError as exc:
        raise ConfigError(f"Cannot open {source.name}: wrong password or not a PKCS#12 file.") from exc
    if key is None or cert is None:
        raise ConfigError(f"{source.name} has no private key. Export the certificate *with* its private key.")

    now = dt.datetime.now(dt.UTC)
    if cert.not_valid_after_utc <= now:
        raise ConfigError(
            f"{source.name} expired on {cert.not_valid_after_utc.date()}.",
            hint="Renew it with the issuer (FNMT: sede.fnmt.gob.es) and import the new one.",
        )
    warnings = []
    if (days := (cert.not_valid_after_utc - now).days) <= 30:
        warnings.append(f"Expires in {days} days.")
    if not _allows_client_auth(cert):
        warnings.append("Certificate is not marked for TLS client authentication; AEAT may reject it.")

    fp = fingerprint(cert)
    current = load_config().get("certificate", {})
    if current.get("fingerprint") and current["fingerprint"] != fp and not replace:
        raise UsageError(
            "Another certificate is already imported.",
            hint="Run `autonomo cert remove` first, or repeat with --replace.",
        )

    store_password = secrets.token_urlsafe(32)
    encryption = (
        PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(KDF_ROUNDS)
        .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
        .hmac_hash(hashes.SHA256())
        .build(store_password.encode())
    )
    blob = pkcs12.serialize_key_and_certificates(b"autonomo", key, cert, chain, encryption)

    directory = store_dir()
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    target = directory / f"{fp[:16]}.p12"
    # Order matters: a failure before the swap leaves the current certificate usable.
    staged = _write_private(target.with_suffix(".tmp"), blob)
    try:
        keyring_set(fp, store_password)
    except Exception:
        staged.unlink(missing_ok=True)
        raise
    os.replace(staged, target)
    write_table("certificate", {"path": str(target), "fingerprint": fp})
    if current.get("fingerprint") and current["fingerprint"] != fp:
        _forget(current)

    return {
        "imported": True,
        "stored_at": str(target),
        "fingerprint_sha256": fp,
        "password_storage": "OS keyring (random password; your original password is not stored)",
        "encryption": "PBES2 PBKDF2-SHA256 + AES-256-CBC",
        "holder": mask_ids(cn(cert.subject)),
        "issuer": cn(cert.issuer),
        "not_after": cert.not_valid_after_utc.date().isoformat(),
        "warnings": warnings,
        "next": f"Optional: delete or move the original file ({source}). autonomo no longer needs it.",
    }


def _write_private(path: Path, data: bytes) -> Path:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def _allows_client_auth(cert: x509.Certificate) -> bool:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return ExtendedKeyUsageOID.CLIENT_AUTH in eku or ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in eku


def status() -> dict[str, Any]:
    section = load_config().get("certificate", {})
    out: dict[str, Any] = {"configured": bool(section.get("path") or os.environ.get("AUTONOMO_CERT_PATH"))}
    if not out["configured"]:
        out["hint"] = "Run `autonomo cert find`, then `autonomo cert import PATH`."
        return out
    cert = Certificate.from_settings(section)
    out.update(cert.describe())
    out["fingerprint_sha256"] = fingerprint(cert.cert)
    out["password_source"] = cert.password_source
    return out


def remove() -> dict[str, Any]:
    section = load_config().get("certificate", {})
    if not section:
        return {"removed": False, "detail": "No certificate configured."}
    removed = _forget(section)
    remove_table("certificate")
    return {"removed": True, **removed}


def _forget(section: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"file_deleted": False, "keyring_entry_deleted": False}
    path = Path(section.get("path", "")).expanduser()
    # Only delete files autonomo created; never the user's own .p12.
    if section.get("path") and path.parent == store_dir() and path.exists():
        path.unlink()
        out["file_deleted"] = True
    if fp := section.get("fingerprint"):
        out["keyring_entry_deleted"] = keyring_delete(fp)
    return out


# -- discovery -----------------------------------------------------------------


def find(extra_dirs: list[Path] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"files": find_files(extra_dirs or []), "os_store": [], "hints": []}
    system = platform.system()
    if system == "Darwin":
        out["os_store"] = macos_identities()
        out["hints"].append(
            "Keychain identities cannot be used directly. Export one: Keychain Access > My Certificates > "
            "right-click the certificate > Export > .p12, with a password. Then `autonomo cert import FILE`."
        )
    elif system == "Windows":
        out["hints"].append(
            "Windows certificate store: run certmgr.msc > Personal > Certificates > right-click > All Tasks > Export, "
            "choose 'Yes, export the private key', .pfx, with a password. Then `autonomo cert import FILE`."
        )
    else:
        out["hints"].append(
            "Firefox: Settings > Privacy & Security > Certificates > View Certificates > Your Certificates > Backup "
            "(creates a .p12). Then `autonomo cert import FILE`."
        )
    out["hints"].append("FNMT certificates last 4 years. Prefer the newest valid one; expired ones are useless.")
    return out


def find_files(extra_dirs: list[Path]) -> list[dict[str, Any]]:
    home = Path.home()
    roots = [home / d for d in SCAN_DIRS] + [Path(d).expanduser() for d in extra_dirs]
    seen: set[Path] = set()
    found = []
    for root in roots:
        depth = 1 if root == home else MAX_DEPTH
        for path in _walk(root, depth):
            if path in seen:
                continue
            seen.add(path)
            found.append(_describe_file(path))
    found.sort(key=lambda f: f["modified"], reverse=True)
    return found


def _walk(root: Path, depth: int):
    if not root.is_dir():
        return
    try:
        entries = list(os.scandir(root))
    except OSError:
        return
    for entry in entries:
        if entry.name.startswith(".") or entry.name in SKIP_DIRS:
            continue
        if entry.is_file(follow_symlinks=False) and entry.name.lower().endswith((".p12", ".pfx")):
            yield Path(entry.path).resolve()
        elif depth > 1 and entry.is_dir(follow_symlinks=False):
            yield from _walk(Path(entry.path), depth - 1)


def _describe_file(path: Path) -> dict[str, Any]:
    stat = path.stat()
    info: dict[str, Any] = {
        "path": str(path),
        "bytes": stat.st_size,
        "modified": dt.datetime.fromtimestamp(stat.st_mtime).date().isoformat(),
        "imported": path.parent == store_dir(),
    }
    # Readable without a password? Then show details and warn: the key is unprotected.
    for pw in (None, b""):
        try:
            key, cert, _ = pkcs12.load_key_and_certificates(path.read_bytes(), pw)
        except Exception:
            continue
        if cert is not None:
            info.update(_cert_summary(cert))
            info["warning"] = "Opens without a password: the private key is not protected."
        return info
    info["locked"] = True
    return info


def _cert_summary(cert: x509.Certificate) -> dict[str, Any]:
    issuer = cn(cert.issuer)
    not_after = cert.not_valid_after_utc
    return {
        "holder": mask_ids(cn(cert.subject)),
        "issuer": issuer,
        "not_after": not_after.date().isoformat(),
        "expired": not_after <= dt.datetime.now(dt.UTC),
        "spanish_ca": any(m in issuer.upper() for m in SPANISH_CA_MARKERS),
        "client_auth": _allows_client_auth(cert),
    }


_IDENTITY_RE = re.compile(r'^\s*\d+\)\s+([0-9A-F]{40})\s+"(.*)"', re.M)
_HASH_RE = re.compile(r"^SHA-1 hash:\s*([0-9A-F]{40})", re.M)


def macos_identities() -> list[dict[str, Any]]:
    """Certificates with a private key in the user's Keychain. Public data only."""
    if not shutil.which("security"):
        return []
    try:
        ids = subprocess.run(["security", "find-identity", "-v"], capture_output=True, text=True, timeout=20).stdout
        dump = subprocess.run(["security", "find-certificate", "-a", "-Z", "-p"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    pems: dict[str, str] = {}
    for block in re.split(r"(?=^SHA-256 hash:|^SHA-1 hash:)", dump, flags=re.M):
        if (m := _HASH_RE.search(block)) and "BEGIN CERTIFICATE" in block:
            pem = block[block.index("-----BEGIN CERTIFICATE-----"):]
            pems[m.group(1)] = pem[: pem.index("-----END CERTIFICATE-----") + 25]
    out = []
    for sha1, _name in dict(_IDENTITY_RE.findall(ids)).items():
        entry: dict[str, Any] = {"store": "macOS Keychain", "sha1": sha1}
        if sha1 in pems:
            entry.update(_cert_summary(x509.load_pem_x509_certificate(pems[sha1].encode())))
        else:
            entry["holder"] = mask_ids(_name)
        out.append(entry)
    return out
