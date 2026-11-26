"""Digital certificate (FNMT or similar, PKCS#12 .p12/.pfx) for mTLS.

AEAT and Seguridad Social authenticate certificate holders at the TLS layer.
Python's ssl module only loads PEM files, so the key is re-encrypted with a
one-time random password, written to a private temp dir, loaded, and deleted.
The decrypted key never touches the disk.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import secrets
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    pkcs12,
)
from cryptography.x509.oid import NameOID

from .config import config_path
from .errors import ConfigError
from .http import default_ssl_context

PATH_ENV = "AUTONOMO_CERT_PATH"
PASSWORD_ENV = "AUTONOMO_CERT_PASSWORD"


@dataclass
class Certificate:
    path: Path
    key: Any
    cert: x509.Certificate
    chain: list[x509.Certificate]
    password_source: str = ""

    @classmethod
    def from_settings(cls, section: dict[str, Any]) -> Certificate:
        raw_path = os.environ.get(PATH_ENV) or section.get("path")
        if not raw_path:
            raise ConfigError(
                "No certificate configured.",
                hint="Run `autonomo cert find` to locate one, then `autonomo cert import PATH`.",
            )
        path = Path(raw_path).expanduser()
        if not path.exists():
            raise ConfigError(f"Certificate file not found: {path}", hint=f"Fix [certificate].path in {config_path()}.")
        # An env path override means "use this other file": the imported fingerprint does not apply.
        if os.environ.get(PATH_ENV):
            section = {k: v for k, v in section.items() if k != "fingerprint"}
        password, source = _password(section)
        try:
            key, cert, chain = pkcs12.load_key_and_certificates(path.read_bytes(), password.encode())
        except ValueError as exc:
            raise ConfigError(
                f"Cannot open {path.name}: wrong password or not a PKCS#12 file.",
                hint="Re-run `autonomo cert import` with the original .p12.",
            ) from exc
        if key is None or cert is None:
            raise ConfigError(f"{path.name} has no private key or certificate.")
        expected = section.get("fingerprint")
        if expected and cert.fingerprint(hashes.SHA256()).hex() != expected:
            raise ConfigError(f"{path.name} is not the imported certificate (fingerprint mismatch).", hint="Run `autonomo cert import` again.")
        return cls(path=path, key=key, cert=cert, chain=list(chain or []), password_source=source)

    @property
    def not_after(self) -> dt.datetime:
        return self.cert.not_valid_after_utc

    def days_left(self) -> int:
        return (self.not_after - dt.datetime.now(dt.UTC)).days

    def describe(self) -> dict[str, Any]:
        return {
            "file": self.path.name,
            "holder": mask_ids(cn(self.cert.subject)),
            "issuer": cn(self.cert.issuer),
            "not_after": self.not_after.date().isoformat(),
            "days_left": self.days_left(),
        }

    def nif(self) -> str | None:
        """Holder NIF/NIE. FNMT puts it in serialNumber ("IDCES-12345678Z")."""
        for attr in self.cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER):
            value = str(attr.value).upper()
            if match := _ID_RE.search(value.removeprefix("IDCES-")):
                return match.group(1)
        match = _ID_RE.search(cn(self.cert.subject).upper())
        return match.group(1) if match else None

    def ssl_context(self) -> ssl.SSLContext:
        ctx = default_ssl_context()
        one_time = secrets.token_bytes(32)
        key_pem = self.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(one_time))
        certs_pem = b"".join(c.public_bytes(Encoding.PEM) for c in [self.cert, *self.chain])
        with tempfile.TemporaryDirectory(prefix="autonomo-") as tmp:
            os.chmod(tmp, 0o700)
            cert_file, key_file = Path(tmp, "cert.pem"), Path(tmp, "key.pem")
            cert_file.write_bytes(certs_pem)
            key_file.write_bytes(key_pem)
            ctx.load_cert_chain(cert_file, key_file, password=one_time)
        return ctx


def _password(section: dict[str, Any]) -> tuple[str, str]:
    """Imported certificate: OS keyring. Otherwise: env var (secret managers, CI)."""
    if fp := section.get("fingerprint"):
        from .certstore import keyring_get

        if value := keyring_get(fp):
            return value, "OS keyring"
    if value := os.environ.get(PASSWORD_ENV):
        return value, f"env {PASSWORD_ENV}"
    raise ConfigError(
        "No password available for the certificate.",
        hint=f"Run `autonomo cert import PATH` (stores it in the OS keyring), or export {PASSWORD_ENV}.",
    )


def cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else name.rfc4514_string()


_ID_RE = re.compile(r"\b([0-9XYZ]\d{7}[A-Z]|[A-HJ-NP-SUVW]\d{7}[0-9A-J])\b")


def mask_ids(text: str) -> str:
    """Mask NIF/NIE/CIF so logs and agent transcripts do not carry them."""
    return _ID_RE.sub(lambda m: "*" * 6 + m.group(1)[-3:], text)
