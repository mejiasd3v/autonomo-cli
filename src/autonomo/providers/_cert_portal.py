"""Shared base for public administration portals that accept the digital certificate.

Mechanism: TLS client authentication (mTLS) with the user's PKCS#12 certificate.
No browser and no Cl@ve. Requests stay inside an allowlist of official hosts,
and redirects are followed by hand so the certificate session never leaves it.
"""

from __future__ import annotations

import gzip
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ..core.certificate import Certificate
from ..core.errors import ConfigError, RemoteError, UsageError
from ..core.html import html_to_page
from ..core.http import make_client, send
from ..core.provider import Binary, Check, FetchOptions, Param, Provider, Resource

MAX_REDIRECTS = 8


class Service:
    """A known read-only page or document of the portal."""

    def __init__(self, name: str, summary: str, url: str, *, params: tuple[Param, ...] = (), status: str = "experimental", note: str = ""):
        self.name = name
        self.summary = summary
        self.url = url
        self.params = params
        self.status = status
        self.note = note

    def resource(self) -> Resource:
        summary = f"{self.summary}. {self.note}".strip(". ") if self.note else self.summary
        return Resource(self.name, summary, self.params, status=self.status)  # type: ignore[arg-type]


def decode_body(response: httpx.Response) -> str:
    """Response text. Some Seguridad Social hosts send gzip without Content-Encoding."""
    raw = response.content
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw).decode(response.encoding or "utf-8", "replace")
    return response.text


class CertPortal(Provider):
    hosts: tuple[str, ...] = ()
    # Redirects to these hosts mean an interactive login the provider cannot do.
    login_host_markers: tuple[str, ...] = ("clave.gob.es", "pasarela.clave", "idp.")
    probe_url: str = ""
    services: tuple[Service, ...] = ()

    def __init__(self, settings: dict[str, Any], transport: httpx.BaseTransport | None = None):
        super().__init__(settings)
        self._transport = transport
        self._client: httpx.Client | None = None
        self._cert: Certificate | None = None

    # -- catalogue -----------------------------------------------------------

    def resources(self) -> list[Resource]:
        base = [
            Resource("certificate", "Datos del certificado configurado (titular enmascarado, emisor, caducidad). Sin red", ()),
            Resource(
                "page",
                f"GET de una página o documento de la sede con el certificado. Hosts: {', '.join(self.hosts)}",
                (Param("url", "URL https de un host permitido", required=True),),
            ),
        ]
        return base + [s.resource() for s in self.services]

    def fetch(self, resource: str, params: dict[str, str], options: FetchOptions) -> Any:
        self.resource(resource)
        if resource == "certificate":
            return self.certificate.describe()
        if resource == "page":
            return self.get_page(params["url"])
        service = next(s for s in self.services if s.name == resource)
        return self.fetch_service(service, params)

    def fetch_service(self, service: Service, params: dict[str, str]) -> Any:
        """Default: GET the service URL (formatted with params) and parse it."""
        return self.get_page(service.url.format(**params))

    # -- http ----------------------------------------------------------------

    @property
    def certificate(self) -> Certificate:
        if self._cert is None:
            self._cert = Certificate.from_settings(self.settings.get("certificate", {}))
        return self._cert

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            ssl_context = None if self._transport else self.certificate.ssl_context()
            self._client = make_client(
                ssl_context=ssl_context,
                transport=self._transport,
                follow_redirects=False,
                headers={"Accept-Language": "es-ES,es;q=0.9"},
            )
        return self._client

    def check_host(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in self.hosts:
            raise UsageError(f"URL not allowed: {url}", hint=f"Allowed hosts (https only): {', '.join(self.hosts)}")

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send a request and follow redirects only inside the host allowlist."""
        self.check_host(url)
        for _ in range(MAX_REDIRECTS):
            response = send(self.client, method, url, **kwargs)
            if not response.is_redirect:
                return response
            target = urljoin(str(response.url), response.headers.get("location", ""))
            host = urlparse(target).hostname or ""
            if any(marker in host for marker in self.login_host_markers):
                raise RemoteError(
                    f"{url} redirected to a login page ({host}).",
                    hint="This service needs Cl@ve or an interactive login. Certificate-only access is not available for it.",
                )
            if host not in self.hosts:
                raise RemoteError(f"{url} redirected outside the allowlist to {host}.", hint="Report the URL so the provider can be updated.")
            url, method, kwargs = target, "GET", {}
        raise RemoteError(f"Too many redirects from {url}.")

    def get_page(self, url: str) -> Any:
        return self.parse(self.request("GET", url))

    def parse(self, response: httpx.Response) -> Any:
        content_type = response.headers.get("content-type", "")
        if "html" in content_type:
            return {"status": response.status_code, **html_to_page(decode_body(response), str(response.url))}
        if "json" in content_type:
            return response.json()
        if content_type.startswith("text/"):
            return {"status": response.status_code, "url": str(response.url), "text": response.text}
        name = urlparse(str(response.url)).path.rsplit("/", 1)[-1] or None
        return Binary(response.content, content_type or "application/octet-stream", name)

    # -- doctor --------------------------------------------------------------

    def doctor(self, online: bool = False) -> list[Check]:
        try:
            info = self.certificate.describe()
        except ConfigError as exc:
            return [Check("certificate", False, exc.message, exc.hint)]
        days = info["days_left"]
        checks = [
            Check("certificate", True, f"{info['holder']} ({info['issuer']})"),
            Check(
                "certificate_expiry",
                days > 0,
                f"expires {info['not_after']} ({days} days)",
                "Renew the certificate at the FNMT." if days <= 30 else "",
            ),
        ]
        if online and self.probe_url:
            try:
                response = self.request("GET", self.probe_url)
                checks.append(Check("mtls", True, f"{self.probe_url} -> HTTP {response.status_code}"))
            except Exception as exc:  # report, do not crash doctor
                checks.append(Check("mtls", False, str(exc), getattr(exc, "hint", "")))
        return checks

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
