"""HTTP layer with a read-only guard.

Every provider gets its client from `make_client`. The transport refuses any
method that can change remote state (POST, PUT, PATCH, DELETE) unless:

* the request is a pure query and the provider marks it with
  `extensions={QUERY: True}` (for example a SOAP "consulta" that must be POST), or
* the code runs inside `writes_unlocked()`. Only a future, explicitly
  confirmed write command may enter that block.

The guard sits below the providers, so a provider bug cannot write by mistake.
"""

from __future__ import annotations

import contextlib
import contextvars
import ssl
import time
from collections.abc import Iterator

import certifi
import httpx

from .. import __version__
from .errors import ReadOnlyViolation, RemoteError

QUERY = "autonomo.read_only_query"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
USER_AGENT = f"autonomo-cli/{__version__}"

STATUS_HINTS = {
    401: "Credentials rejected. Run `autonomo doctor --online`.",
    403: "No permission: missing scope on the API key, wrong company, or certificate not authorized for this service.",
    404: "Wrong id or path, or the resource belongs to another company.",
}

_writes_unlocked: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "autonomo_writes_unlocked", default=False
)


@contextlib.contextmanager
def writes_unlocked() -> Iterator[None]:
    token = _writes_unlocked.set(True)
    try:
        yield
    finally:
        _writes_unlocked.reset(token)


class ReadOnlyTransport(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport):
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        method = request.method.upper()
        if method not in SAFE_METHODS and not request.extensions.get(QUERY) and not _writes_unlocked.get():
            raise ReadOnlyViolation(
                f"Blocked {method} {request.url}: autonomo runs in read-only mode.",
                hint="Write operations are not enabled in this version.",
            )
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


def default_ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=certifi.where())


def make_client(
    *,
    base_url: str = "",
    headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = 30.0,
    follow_redirects: bool = True,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    """Build a guarded client. `transport` is for tests (httpx.MockTransport)."""
    inner = transport or httpx.HTTPTransport(verify=ssl_context or default_ssl_context(), retries=1)
    return httpx.Client(
        base_url=base_url,
        headers={"User-Agent": USER_AGENT, **(headers or {})},
        transport=ReadOnlyTransport(inner),
        timeout=timeout,
        follow_redirects=follow_redirects,
    )


def send(client: httpx.Client, method: str, url: str, *, max_rate_retries: int = 3, **kwargs) -> httpx.Response:
    """Send a request, wait on HTTP 429, and turn HTTP errors into RemoteError."""
    for attempt in range(max_rate_retries + 1):
        try:
            response = client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise RemoteError(f"{method} {url} failed: {exc}", hint=_network_hint(exc)) from exc
        if response.status_code == 429 and attempt < max_rate_retries:
            time.sleep(_retry_delay(response))
            continue
        break
    if response.is_error:
        raise RemoteError(
            f"{method} {response.request.url} returned HTTP {response.status_code}.",
            hint=STATUS_HINTS.get(response.status_code, ""),
            status=response.status_code,
            body=response.text[:2000],
        )
    return response


def _retry_delay(response: httpx.Response) -> float:
    for header in ("Retry-After", "X-RateLimit-Reset"):
        value = response.headers.get(header)
        if value and value.isdigit():
            seconds = int(value)
            # X-RateLimit-Reset can be an epoch timestamp.
            if seconds > 10_000_000:
                seconds = int(seconds - time.time())
            return float(min(max(seconds, 1), 60))
    return 5.0


def _network_hint(exc: httpx.HTTPError) -> str:
    text = str(exc).lower()
    if "certificate" in text or "ssl" in text or "handshake" in text:
        return "TLS failed. Check the client certificate (autonomo doctor) and that it is not expired or revoked."
    return ""
