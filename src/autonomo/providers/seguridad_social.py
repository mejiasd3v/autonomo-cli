"""Seguridad Social (TGSS), read-only, through Importass with the digital certificate.

Login (plain HTTP, no browser), verified 2026-11-26:

    Importass /personal  ->  auto-POST form "loginFormSubmit=ACCESO" (action relative to <base href>)
      ->  SAMLRequest  -> idp.seg-social.es/PGIS/Login   (method chooser: IPCE = "DNIe o certificado")
      ->  SAMLRequest  -> ipce.seg-social.es/IPCE/Login  (TLS client certificate is checked here)
      ->  SAMLResponse -> idp.seg-social.es/PGIS/PostLogin
      ->  SAMLResponse -> Importass  ->  302 to /personal with the LtpaToken2 session cookie

Each login POST is a pure authentication step and is marked QUERY for the
read-only guard. Every other POST stays blocked, so Importass forms that change
data (bajas, modificaciones, "informar error") cannot be submitted.

Not covered yet: notificaciones and deudas. Both leave Importass for the sede
(sp.seg-social.es, "Prosa" apps rendered client-side from XML). Opening a
notification there would also count as comparecencia.
"""

from __future__ import annotations

import html
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ..core.certificate import mask_ids
from ..core.errors import RemoteError, UsageError
from ..core.http import QUERY
from ..core.html import html_to_page
from ..core.provider import Check, FetchOptions, Param
from ._cert_portal import CertPortal, Service, decode_body
from .importass import page_position, parse_quota_history

PORTAL = "https://portal.seg-social.gob.es"
IMPORTASS = f"{PORTAL}/wps/myportal/importass/importass"
PERSONAL = f"{IMPORTASS}/personal/"
IDP_CHOOSE_CERT = "https://idp.seg-social.es/PGIS/Login?seleccion=IPCE"
MAX_LOGIN_STEPS = 10
MAX_HISTORY_PAGES = 40
# Search buttons that only filter a list. Any other "accion" (for example
# AC_INFORMAR_ERROR on the bases page) is never submitted.
HISTORY_SEARCH = {"recibos": "AC_BUSCAR_RECIBOS", "bases-cotizacion": "AC_AEIM_BUSCAR"}

_HIDDEN_RE = re.compile(r"<input[^>]*type=[\"']hidden[\"'][^>]*name=[\"']([^\"']+)[\"'][^>]*value=[\"']([^\"']*)", re.I)
_LOGIN_FORM_RE = re.compile(r'<form[^>]*id="P017_login"[^>]*action="([^"]+)"', re.I)
_BASE_RE = re.compile(r'<base href="([^"]+)"', re.I)
# WebSphere portlet state JSON and portlet ids that leak into the text.
_PORTLET_NOISE_RE = re.compile(r'^\{.*\}$|^[A-Z]{4}\d{2}[A-Za-z]+$', re.M)
# NUSS / NAF: 12 digits, sometimes as 28/12345678/90.
_NUSS_RE = re.compile(r"\b(\d{2})[ /]?(\d{8})[ /]?(\d{2})\b")


def _mask(text: str) -> str:
    """Mask NIF/NIE and NUSS so agent transcripts do not carry them."""
    return _NUSS_RE.sub(lambda m: "*" * 10 + m.group(3), mask_ids(text))


class SeguridadSocial(CertPortal):
    name = "seguridad-social"
    title = "Seguridad Social"
    description = "Importass con certificado digital: resumen, recibos de autónomo, vida laboral, bases de cotización, regularización, avisos y expedientes."
    hosts = (
        "portal.seg-social.gob.es",
        "idp.seg-social.es",
        "ipce.seg-social.es",
    )
    # idp.seg-social.es is the Seguridad Social IdP that this provider drives itself.
    login_host_markers = ("clave.gob.es", "pasarela.clave")
    probe_url = PERSONAL
    services = (
        Service("resumen", "Área personal: situación de alta, días cotizados, base actual y próxima cuota con su desglose", PERSONAL, status="stable"),
        Service(
            "recibos",
            "Recibos de autónomo desde 2018: periodo, importe, desglose por contingencia, fecha de cargo y referencia. 12 por página; --all sigue la paginación",
            f"{IMPORTASS}/tramites/historialRecibosRETA",
            params=(Param("desde", "YYYY-MM (opcional)"), Param("hasta", "YYYY-MM (opcional)")),
            status="stable",
        ),
        Service("vida-laboral", "Vida laboral completa: empresas y regímenes, fechas de alta y baja, días cotizados", f"{IMPORTASS}/tramites/datosvidalaboral/inicio", status="stable"),
        Service(
            "bases-cotizacion",
            "Bases de cotización por mes y régimen o empresa. 12 por página; --all sigue la paginación",
            f"{IMPORTASS}/tramites/informebases/inicio",
            params=(Param("desde", "YYYY-MM (opcional)"), Param("hasta", "YYYY-MM (opcional)")),
            status="stable",
        ),
        Service("regularizacion", "Regularización anual de cuotas de años anteriores: resultado por año (a ingresar o a devolver)", f"{IMPORTASS}/tramites/regularizacionCuotasAnyosAnteriores", status="stable"),
        Service("avisos", "Avisos de Importass, leídos y no leídos (no son notificaciones oficiales)", f"{IMPORTASS}/tramites/avisosComunicaciones/", status="stable"),
        Service("expedientes", "Expedientes y solicitudes presentados ante la TGSS", f"{IMPORTASS}/tramites/consultaTramitesConAutenticacion", status="stable"),
    )

    def __init__(self, settings: dict[str, Any], transport: httpx.BaseTransport | None = None):
        super().__init__(settings, transport)
        self._logged_in = False
        self._all_pages = False

    # -- session -------------------------------------------------------------

    def login(self) -> None:
        if self._logged_in:
            return
        response = self.request("GET", PERSONAL)
        for _ in range(MAX_LOGIN_STEPS):
            page = decode_body(response)
            if self._is_personal_area(response, page):
                self._logged_in = True
                return
            response = self._next_login_step(response, page)
        raise RemoteError(
            "Seguridad Social login did not finish.",
            hint="The login flow may have changed. Run `autonomo doctor seguridad-social --online` and report the result.",
        )

    def _is_personal_area(self, response: httpx.Response, page: str) -> bool:
        return urlparse(str(response.url)).hostname == "portal.seg-social.gob.es" and "/wps/myportal/" in str(response.url) and not _LOGIN_FORM_RE.search(page)

    def _next_login_step(self, response: httpx.Response, page: str) -> httpx.Response:
        if "seleccion=IPCE" in page:
            return self._post(IDP_CHOOSE_CERT, {})
        fields = dict(_HIDDEN_RE.findall(page))
        if {"SAMLRequest", "SAMLResponse"} & fields.keys():
            action = re.search(r'<form[^>]*name="redirectForm"[^>]*action="([^"]+)"', page) or re.search(r'<form[^>]*id="P017_login"[^>]*action="([^"]+)"', page)
            if not action:
                raise RemoteError("SAML step without a form action.")
            return self._post(html.unescape(action.group(1)), fields)
        if form := _LOGIN_FORM_RE.search(page):
            base = _BASE_RE.search(page)
            action = urljoin(base.group(1) if base else str(response.url), html.unescape(form.group(1)).split("#")[0])
            return self._post(action, {"loginFormSubmit": "ACCESO"})
        raise RemoteError(
            f"Unexpected page during Seguridad Social login: {urlparse(str(response.url)).hostname}{urlparse(str(response.url)).path}",
            hint="The certificate may have been rejected, or the login flow changed.",
        )

    def _post(self, url: str, data: dict[str, str]) -> httpx.Response:
        # Authentication handshake only: allowed through the read-only guard.
        return self.request("POST", url, data=data, extensions={QUERY: True})

    # -- fetch ---------------------------------------------------------------

    def fetch(self, resource: str, params: dict[str, str], options: FetchOptions) -> Any:
        self._all_pages = options.all_pages
        if resource != "certificate":
            self.login()
        return super().fetch(resource, params, options)

    def fetch_service(self, service: Service, params: dict[str, str]) -> Any:
        if service.name in HISTORY_SEARCH:
            return self._history(service, params)
        return super().fetch_service(service, params)

    def _history(self, service: Service, params: dict[str, str]) -> dict[str, Any]:
        """Receipts or bases as records. Search form only when a range is given."""
        response = self.request("GET", service.url)
        page = decode_body(response)
        searched = bool(params.get("desde") or params.get("hasta"))
        if searched:
            response = self._search(response, page, HISTORY_SEARCH[service.name], params)
            page = decode_body(response)
            found = re.search(r"(\d+)\s+resultados?\s+en el periodo", html_to_page(page, str(response.url))["text"])
            if not found or found.group(1) == "0":
                # With no matches the portal shows the default list instead: do not return it.
                return {"items": [], "count": 0, "note": "No entries in that period."}
        items = parse_quota_history(page)
        position = page_position(html_to_page(page, str(response.url))["text"])
        pages = 1
        while self._all_pages and position and position[0] < position[1] and pages < MAX_HISTORY_PAGES:
            link = self._next_page_link(response, page)
            if not link:
                break
            response = self.request("GET", link)
            page = decode_body(response)
            items += parse_quota_history(page)
            position = page_position(html_to_page(page, str(response.url))["text"])
            pages += 1
        for item in items:
            if details := item.get("details"):
                item["details"] = {k: _mask(v) for k, v in details.items()}
        out: dict[str, Any] = {"items": items, "count": len(items)}
        if position:
            out["page"], out["pages"] = position
            if position[0] < position[1]:
                out["more"] = "Older entries exist. Repeat with --all, or narrow with desde=YYYY-MM hasta=YYYY-MM."
        return out

    def _search(self, response: httpx.Response, page: str, accion: str, params: dict[str, str]) -> httpx.Response:
        form = next((f for f in re.findall(r"<form\b.*?</form>", page, re.S | re.I) if f'value="{accion}"' in f), None)
        if not form:
            raise RemoteError(f"Search form {accion} not found on {response.url}.", hint="The page layout may have changed.")
        action = html.unescape(re.search(r'action="([^"]+)"', form).group(1)).split("#")[0]
        base = _BASE_RE.search(page)
        data = {"accion": accion}
        for side in ("desde", "hasta"):
            if value := params.get(side):
                m = re.fullmatch(r"(\d{4})-(\d{2})", value)
                if not m:
                    raise UsageError(f"{side} must be YYYY-MM.")
                data[f"{side}Anio"], data[f"{side}Mes"] = m.group(1), m.group(2)
        # A filter search changes nothing on the server: allowed as a query.
        return self.request("POST", urljoin(base.group(1) if base else str(response.url), action), data=data, extensions={QUERY: True})

    def _next_page_link(self, response: httpx.Response, page: str) -> str | None:
        m = re.search(r'<a\b[^>]*href="([^"]*accion!PAGINA_SIGUIENTE_[^"]*)"', page)
        if not m:
            return None
        base = _BASE_RE.search(page)
        return urljoin(base.group(1) if base else str(response.url), html.unescape(m.group(1)).split("#")[0])

    def get_page(self, url: str) -> Any:
        page = super().get_page(url)
        if isinstance(page, dict) and "text" in page:
            if page.get("title") == "Iniciar sesión":
                raise RemoteError("Seguridad Social session expired.", hint="Retry the command.")
            text = _PORTLET_NOISE_RE.sub("", page["text"])
            page["text"] = _mask(re.sub(r"\n{2,}", "\n", text).strip())
            for table in page.get("tables", []):
                table["rows"] = [
                    {k: _mask(v) for k, v in row.items()} if isinstance(row, dict) else [_mask(c) for c in row]
                    for row in table["rows"]
                ]
        return page

    def doctor(self, online: bool = False) -> list[Check]:
        checks = super().doctor(online=False)
        if online and all(c.ok for c in checks):
            try:
                self.login()
                checks.append(Check("login", True, "Importass personal area reached with the certificate (IPCE)"))
            except Exception as exc:  # report, do not crash doctor
                checks.append(Check("login", False, str(exc), getattr(exc, "hint", "")))
        return checks
