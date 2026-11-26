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

Sede apps (sp.seg-social.es, "Prosa"): reached through Importass's redirector
with the same IdP session (SSO). See prosa.py for the page format.
* notificaciones: the list screen only. Signing a notification (SPM.ACC.FIRMARNOT)
  is comparecencia and is never sent.
* deudas: one query step (option 1: by NAF). The later steps that generate a
  payment document are never sent.
"""

from __future__ import annotations

import html
import re
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

import httpx

from ..core.redact import mask_text as _mask, mask_tree as _mask_tree
from ..core.errors import RemoteError, UsageError
from ..core.http import QUERY, safe_url
from ..core.html import html_to_page
from ..core.provider import Check, FetchOptions, Param
from . import prosa
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


SAML_FIELDS = {"SAMLRequest", "SAMLResponse", "RelayState", "allowLegalPerson"}


# The only endpoints a SAML message may be posted to: exact paths, plus the
# Importass subtree (its assertion consumer URL carries per-session portlet state).
SAML_ENDPOINTS = {
    ("idp.seg-social.es", "/PGIS/Login"),
    ("idp.seg-social.es", "/PGIS/PostLogin"),
    ("ipce.seg-social.es", "/IPCE/Login"),
    ("sp.seg-social.es", "/SPAutenticacionClave/PostLogin"),
    ("sp.seg-social.es", "/ProsaInternet/OnlineAccess"),
}
SAML_PREFIX_ENDPOINT = ("portal.seg-social.gob.es", "/wps/portal/importass/")


def _saml_form(page: str) -> tuple[str, dict[str, str]] | None:
    """The one form that carries a SAML message: its action and only its SAML fields."""
    found = []
    for form in re.findall(r"<form\b.*?</form>", page, re.S | re.I):
        fields = {k: html.unescape(v) for k, v in _HIDDEN_RE.findall(form) if k in SAML_FIELDS}
        action = re.search(r'<form\b[^>]*action=["\']([^"\']+)', form, re.I)
        if action and {"SAMLRequest", "SAMLResponse"} & fields.keys():
            found.append((str(httpx.URL(html.unescape(action.group(1)))), fields))
    if not found:
        return None
    if len(found) > 1:
        raise RemoteError("Login page with more than one SAML form.", hint="The login flow changed; refusing to guess.")
    url, fields = found[0]
    parsed = httpx.URL(url)
    allowed = (parsed.host, parsed.path) in SAML_ENDPOINTS or (
        parsed.host == SAML_PREFIX_ENDPOINT[0] and parsed.path.startswith(SAML_PREFIX_ENDPOINT[1])
    )
    if parsed.scheme != "https" or parsed.port is not None or not allowed:
        raise RemoteError(f"SAML message addressed to an unexpected endpoint: {safe_url(url)}")
    return url, fields


class SeguridadSocial(CertPortal):
    name = "seguridad-social"
    title = "Seguridad Social"
    description = "Importass y sede con certificado digital: resumen, recibos, vida laboral, bases, regularización, avisos, expedientes, notificaciones (lista) y deudas."
    hosts = (
        "portal.seg-social.gob.es",
        "idp.seg-social.es",
        "ipce.seg-social.es",
        "sp.seg-social.es",
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
        Service(
            "notificaciones",
            "Notificaciones telemáticas de la Seguridad Social pendientes en la sede (últimos 60 días). Solo la lista: nunca se abren ni firman, para no producir comparecencia",
            f"{PORTAL}/wps/portal/importass/Seguridad/PortalRedirectorN2A?idApp=323",
            status="stable",
        ),
        Service(
            "deudas",
            "Deudas y liquidaciones pendientes con la Seguridad Social (consulta en la sede por NAF; nunca genera documento de pago)",
            f"{PORTAL}/wps/portal/importass/Seguridad/PortalRedirectorN1A?idApp=370&N1&A",
            status="stable",
        ),
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
        if saml := _saml_form(page):
            return self._post(*saml)
        if form := _LOGIN_FORM_RE.search(page):
            base = _BASE_RE.search(page)
            action = urljoin(base.group(1) if base else str(response.url), html.unescape(form.group(1)).split("#")[0])
            return self._post(action, {"loginFormSubmit": "ACCESO"})
        raise RemoteError(
            f"Unexpected page during Seguridad Social login: {urlparse(str(response.url)).hostname}{urlparse(str(response.url)).path}",
            hint="The certificate may have been rejected, or the login flow changed.",
        )

    def check_page(self, url: str) -> None:
        """`page` reads Importass pages only, on every hop: no IdP or sede hosts, no portlet actions."""
        super().check_page(url)
        if urlparse(url).hostname != "portal.seg-social.gob.es" or "accion!" in unquote(url).lower():
            raise UsageError(
                "`page` only reads plain Importass pages (portal.seg-social.gob.es, no portlet actions).",
                hint="Use the named resources; sede apps and actions are reachable only through them.",
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
        if service.name == "notificaciones":
            return self._notificaciones(service)
        if service.name == "deudas":
            return self._deudas(service)
        return super().fetch_service(service, params)

    # -- sede (Prosa) ----------------------------------------------------------

    def _open_sede(self, redirector_url: str) -> tuple[httpx.Response, prosa.ProsaPage]:
        """Importass redirector -> sede app, reusing the IdP session."""
        response = self.request("GET", redirector_url)
        page = decode_body(response)
        link = re.search(r'id="importassPortalRedirectorLinkPage"[^>]*href="\s*([^"]+)"', page)
        base = _BASE_RE.search(page)
        if not link or not base:
            raise RemoteError("Importass did not offer the link to the sede.", hint="The redirector page may have changed.")
        response = self.request("GET", urljoin(base.group(1), html.unescape(link.group(1)).split("#")[0]))
        for _ in range(MAX_LOGIN_STEPS):
            page = decode_body(response)
            if prosa.is_prosa(page):
                return response, prosa.parse(page)
            response = self._next_login_step(response, page)
        raise RemoteError("Could not open the Seguridad Social sede app.")

    def _notificaciones(self, service: Service) -> dict[str, Any]:
        _, page = self._open_sede(service.url)
        if "ListaNotif" not in page.view:
            raise RemoteError(f"Unexpected sede screen: {page.view}", hint="The notifications app may have changed.")
        items = [_mask_tree(n) for n in prosa.as_list(page.data.get("NOTIFICACIONES", {}).get("NOTIFICACION") if isinstance(page.data.get("NOTIFICACIONES"), dict) else None)]
        criteria = page.data.get("CRITERIOS_BUSQUEDA", {})
        return {
            "items": items,
            "count": len(items),
            "window": {"desde": criteria.get("FECHA_DESDE"), "hasta": criteria.get("FECHA_HASTA")} if isinstance(criteria, dict) else None,
            "messages": _mask_tree(page.messages),
            "note": "Pending notifications in the sede's default window. Opening one counts as comparecencia: the user must do it in the sede.",
        }

    def _deudas(self, service: Service) -> dict[str, Any]:
        response, page = self._open_sede(service.url)
        if "IdentificarDocumento" not in page.view:
            raise RemoteError(f"Unexpected sede screen: {page.view}", hint="The debts app may have changed.")
        data = {
            **page.form_base(),
            "OPCION": "1",  # option 1: by identifier
            "TIPO_IDENTIFICADOR": "07",  # NAF
            "IDENTIFICADOR": self._naf(),
            "MES_DESDE": "", "ANYO_DESDE": "", "MES_HASTA": "", "ANYO_HASTA": "",
            "CC6Cotizacion": "", "IP3Identificador": "", "NA5NAF": "", "NIFApoderado": "", "NIFPoderdante": "",
            "SPM.ACC.CONTINUAR": "CONTINUAR",
        }
        # The query step only lists debts; generating a payment document is a later step that is never sent.
        result = self.request("POST", page.form_url("sp.seg-social.es"), data=data, extensions={QUERY: True})
        body = decode_body(result)
        if not prosa.is_prosa(body):
            text = html_to_page(body, str(result.url))["text"]
            raise RemoteError("The sede rejected the debts query.", body=text[:500])
        answer = prosa.parse(body)
        found = "IdentificarDocumento" not in answer.view
        # A new screen means a list of debts; staying on the form with a message means none.
        has_debts = True if found else (False if answer.messages else None)
        return {
            "has_debts": has_debts,
            "messages": _mask_tree(answer.messages),
            "screen": answer.view.rsplit("/", 1)[-1],
            "data": _mask_tree({k: v for k, v in answer.data.items() if k not in {"estado", "NIFApoderado", "NIFPoderdante", "IP3Identificador", "CC2Regimen", "CC6Cotizacion", "NA5NAF", "REGIdentificador", "NIFIdentificador"}}) if found else {},
        }

    def _naf(self) -> str:
        page = decode_body(self.request("GET", PERSONAL))
        m = re.search(r"NUSS\)?:?\s*(?:<[^>]+>\s*)*(\d{2})[ /]?(\d{8})[ /]?(\d{2})", page)
        if not m:
            raise RemoteError("Could not read the NUSS from the Importass personal area.")
        return "".join(m.groups())

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

    def get_page(self, url: str, policy: Any = None) -> Any:
        page = super().get_page(url, policy=policy)
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
