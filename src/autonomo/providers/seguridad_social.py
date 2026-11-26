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
from ..core.errors import RemoteError
from ..core.http import QUERY
from ..core.provider import Check, FetchOptions
from ._cert_portal import CertPortal, Service, decode_body

PORTAL = "https://portal.seg-social.gob.es"
IMPORTASS = f"{PORTAL}/wps/myportal/importass/importass"
PERSONAL = f"{IMPORTASS}/personal/"
IDP_CHOOSE_CERT = "https://idp.seg-social.es/PGIS/Login?seleccion=IPCE"
MAX_LOGIN_STEPS = 10

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
        Service("recibos", "Historial de recibos de autónomo: importe, desglose, fecha de cargo y referencia (año en curso)", f"{IMPORTASS}/tramites/historialRecibosRETA", status="stable"),
        Service("vida-laboral", "Vida laboral completa: empresas y regímenes, fechas de alta y baja, días cotizados", f"{IMPORTASS}/tramites/datosvidalaboral/inicio", status="stable"),
        Service("bases-cotizacion", "Bases de cotización por mes (primera página, 12 meses más recientes)", f"{IMPORTASS}/tramites/informebases/inicio", status="stable"),
        Service("regularizacion", "Regularización anual de cuotas de años anteriores: resultado por año (a ingresar o a devolver)", f"{IMPORTASS}/tramites/regularizacionCuotasAnyosAnteriores", status="stable"),
        Service("avisos", "Avisos de Importass, leídos y no leídos (no son notificaciones oficiales)", f"{IMPORTASS}/tramites/avisosComunicaciones/", status="stable"),
        Service("expedientes", "Expedientes y solicitudes presentados ante la TGSS", f"{IMPORTASS}/tramites/consultaTramitesConAutenticacion", status="stable"),
    )

    def __init__(self, settings: dict[str, Any], transport: httpx.BaseTransport | None = None):
        super().__init__(settings, transport)
        self._logged_in = False

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
        if resource != "certificate":
            self.login()
        return super().fetch(resource, params, options)

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
