"""Agencia Tributaria (AEAT), read-only, with the digital certificate (mTLS).

www1.agenciatributaria.gob.es authenticates at the TLS layer: no Cl@ve, no
browser. Without a certificate it redirects to an error page.

Legal note: opening the content of a notification counts as "comparecencia".
It marks the notification as received and starts legal deadlines. This
provider only reads the notification list and blocks every other URL of the
notifications application (GNNO).
"""

from __future__ import annotations

import datetime as dt
from typing import Any
from urllib.parse import unquote, urlparse

from ..core.config import setting
from ..core.errors import ConfigError, RemoteError, UsageError
from ..core.http import QUERY
from ..core.provider import Param
from . import datos_fiscales
from ._cert_portal import CertPortal, Service

WWW1 = "https://www1.agenciatributaria.gob.es"
NOTIFICATIONS_APP = "/wlpl/GNNO-"
NOTIFICATIONS_LIST = f"{WWW1}/wlpl/GNNO-JDIT/ResumenInteresados"
DEUDAS_URL = f"{WWW1}/wlpl/SRVO-JDIT/ConsultaDdas"

# Error texts from the datos fiscales spec (Anexo II). The service answers 200 with them.
DATOS_FISCALES_ERRORS = (
    "Es obligatorio el Nif",
    "Error en Parámetro de entrada",
    "Existen problemas en la Identificación",
    "No se ha podido descargar",
    "No está autorizado a este Trámite",
    "Error de Seguridad",
    "Por razones técnicas",
)


def last_fiscal_year() -> int:
    return dt.date.today().year - 1


YEAR = Param("year", "Ejercicio fiscal (por defecto, el año anterior)")


class AEAT(CertPortal):
    name = "aeat"
    title = "Agencia Tributaria"
    description = "Sede de la AEAT con certificado digital: deudas, alertas, notificaciones no leídas, últimos accesos, datos fiscales, domicilio fiscal."
    hosts = (
        "www1.agenciatributaria.gob.es",
        "www2.agenciatributaria.gob.es",
        "sede.agenciatributaria.gob.es",
    )
    probe_url = f"{WWW1}/wlpl/IIIC-ALER/SvObtAlertas"
    services = (
        Service(
            "datos-fiscales",
            "Datos fiscales de Renta en JSON: pagos fraccionados (130), cotizaciones RETA, rendimientos, retenciones, inmuebles, préstamos, donaciones, familia...",
            WWW1 + "/wlpl/DFPA-D182/SvDesDF{yy}Pei",
            params=(
                YEAR,
                Param("personales", "S: datos fiscales y personales (defecto). N: solo fiscales"),
                Param("formato", "json (defecto) o raw: el fichero oficial de ancho fijo sin procesar"),
                Param("mascara", "si (defecto): oculta NIF e IBAN. no: los muestra completos"),
            ),
            status="stable",
            note="Verificado para 2024 y 2025. Importes en euros",
        ),
        Service(
            "domicilio-ratificado",
            "Indica si el domicilio fiscal está ratificado para la Renta (JSON oficial)",
            WWW1 + "/wlpl/TOAG-JDIT/IsRatificadoExJson",
            params=(YEAR,),
            status="stable",
        ),
        Service(
            "deudas",
            "Deudas pendientes con la AEAT (consulta; nunca paga ni aplaza)",
            DEUDAS_URL,
            status="stable",
        ),
        Service(
            "notificaciones",
            "Resumen de notificaciones y comunicaciones no leídas (no abre ninguna, para no producir comparecencia)",
            NOTIFICATIONS_LIST,
            status="stable",
        ),
        Service(
            "alertas",
            "Mis alertas: avisos personales de la AEAT",
            WWW1 + "/wlpl/IIIC-ALER/SvObtAlertas",
            status="stable",
        ),
        Service(
            "ultimos-accesos",
            "Mis últimos accesos: fecha, modo de autenticación y canal de cada acceso a la sede",
            WWW1 + "/wlpl/ADHT-AUTH/UltimasConexionesW",
            status="stable",
        ),
    )

    def nif(self) -> str:
        nif = setting(self.settings, "nif", "AUTONOMO_NIF") or self.certificate.nif()
        if not nif:
            raise ConfigError("Cannot find the NIF in the certificate.", hint="Set `nif = ...` under [aeat] or AUTONOMO_NIF.")
        return str(nif).upper()

    def check_host(self, url: str) -> None:
        super().check_host(url)
        path = unquote(urlparse(url).path).upper()
        if path.startswith(NOTIFICATIONS_APP.upper()) and url.split("#")[0] != NOTIFICATIONS_LIST:
            raise UsageError(
                "Blocked: this URL can open a notification. Opening it counts as legal receipt (comparecencia) and starts deadlines.",
                hint="Use `autonomo get aeat notificaciones` for the list. Open notifications yourself in the sede.",
            )

    def fetch_service(self, service: Service, params: dict[str, str]) -> Any:
        if service.name == "datos-fiscales":
            return self._datos_fiscales(params)
        if service.name == "domicilio-ratificado":
            return self._domicilio_ratificado(params)
        if service.name == "deudas":
            return self._deudas()
        return super().fetch_service(service, params)

    def _year(self, params: dict[str, str]) -> int:
        raw = params.get("year") or str(last_fiscal_year())
        if not raw.isdigit() or not 2015 <= int(raw) <= dt.date.today().year:
            raise UsageError(f"Invalid year '{raw}'.")
        return int(raw)

    def _datos_fiscales(self, params: dict[str, str]) -> dict[str, Any]:
        year = self._year(params)
        personales = params.get("personales", "S").upper()
        if personales not in ("S", "N"):
            raise UsageError("personales must be S or N.")
        url = f"{WWW1}/wlpl/DFPA-D182/SvDesDF{year % 100:02d}Pei"
        response = self.request("GET", url, params={"nif": self.nif(), "pdp": personales})
        text = response.text
        if "html" in response.headers.get("content-type", "") or any(e in text[:500] for e in DATOS_FISCALES_ERRORS):
            raise RemoteError(
                f"AEAT did not return the datos fiscales file for {year}.",
                hint="Datos fiscales exist only during the Renta campaign, for the holder of the certificate.",
                body=text[:1000],
            )
        formato = params.get("formato", "json").lower()
        if formato == "raw":
            return {"year": year, "lines": len(text.splitlines()), "content": text}
        if formato != "json":
            raise UsageError("formato must be json or raw.")
        mascara = params.get("mascara", "si").lower()
        if mascara not in ("si", "sí", "no"):
            raise UsageError("mascara must be si or no.")
        return datos_fiscales.parse(text, year, mask=mascara != "no")

    def _deudas(self) -> Any:
        # The page is a query form; "Aceptar" posts it back. Same fields as the browser sends.
        self.request("GET", f"{DEUDAS_URL}?faccion=CONS_DDAS")
        response = self.request(
            "POST",
            DEUDAS_URL,
            data={"fnif": self.nif(), "faccion": "CONS_DDAS", "flistadoselecc": "", "ACEPTAR": "Aceptar"},
            extensions={QUERY: True},  # pure query, allowed by the read-only guard
        )
        page = self.parse(response)
        # Drop links into payment and deferral flows: agents must not follow them.
        page["links"] = []
        return page

    def _domicilio_ratificado(self, params: dict[str, str]) -> dict[str, Any]:
        year = self._year(params)
        response = self.request(
            "POST",
            f"{WWW1}/wlpl/TOAG-JDIT/IsRatificadoExJson",
            data={"EJERCICIO": str(year), "NIF": self.nif()},
            extensions={QUERY: True},  # pure query, allowed by the read-only guard
        )
        data = response.json()
        if data.get("status") != "OK":
            raise RemoteError(f"AEAT: {data.get('mensaje', 'unknown error')}", body=response.text[:1000])
        return {"year": year, **data.get("respuesta", {})}
