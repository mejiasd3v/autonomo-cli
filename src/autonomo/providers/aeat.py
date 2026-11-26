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
from ..core.provider import FetchOptions, Param
from ..core.redact import mask_text, mask_tree
from . import datos_fiscales, verifactu
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
    description = "Sede de la AEAT con certificado digital: deudas, alertas, notificaciones no leídas, últimos accesos, datos fiscales, domicilio fiscal, registros Verifactu."
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
            "verifactu",
            "Registros de facturación Verifactu que constan en AEAT (ConsultaFactuSistemaFacturacion; solo consulta, nunca da de alta ni anula)",
            verifactu.ENDPOINT,
            params=(
                Param("rol", "emitidas (defecto): facturas que expediste. recibidas: facturas en las que eres destinatario"),
                Param("year", "Ejercicio (por defecto, el de desde/hasta o el actual)"),
                Param("mes", "Mes 01-12. Sin mes: cada mes del año (hasta el actual), una consulta por mes"),
                Param("numserie", "Serie y número de la factura"),
                Param("desde", "Fecha de expedición desde, YYYY-MM-DD"),
                Param("hasta", "Fecha de expedición hasta, YYYY-MM-DD"),
            ),
            note="Sin verificar con datos reales",
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

    def holder_name(self) -> str:
        return str(setting(self.settings, "nombre", "AUTONOMO_NOMBRE") or self.certificate.holder_name()).upper()

    def fetch(self, resource: str, params: dict[str, str], options: FetchOptions) -> Any:
        if resource == "verifactu":
            return self._verifactu(params, options.all_pages)
        return super().fetch(resource, params, options)

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

    # -- verifactu -----------------------------------------------------------

    def _verifactu(self, params: dict[str, str], all_pages: bool) -> dict[str, Any]:
        rol = params.get("rol", "emitidas").lower()
        if rol not in verifactu.ROLES:
            raise UsageError("rol must be emitidas or recibidas.")
        desde, hasta = _iso_date(params, "desde"), _iso_date(params, "hasta")
        today = dt.date.today()
        raw_year = params.get("year") or str((desde or hasta or today).year)
        if not raw_year.isdigit() or not 2000 <= int(raw_year) <= today.year:
            raise UsageError(f"Invalid year '{raw_year}'.")
        year = int(raw_year)
        if any(d and d.year != year for d in (desde, hasta)) or (desde and hasta and desde > hasta):
            raise UsageError(f"desde and hasta must be in {year}, with desde <= hasta.")
        numserie = params.get("numserie") or None
        if numserie and len(numserie) > 60:
            raise UsageError("numserie has at most 60 characters.")

        if params.get("mes"):
            raw = params["mes"]
            if not raw.isdigit() or not 1 <= int(raw) <= 12:
                raise UsageError(f"Invalid mes '{raw}'. Use 01-12.")
            months = [int(raw)]
        else:
            last = today.month if year == today.year else 12
            months = list(range(desde.month if desde else 1, (hasta.month if hasta else last) + 1))

        query = {
            "rol": rol,
            "nif": self.nif(),
            "nombre": self.holder_name(),
            "year": year,
            "numserie": numserie,
            "desde": verifactu.aeat_date(desde.isoformat()) if desde else None,
            "hasta": verifactu.aeat_date(hasta.isoformat()) if hasta else None,
        }
        items: list[dict[str, Any]] = []
        truncated: list[str] = []
        for month in months:
            clave, seen = None, set()
            while True:
                page = self._verifactu_page(verifactu.build_request(month=month, clave=clave, **query))
                items += [{"periodo": f"{year}-{month:02d}", **record} for record in page["records"]]
                if not page["more"]:
                    break
                if not all_pages:
                    truncated.append(f"{year}-{month:02d}")
                    break
                clave = page["clave"]
                cursor = tuple(clave.get(f) for f in verifactu.CURSOR) if isinstance(clave, dict) else ()
                if not all(isinstance(v, str) and v for v in cursor) or len(cursor) != 3 or cursor in seen:
                    raise RemoteError(f"Verifactu said {year}-{month:02d} has more records but gave no new valid ClavePaginacion.")
                seen.add(cursor)
        result: dict[str, Any] = {
            "rol": rol,
            "year": year,
            "periodos": [f"{year}-{m:02d}" for m in months],
            "count": len(items),
            "more": bool(truncated),
            "items": items,
        }
        if truncated:
            result["note"] = f"More records in {', '.join(truncated)}. Repeat with --all."
        return mask_tree(result)

    def _verifactu_page(self, body: bytes) -> dict[str, Any]:
        try:
            response = self.request(
                "POST",
                verifactu.ENDPOINT,
                content=body,
                headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""'},
                extensions={QUERY: True},  # ConsultaFactuSistemaFacturacion only reads
            )
        except RemoteError as exc:
            if fault := verifactu.fault_from_body(exc.body):
                raise RemoteError(f"Verifactu: {fault}", hint=verifactu.FAULT_HINT, status=exc.status) from exc
            raise
        if "xml" not in response.headers.get("content-type", ""):
            raise RemoteError(
                "Verifactu did not return a SOAP response.",
                hint=verifactu.CERT_HINT,
                body=mask_text(response.text[:1000]),
            )
        return verifactu.parse_response(response.content)


def _iso_date(params: dict[str, str], key: str) -> dt.date | None:
    if not (raw := params.get(key)):
        return None
    try:
        return dt.date.fromisoformat(raw)
    except ValueError:
        raise UsageError(f"Invalid {key} '{raw}'. Use YYYY-MM-DD.") from None
