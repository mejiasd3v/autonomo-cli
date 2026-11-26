"""AEAT Verifactu: query of invoice records (ConsultaFactuSistemaFacturacion).

SOAP 1.1 over mTLS, from the official WSDL
(static_files/.../tikeV1.0/cont/ws/SistemaFacturacion.wsdl). Only the
consulta operation is built here. RegFactuSistemaFacturacion (alta and
anulación of records) is never called.

The query covers one month (PeriodoImputacion) per request and returns up to
10,000 records per page. IndicadorPaginacion=S means more pages: the next
request repeats the filter with the returned ClavePaginacion.
"""

from __future__ import annotations

import datetime as dt
import xml.etree.ElementTree as ET
from typing import Any

from ..core.errors import RemoteError
from ..core.redact import mask_text

ENDPOINT = "https://www1.agenciatributaria.gob.es/wlpl/TIKE-CONT/ws/SistemaFacturacion/VerifactuSOAP"
_BASE = "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
CON = _BASE + "ConsultaLR.xsd"
SUM = _BASE + "SuministroInformacion.xsd"

# Elements with maxOccurs > 1 in RespuestaConsultaLR.xsd / SuministroInformacion.xsd.
REPEATED = frozenset({
    "RegistroRespuestaConsultaFactuSistemaFacturacion",
    "DetalleDesglose",
    "IDDestinatario",
    "IDFacturaRectificada",
    "IDFacturaSustituida",
})

CURSOR = ("IDEmisorFactura", "NumSerieFactura", "FechaExpedicionFactura")
ROLES = {"emitidas": "ObligadoEmision", "recibidas": "Destinatario"}


def aeat_date(value: str) -> str:
    """YYYY-MM-DD -> DD-MM-YYYY (the schema's `fecha` type)."""
    return dt.date.fromisoformat(value).strftime("%d-%m-%Y")


def build_request(
    *,
    rol: str,
    nif: str,
    nombre: str,
    year: int,
    month: int,
    numserie: str | None = None,
    desde: str | None = None,
    hasta: str | None = None,
    clave: dict[str, str] | None = None,
) -> bytes:
    """Envelope for ConsultaFactuSistemaFacturacion. Dates are already DD-MM-YYYY."""

    def sub(parent: ET.Element, ns: str, tag: str, text: str | None = None) -> ET.Element:
        el = ET.SubElement(parent, f"{{{ns}}}{tag}")
        if text is not None:
            el.text = text
        return el

    envelope = ET.Element(f"{{{SOAP}}}Envelope")
    sub(envelope, SOAP, "Header")
    query = sub(sub(envelope, SOAP, "Body"), CON, "ConsultaFactuSistemaFacturacion")

    header = sub(query, CON, "Cabecera")
    sub(header, SUM, "IDVersion", "1.0")
    party = sub(header, SUM, ROLES[rol])
    sub(party, SUM, "NombreRazon", nombre)
    sub(party, SUM, "NIF", nif)

    # Element order follows LRFiltroRegFacturacionType.
    filtro = sub(query, CON, "FiltroConsulta")
    periodo = sub(filtro, CON, "PeriodoImputacion")
    sub(periodo, SUM, "Ejercicio", str(year))
    sub(periodo, SUM, "Periodo", f"{month:02d}")
    if numserie:
        sub(filtro, CON, "NumSerieFactura", numserie)
    if desde or hasta:
        rango = sub(sub(filtro, CON, "FechaExpedicionFactura"), SUM, "RangoFechaExpedicion")
        if desde:
            sub(rango, SUM, "Desde", desde)
        if hasta:
            sub(rango, SUM, "Hasta", hasta)
    if clave:
        key = sub(filtro, CON, "ClavePaginacion")
        for tag in CURSOR:
            sub(key, SUM, tag, clave[tag])

    # The issuer name is the only way to tell received invoices apart once NIFs are masked.
    if rol == "recibidas":
        sub(sub(query, CON, "DatosAdicionalesRespuesta"), CON, "MostrarNombreRazonEmisor", "S")

    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


def parse_response(content: bytes | str) -> dict[str, Any]:
    """RespuestaConsultaFactuSistemaFacturacion as a dict without namespaces.

    Returns {"more", "records", "clave"}. A SOAP Fault becomes RemoteError.
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise RemoteError("Verifactu returned a response that is not XML.", hint=CERT_HINT) from exc
    body = next((el for el in root if _local(el.tag) == "Body"), None)
    payload = body[0] if body is not None and len(body) else None
    if payload is None:
        raise RemoteError("Verifactu returned an empty SOAP body.")
    if _local(payload.tag) == "Fault":
        raise RemoteError(f"Verifactu: {fault_text(payload)}", hint=FAULT_HINT)
    data = _to_dict(payload)
    if not isinstance(data, dict) or _local(payload.tag) != "RespuestaConsultaFactuSistemaFacturacion" or data.get("ResultadoConsulta") not in ("ConDatos", "SinDatos"):
        raise RemoteError(f"Verifactu returned an unexpected response ({_local(payload.tag)}).", hint=CERT_HINT)
    return {
        "more": data.get("IndicadorPaginacion") == "S",
        "records": data.get("RegistroRespuestaConsultaFactuSistemaFacturacion", []),
        "clave": data.get("ClavePaginacion"),
    }


def fault_from_body(body: str) -> str | None:
    """faultstring of a SOAP Fault body (AEAT sends faults with HTTP 500)."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    fault = next((el for el in root.iter() if _local(el.tag) == "Fault"), None)
    return fault_text(fault) if fault is not None else None


def fault_text(fault: ET.Element) -> str:
    texts = {_local(el.tag): (el.text or "").strip() for el in fault.iter()}
    return mask_text(texts.get("faultstring") or texts.get("faultcode") or "SOAP Fault without a message")


CERT_HINT = "Check that the certificate is accepted by AEAT: `autonomo doctor aeat --online`."
FAULT_HINT = (
    "AEAT rejected the query. Codes 4xxx are request errors (NIF or name of the certificate holder, "
    "period, dates). The consulta only covers Verifactu records sent to AEAT."
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _to_dict(el: ET.Element) -> Any:
    children = list(el)
    if not children:
        return (el.text or "").strip()
    out: dict[str, Any] = {}
    for child in children:
        name, value = _local(child.tag), _to_dict(child)
        if name in REPEATED:
            out.setdefault(name, []).append(value)
        elif name in out:
            # Not expected by the schema; keep every value instead of dropping one.
            out[name] = (out[name] if isinstance(out[name], list) else [out[name]]) + [value]
        else:
            out[name] = value
    return out
