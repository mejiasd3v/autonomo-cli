"""Seguridad Social sede apps ("Prosa", sp.seg-social.es).

Prosa pages ship their data as XML inside <script id="xml" type="text/plain">
and render it in the browser with an XSL stylesheet. The XML is the source of
truth, so this module reads it directly:

* ARQ: session plumbing (ticket, front-end URL, jsessionid) and MESSAGES.
* Everything else under SPM: the application data, returned as JSON.

A Prosa form post goes to SPM.URLFRONTEND + SPM.IDSESSION with the ticket,
fixed SPM.* fields, the form fields and the pressed button (SPM.ACC.<NAME>).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from ..core.errors import RemoteError

_XML_RE = re.compile(r'<script id="xml" type="text/plain">(.*?)</script>', re.S)
_XSL_RE = re.compile(r'id="xslUri" href="([^"]+)"')
# Header, analytics and framework nodes that carry no application data.
_NOISE = {"ARQ", "DatosCabecera", "informacionAplicacion", "ARQ.ANALYTICS", "ARQ.ICORPORATIVA"}


@dataclass
class ProsaPage:
    view: str  # stylesheet path: identifies the screen
    data: dict[str, Any]
    messages: list[dict[str, str]] = field(default_factory=list)
    arq: dict[str, str] = field(default_factory=dict)

    def form_url(self, host: str) -> str:
        return f"https://{host}{self.arq['SPM.URLFRONTEND']}{self.arq.get('SPM.IDSESSION', '')}"

    def form_base(self) -> dict[str, str]:
        return {
            "ARQ.SPM.TICKET": self.arq["SPM.TICKET"],
            "SPM.CONTEXT": self.arq.get("SPM.CONTEXT", "internet"),
            "ARQ.SPM.OUT": "XML_STYLESHEET",
            "ES_FW4": "1",
            "SPM.ISPOPUP": self.arq.get("SPM.ISPOPUP", "0"),
            "ARQ.SPM.IDIOMA": self.arq.get("SPM.LANGUAGE", "ES"),
            "SPM.HAYJS": "1",
        }


def is_prosa(page: str) -> bool:
    return bool(_XML_RE.search(page))


def parse(page: str) -> ProsaPage:
    m = _XML_RE.search(page)
    if not m:
        raise RemoteError("Expected a Seguridad Social sede page with embedded data, got something else.")
    try:
        root = ET.fromstring(m.group(1).strip().lstrip("﻿"))
    except ET.ParseError as exc:
        raise RemoteError(f"Could not read the sede page data: {exc}") from exc
    spm = root.find("SPM")
    if spm is None:
        raise RemoteError("Sede page without SPM data.")
    arq_node = spm.find("ARQ")
    arq: dict[str, str] = {}
    messages: list[dict[str, str]] = []
    if arq_node is not None:
        for child in arq_node:
            if child.tag == "MESSAGES":
                messages = [
                    {"type": (msg.findtext("TIPO") or "").strip(), "text": " ".join((msg.findtext("TEXTO") or "").split())}
                    for msg in child.findall("MESSAGE")
                ]
            elif len(child) == 0:
                arq[child.tag] = (child.text or "").strip()
    data = {child.tag: to_json(child) for child in spm if child.tag not in _NOISE}
    view = _XSL_RE.search(page)
    return ProsaPage(view=view.group(1) if view else "", data=data, messages=messages, arq=arq)


def to_json(node: ET.Element) -> Any:
    if len(node) == 0:
        return (node.text or "").strip()
    out: dict[str, Any] = {}
    for child in node:
        value = to_json(child)
        if child.tag in out:
            if not isinstance(out[child.tag], list):
                out[child.tag] = [out[child.tag]]
            out[child.tag].append(value)
        else:
            out[child.tag] = value
    return out


def as_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    return value if isinstance(value, list) else [value]
