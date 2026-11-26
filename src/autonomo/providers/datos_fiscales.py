"""Parser for the AEAT "datos fiscales" fixed-width file (Renta / IRPF).

The record layouts come from AEAT's official Excel, converted to JSON by
scripts/build_datos_fiscales_layout.py (one file per fiscal year in
data/datos_fiscales/). Amounts are stored in cents in the file; the parser
returns euros.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from functools import cache
from importlib import resources
from typing import Any

from ..core.certificate import mask_ids

LAYOUT_PACKAGE = "autonomo.providers.data.datos_fiscales"
MASKED_FIELDS = {"iban"}


@cache
def available_layouts() -> tuple[int, ...]:
    files = resources.files(LAYOUT_PACKAGE).iterdir()
    return tuple(sorted(int(f.name[:4]) for f in files if re.fullmatch(r"\d{4}\.json", f.name)))


@cache
def load_layout(year: int) -> dict[str, Any]:
    return json.loads(resources.files(LAYOUT_PACKAGE).joinpath(f"{year}.json").read_text(encoding="utf-8"))


def pick_layout(year: int) -> tuple[dict[str, Any], list[str]]:
    years = available_layouts()
    if year in years:
        return load_layout(year), []
    older = [y for y in years if y < year]
    chosen = older[-1] if older else years[0]
    return load_layout(chosen), [
        f"No record layout for {year}; parsed with the {chosen} layout. New or changed fields may be wrong or missing. "
        f"Add data/datos_fiscales/{year}.json with scripts/build_datos_fiscales_layout.py."
    ]


def parse(content: str, year: int, mask: bool = True) -> dict[str, Any]:
    layout, warnings = pick_layout(year)
    records = layout["records"]
    codes = sorted((c for c, r in records.items() if r["type"] in ("2", "3")), key=len, reverse=True)
    grouped: dict[str, dict[str, Any]] = {}
    unknown: list[str] = []
    fecha_proceso = None

    for line in content.splitlines():
        if not line.strip():
            continue
        kind = line[0]
        if kind in ("0", "9"):
            continue
        if kind == "1":
            fecha_proceso = _date(line[51:59])
            continue
        code = _match_code(line[1:8], codes)
        if code is None:
            unknown.append(line[:8])
            continue
        spec = records[code]
        item = _fields(line, spec["fields"], mask)
        group = grouped.setdefault(code, {"code": code, "title": spec["title"], "section": "personal" if kind == "3" else "fiscal", "items": []})
        group["items"].append(item)

    if unknown:
        warnings.append(f"{len(unknown)} line(s) with unknown record codes: {sorted(set(unknown))}")
    return {
        "year": year,
        "layout": f"{layout['year']} ({layout['source']})",
        "fecha_proceso": fecha_proceso,
        "units": "Amounts in euros (the file stores cents). Decimals and dates already converted.",
        "records": list(grouped.values()),
        "warnings": warnings,
    }


def _match_code(raw: str, codes: list[str]) -> str | None:
    for code in codes:
        if raw.startswith(code) and raw[len(code):].strip().isdigit():
            return code
    return None


def _fields(line: str, fields: list[dict[str, Any]], mask: bool) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field in fields:
        raw = line[field["pos"] - 1 : field["pos"] - 1 + field["len"]]
        value = _convert(raw, field)
        if value is None:
            continue
        if mask and isinstance(value, str):
            value = _mask(field["name"], value)
        out[field["name"]] = value
    return out


def _convert(raw: str, field: dict[str, Any]) -> Any:
    text = raw.strip()
    if not text:
        return None
    kind = field["kind"]
    if kind == "amount":
        return _number(text, 2)
    if kind == "decimal":
        return _number(text, field.get("places", 2))
    if kind == "date":
        return _date(text)
    return text


def _number(text: str, places: int) -> Any:
    sign = 1
    if text[0] in "-N":  # AEAT files mark negatives with N or -
        sign, text = -1, text[1:]
    if not text.isdigit():
        return text  # unexpected format: keep raw rather than guess
    return float(sign * Decimal(int(text)).scaleb(-places))


def _date(text: str) -> str | None:
    text = text.strip()
    if not text.isdigit() or len(text) != 8 or set(text) == {"0"}:
        return None
    return f"{text[:4]}-{text[4:6]}-{text[6:]}"


def _mask(name: str, value: str) -> str:
    if name in MASKED_FIELDS and len(value) > 4:
        return "*" * (len(value) - 4) + value[-4:]
    return mask_ids(value) if "nif" in name else value
