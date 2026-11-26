"""Convert AEAT's "Diseño de registro de datos fiscales" Excel into a JSON layout.

Source (one per fiscal year), from AEAT Desarrolladores > IRPF > Modelo 100 > Ejercicio YYYY:
  https://www.agenciatributaria.es/static_files/AEAT_Desarrolladores/EEDD/Modelo_100/2025/2025_Datos_Fiscales_EEDD.xlsx

Usage (openpyxl is only needed here, not at runtime):
  uv run --with openpyxl python scripts/build_datos_fiscales_layout.py FILE.xlsx YEAR

Writes src/autonomo/providers/data/datos_fiscales/YEAR.json. Review the diff:
the field "kind" is inferred (amount, decimal, date, text) and drives parsing.
"""

from __future__ import annotations

import json
import re
import sys
import unicodedata
from pathlib import Path

import openpyxl

OUT_DIR = Path(__file__).resolve().parents[1] / "src/autonomo/providers/data/datos_fiscales"
NUMBERS = {"uno": 1, "un": 1, "dos": 2, "tres": 3, "cuatro": 4, "cinco": 5, "seis": 6, "siete": 7, "ocho": 8, "nueve": 9, "diez": 10}
NOT_AMOUNT = re.compile(
    r"nif|c[oó]digo|fecha|justificante|referencia|n[uú]mero|identific|iban|swift|tel[eé]f|postal|a[nñ]o|ejercicio|"
    r"clave|delegaci|per[ií]odo|modelo|tipo|marca|porcentaje|coeficiente|grado|d[ií]as|meses|situaci|"
    r"provincia|municipio|pa[ií]s|comunidad|nombre|apellido|domicilio|sexo|estado|subtipo|reservad|orden|indicador",
    re.I,
)
AMOUNT = re.compile(
    r"importe|retenc|percepc|rendimiento|rdto|gasto|ingreso|cuota|valor|regulariz|cantidad|base|reducc|saldo|"
    r"amortiz|deducc|inter[eé]s|aportac|subvenc|ganancia|p[eé]rdida|prima|capital|retribuc|dividend|pago|"
    r"precio|renta|cotizac|minorac|adquisici|transmisi|exceso|ayuda|prestac|pensi|premio|volumen|total|devol",
    re.I,
)
SPECIAL = {
    "Registro de Cabecera": ("0", "DDFF", "Cabecera"),
    "Fecha de proceso": ("1", "", "Fecha de proceso"),
    "Registro de cierre": ("9", "99", "Cierre"),
}


def slug(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def kind(name: str, length: int, desc: str) -> dict:
    if m := re.search(r"(\w+) enteros? y (\w+) decimal", desc, re.I):
        places = NUMBERS.get(m.group(2).lower())
        if places:
            return {"kind": "decimal", "places": places}
    if "AAAAMMDD" in desc.upper() or (length == 8 and re.match(r"(\d+_)?fecha", slug(name))):
        return {"kind": "date"}
    if "céntimos" in desc or "centimos" in desc:
        return {"kind": "amount"}
    if length >= 8 and AMOUNT.search(name) and not NOT_AMOUNT.search(name):
        return {"kind": "amount"}
    return {"kind": "text"}


def build(xlsx: Path, year: int) -> dict:
    wb = openpyxl.load_workbook(xlsx, read_only=True, data_only=True)
    records: dict[str, dict] = {}
    for ws in wb.worksheets:
        title = ws.title.strip()
        if title in SPECIAL:
            rtype, code, label = SPECIAL[title]
        elif " - " in title:
            code, label = (part.strip() for part in title.split(" - ", 1))
            rtype = ""
        else:
            continue
        fields = []
        for row in ws.iter_rows(values_only=True, min_row=1):
            if len(row) < 7 or not str(row[2] or "").strip().isdigit() or str(row[2]).strip() == "0":
                continue
            name, pos, length, desc = str(row[3] or "").strip(), row[4], row[5], str(row[6] or "")
            if not name or not str(pos).isdigit() or not str(length).isdigit():
                continue
            if name.lower() == "tipo" and int(pos) == 1:
                if m := re.search(r"'(\d)'", desc):
                    rtype = rtype or m.group(1)
                continue
            if name.lower().startswith("c") and "digo" in name.lower() and int(pos) == 2:
                continue
            if "reservad" in name.lower():
                continue
            key = slug(name)
            if any(f["name"] == key for f in fields):
                # Some records repeat a label (2025 DOM: two "Fecha de modificación"): keep both.
                key = f"{key}_pos{int(pos)}"
            fields.append({"name": key, "label": name, "pos": int(pos), "len": int(length), **kind(name, int(length), desc)})
        if not fields and title not in SPECIAL:
            continue
        records[code] = {"type": rtype, "title": label, "fields": fields}
    return {"year": year, "source": xlsx.name, "records": records}


def main() -> None:
    xlsx, year = Path(sys.argv[1]), int(sys.argv[2])
    layout = build(xlsx, year)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{year}.json"
    out.write_text(json.dumps(layout, ensure_ascii=False, indent=1) + "\n")
    print(f"{out}: {len(layout['records'])} record types")


if __name__ == "__main__":
    main()
