"""Parser for Importass "quota-history" lists: RETA receipts and contribution bases.

Both pages share one markup:
  quota-history__year   -> year
  quota-history__month  -> month
  quota-history__item   -> one entry: item-title, item-amount, and optional
                           breakdown lists (concept amounts, or label/value fields)
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

MONTHS = {m: i for i, m in enumerate(
    ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"], 1
)}


VOID = {"br", "hr", "img", "input", "meta", "link", "source", "wbr", "area", "col", "embed", "param", "track"}


def euros(text: str) -> float | None:
    """'1.633,99 €' -> 1633.99"""
    m = re.search(r"-?[\d.]+,\d{2}", text)
    return float(m.group(0).replace(".", "").replace(",", ".")) if m else None


class _QuotaHistory(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[dict[str, Any]] = []
        self.year: str | None = None
        self.month: str | None = None
        self._capture: str | None = None  # which field the current text belongs to
        self._buf: list[str] = []
        self._stack: list[str | None] = []  # capture target opened by each tag
        self._li: dict[str, str] | None = None

    def handle_starttag(self, tag, attrs):
        if tag in VOID:
            return
        cls = dict(attrs).get("class") or ""
        target = None
        if "quota-history__year" in cls:
            target = "year"
        elif "quota-history__month" in cls:
            target = "month"
        elif "quota-history__item-title" in cls:
            self.items.append({"year": self.year, "month": self.month, "concepts": {}, "fields": {}})
            target = "title"
        elif "quota-history__item-amount" in cls:
            target = "amount"
        elif "quota-history__breakdown-amount" in cls:
            target = "li_amount"
        elif tag == "p" and self._li is not None:
            target = "li_label" if "encabezadoLista" in cls else "li_value"
        if tag == "li":
            self._li = {}
        if target:
            self._capture, self._buf = target, []
        self._stack.append(target)

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        target = self._stack.pop() if self._stack else None
        if target and target == self._capture:
            self._store(target, " ".join("".join(self._buf).split()))
            self._capture = None
        if tag == "li" and self._li is not None:
            self._close_li()

    def handle_data(self, data):
        if self._capture:
            self._buf.append(data)

    def _store(self, target: str, text: str) -> None:
        if target == "year":
            m = re.search(r"\b(19|20)\d{2}\b", text)
            self.year = m.group(0) if m else text
        elif target == "month":
            self.month = text
        elif not self.items:
            return
        elif target == "title":
            self.items[-1]["title"] = text
        elif target == "amount":
            self.items[-1]["amount_text"] = text
        elif self._li is not None:
            self._li[target] = text

    def _close_li(self) -> None:
        li, self._li = self._li, None
        if not self.items or not li:
            return
        item = self.items[-1]
        if "li_amount" in li and "li_label" in li:
            item["concepts"][li["li_label"]] = euros(li["li_amount"])
        elif "li_label" in li:
            item["fields"][li["li_label"]] = li.get("li_value", "")


def parse_quota_history(html: str) -> list[dict[str, Any]]:
    parser = _QuotaHistory()
    parser.feed(html)
    out = []
    for item in parser.items:
        month = (item.get("month") or "").strip().lower()
        entry: dict[str, Any] = {
            "period": f"{item['year']}-{MONTHS[month]:02d}" if item.get("year") and month in MONTHS else None,
            "concept": item.get("title"),
            "amount_eur": euros(item.get("amount_text", "")),
        }
        if not entry["amount_eur"] and item.get("amount_text"):
            entry["amount_text"] = item["amount_text"]
        if item["concepts"]:
            entry["breakdown_eur"] = item["concepts"]
        if item["fields"]:
            entry["details"] = item["fields"]
        out.append(entry)
    return out


def page_position(text: str) -> tuple[int, int] | None:
    """'1 de 7' -> (1, 7)"""
    m = re.search(r"\b(\d+) de (\d+)\b", text)
    return (int(m.group(1)), int(m.group(2))) if m else None
