"""Turn HTML pages from public administration portals into agent-friendly JSON.

Output: title, text (only the <main> region when the page has one, so the
portal header and footer are dropped), tables as rows, and links.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

_SKIP = {"script", "style", "noscript", "template", "svg", "head"}
_BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section", "article", "form", "dt", "dd", "legend", "fieldset"}


class _Extractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self.parts: list[str] = []
        self.main_parts: list[str] = []
        self.links: list[dict[str, str]] = []
        self.main_links: list[dict[str, str]] = []
        self.tables: list[list[list[str]]] = []
        self._skip = 0
        self._main = 0
        self._in_title = False
        self._href: str | None = None
        self._link_text: list[str] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def _emit(self, text: str) -> None:
        self.parts.append(text)
        if self._main:
            self.main_parts.append(text)

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP:
            self._skip += 1
        if tag == "main":
            self._main += 1
        if tag == "title":
            self._in_title = True
        if tag in _BLOCK:
            self._emit("\n")
        if tag == "table":
            self.tables.append([])
        if tag == "tr" and self.tables:
            self._row = []
        if tag in ("td", "th"):
            self._emit(" | ")
            self._cell = []
        if tag == "base" and (base := dict(attrs).get("href")):
            # Portals such as IBM WebSphere resolve relative links against <base href>.
            self.base_url = urljoin(self.base_url, base.strip())
        if tag == "a":
            href = dict(attrs).get("href")
            if href and not href.strip().startswith(("javascript:", "#", "mailto:")):
                self._href = urljoin(self.base_url, href.strip())
                self._link_text = []

    def handle_endtag(self, tag):
        if tag in _SKIP and self._skip:
            self._skip -= 1
        if tag == "main" and self._main:
            self._main -= 1
        if tag == "title":
            self._in_title = False
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        if tag == "tr" and self._row is not None:
            if any(self._row):
                self.tables[-1].append(self._row)
            self._row = None
        if tag == "a" and self._href:
            link = {"text": " ".join("".join(self._link_text).split()), "href": self._href}
            self.links.append(link)
            if self._main:
                self.main_links.append(link)
            self._href = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._skip:
            return
        self._emit(data)
        if self._href:
            self._link_text.append(data)
        if self._cell is not None:
            self._cell.append(data)


def _clean(parts: list[str]) -> str:
    text = "".join(parts)
    text = re.sub(r"[ \t\r\f\v\xa0]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    return re.sub(r"\n{2,}", "\n", text).strip()


def _table_json(rows: list[list[str]]) -> dict:
    if len(rows) < 2:
        return {"rows": rows}
    headers = rows[0]
    if all(headers) and all(len(r) == len(headers) for r in rows[1:]):
        return {"columns": headers, "rows": [dict(zip(headers, r)) for r in rows[1:]]}
    return {"rows": rows}


def html_to_page(html: str, url: str, max_links: int = 200) -> dict:
    parser = _Extractor(url)
    parser.feed(html)
    has_main = bool(parser.main_parts)
    page = {
        "url": url,
        "title": " ".join(parser.title.split()),
        "text": _clean(parser.main_parts if has_main else parser.parts),
        "links": (parser.main_links if has_main else parser.links)[:max_links],
    }
    tables = [_table_json(t) for t in parser.tables if t]
    if tables:
        page["tables"] = tables
    return page
