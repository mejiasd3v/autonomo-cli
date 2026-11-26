"""Cross-source views built on the other providers.

* pendientes: one answer to "does anything need my attention?"
* reta:       RETA paid (Importass receipts) vs RETA reported to AEAT (datos fiscales)
* pagos-130:  modelo 130 payments known to AEAT vs 130 forms generated in FacturaDirecta

Every check reports a status (ok, attention, info, unknown, error, skipped) and
never hides a failing source: one error does not stop the other checks.
Recognized "nothing here" sentences come from the live portals; any other page
content is reported as `attention` with the text, never silently as `ok`.
"""

from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict
from typing import Any, Callable

from ..core.errors import AutonomoError
from ..core.provider import FetchOptions, Param, Provider, Resource

YEAR = Param("year", "Ejercicio (por defecto, el año anterior)")
EMPTY_AEAT_NOTIFICATIONS = (
    "No tiene notificaciones pendientes de notificar no leídas",
    "No tiene notificaciones notificadas no leídas",
    "No tiene comunicaciones no leídas",
)


class Panel(Provider):
    name = "panel"
    title = "Panel"
    description = "Vistas que cruzan fuentes: pendientes (deudas, notificaciones, alertas, próxima cuota), RETA pagada vs declarada, pagos del 130."

    def __init__(self, settings: dict[str, Any], config: dict[str, Any] | None = None):
        super().__init__(settings)
        self._config = config
        self._providers: dict[str, Provider] = {}

    def resources(self) -> list[Resource]:
        return [
            Resource("pendientes", "Qué requiere atención hoy: deudas y notificaciones (AEAT y Seguridad Social), alertas, avisos, próxima cuota, facturas vencidas", ()),
            Resource("reta", "Cuotas RETA del año: recibos de Importass frente a lo que AEAT recibió (datos fiscales)", (YEAR,)),
            Resource("pagos-130", "Modelo 130 por trimestre: pagos que constan en AEAT frente a modelos generados en FacturaDirecta", (YEAR,)),
        ]

    def fetch(self, resource: str, params: dict[str, str], options: FetchOptions) -> Any:
        self.resource(resource)
        if resource == "pendientes":
            return self._pendientes()
        year = _year(params)
        if resource == "reta":
            return self._reta(year)
        return self._pagos_130(year)

    def close(self) -> None:
        for provider in self._providers.values():
            provider.close()

    # -- plumbing ------------------------------------------------------------

    def _provider(self, name: str) -> Provider:
        if name not in self._providers:
            from ..core.registry import get_provider

            self._providers[name] = get_provider(name, self._config)
        return self._providers[name]

    def _configured(self, name: str) -> bool:
        return all(c.ok for c in self._provider(name).doctor(online=False))

    def _get(self, provider: str, resource: str, params: dict[str, str] | None = None, all_pages: bool = False) -> Any:
        return self._provider(provider).fetch(resource, params or {}, FetchOptions(all_pages=all_pages))

    def _check(self, source: str, item: str, fn: Callable[[], tuple[str, str]]) -> dict[str, str]:
        if not self._configured(source):
            return {"source": source, "item": item, "status": "skipped", "detail": f"{source} is not configured (autonomo doctor {source})."}
        try:
            status, detail = fn()
        except AutonomoError as exc:
            status, detail = "error", f"{exc.message} {exc.hint}".strip()
        except Exception as exc:  # a broken source must not hide the others
            status, detail = "error", f"{type(exc).__name__}: {exc}"
        return {"source": source, "item": item, "status": status, "detail": detail}

    # -- pendientes ----------------------------------------------------------

    def _pendientes(self) -> dict[str, Any]:
        checks = [
            self._check("aeat", "deudas", self._aeat_deudas),
            self._check("aeat", "notificaciones", self._aeat_notificaciones),
            self._check("aeat", "alertas", self._aeat_alertas),
            self._check("seguridad-social", "deudas", self._ss_deudas),
            self._check("seguridad-social", "notificaciones", self._ss_notificaciones),
            self._check("seguridad-social", "avisos no leídos", self._ss_avisos),
            self._check("seguridad-social", "próxima cuota", self._ss_proxima_cuota),
            self._check("facturadirecta", "facturas vencidas", self._fd_vencidas),
        ]
        counts: dict[str, int] = defaultdict(int)
        for c in checks:
            counts[c["status"]] += 1
        return {"checked_at": dt.datetime.now().isoformat(timespec="seconds"), "summary": dict(counts), "checks": checks}

    def _aeat_deudas(self) -> tuple[str, str]:
        text = self._get("aeat", "deudas")["text"]
        if "No existen deudas" in text:
            return "ok", "No existen deudas para mostrar"
        return "attention", _excerpt(text, "Avisos")

    def _aeat_notificaciones(self) -> tuple[str, str]:
        text = self._get("aeat", "notificaciones")["text"]
        if all(line in text for line in EMPTY_AEAT_NOTIFICATIONS):
            return "ok", "No unread notifications or communications"
        return "attention", _excerpt(text, "Nombre") + " Open them only in the sede (comparecencia)."

    def _aeat_alertas(self) -> tuple[str, str]:
        text = self._get("aeat", "alertas")["text"]
        if "No existen Alertas" in text:
            return "ok", "No existen Alertas"
        return "attention", _excerpt(text, "Consulta Mis Alertas")

    def _ss_deudas(self) -> tuple[str, str]:
        result = self._get("seguridad-social", "deudas")
        message = " ".join(m["text"] for m in result.get("messages", []))
        if result.get("has_debts") is False:
            return "ok", message or "No debts"
        if result.get("has_debts"):
            return "attention", "The sede lists debts or liquidations. Run `autonomo get seguridad-social deudas` for details."
        return "unknown", message or "The sede answer was unclear."

    def _ss_notificaciones(self) -> tuple[str, str]:
        result = self._get("seguridad-social", "notificaciones")
        window = result.get("window") or {}
        span = f"{window.get('desde')} - {window.get('hasta')}"
        if result["count"] == 0:
            return "ok", f"No pending notifications ({span})"
        return "attention", f"{result['count']} pending notification(s) ({span}). Open them only in the sede (comparecencia)."

    def _ss_avisos(self) -> tuple[str, str]:
        text = self._get("seguridad-social", "avisos")["text"]
        m = re.search(r"Avisos no leídos\n(.*?)(?:\nAvisos leídos|\Z)", text, re.S)
        unread = (m.group(1).strip() if m else "")
        if not unread or unread.startswith("No tienes"):
            return "ok", "No unread notices"
        return "info", " ".join(unread.split())[:400]

    def _ss_proxima_cuota(self) -> tuple[str, str]:
        text = self._get("seguridad-social", "resumen")["text"]
        m = re.search(r"Tu próxima cuota\n([\d.,]+)\n€\n(?:Pago\n)?(\d{1,2})\n(\w{3})\n(\d{4})", text)
        if not m:
            return "unknown", "Next cuota not found on the Importass summary page."
        return "info", f"{m.group(1)} € on {m.group(2)} {m.group(3)} {m.group(4)}"

    def _fd_vencidas(self) -> tuple[str, str]:
        result = self._get("facturadirecta", "invoices", {"state": "overdue", "limit": "50"})
        total = result.get("pagination", {}).get("total", len(result.get("items", [])))
        if not total:
            return "ok", "No overdue invoices"
        return "attention", f"{total} overdue invoice(s). Run `autonomo get facturadirecta invoices state=overdue`."

    # -- reta ----------------------------------------------------------------

    def _reta(self, year: int) -> dict[str, Any]:
        out: dict[str, Any] = {"year": year}
        receipts = self._safe(lambda: self._get("seguridad-social", "recibos", {"desde": f"{year}-01", "hasta": f"{year}-12"}, all_pages=True))
        if "error" in receipts:
            out["importass"] = receipts
        else:
            by_concept: dict[str, float] = defaultdict(float)
            for item in receipts["items"]:
                by_concept[item.get("concept") or "?"] += item.get("amount_eur") or 0
            out["importass"] = {
                "receipts": receipts["count"],
                "total_eur": round(sum(by_concept.values()), 2),
                "by_concept_eur": {k: round(v, 2) for k, v in sorted(by_concept.items())},
            }
        fiscal = self._safe(lambda: self._get("aeat", "datos-fiscales", {"year": str(year)}))
        if "error" in fiscal:
            out["aeat_datos_fiscales"] = fiscal
        else:
            groups = {g["code"]: g for g in fiscal["records"]}
            ct = [i.get("importe") or 0 for i in groups.get("CT", {}).get("items", [])]
            ret = groups.get("RET", {}).get("items", [])
            out["aeat_datos_fiscales"] = {
                "cotizaciones_reta_eur": round(sum(ct), 2),
                "regularizacion_reta": ret,
                "warnings": fiscal.get("warnings", []),
            }
        out["importass_regularizaciones"] = self._regularizaciones()
        for ret in out["aeat_datos_fiscales"].get("regularizacion_reta") or []:
            for side in ("ingresar", "devolver"):
                amount = ret.get(f"regularizacion_reta_a_{side}") or 0
                same = [r for r in out["importass_regularizaciones"] if r["side"] == side and abs(r["amount_eur"] - amount) < 0.01]
                if amount and same:
                    ret[f"matches_importass_resolution_{side}"] = same[0]["year"]
        imp, aeat = out["importass"].get("total_eur"), out["aeat_datos_fiscales"].get("cotizaciones_reta_eur")
        if imp is not None and aeat is not None:
            diff = round(imp - aeat, 2)
            out["difference_eur"] = diff
            out["status"] = "match" if abs(diff) < 0.01 else "mismatch"
            if out["status"] == "mismatch":
                out["note"] = "Receipts are dated by charge month; AEAT counts what the TGSS reported for the year. Regularizations and late charges can move amounts between years."
        else:
            out["status"] = "incomplete"
        return out

    def _regularizaciones(self) -> list[dict[str, Any]]:
        """Importass yearly regularization results: [{year, side, amount_eur}]."""
        page = self._safe(lambda: self._get("seguridad-social", "regularizacion"))
        text = page.get("text", "") if isinstance(page, dict) else ""
        return [
            {"year": int(y), "side": side, "amount_eur": float(a.replace(".", "").replace(",", "."))}
            for y, side, a in re.findall(r"Resolución (\d{4}).*?A (ingresar|devolver): ([\d.]+,\d{2}) €", text, re.S)
        ]

    # -- pagos 130 -----------------------------------------------------------

    def _pagos_130(self, year: int) -> dict[str, Any]:
        out: dict[str, Any] = {"year": year}
        aeat_q: dict[str, float] = {}
        fiscal = self._safe(lambda: self._get("aeat", "datos-fiscales", {"year": str(year)}))
        if "error" in fiscal:
            out["aeat"] = fiscal
        else:
            for item in next((g["items"] for g in fiscal["records"] if g["code"] == "PF"), []):
                if item.get("modelo") == "130":
                    aeat_q[item.get("periodo", "?")] = round(aeat_q.get(item.get("periodo", "?"), 0) + (item.get("importe") or 0), 2)
            out["aeat"] = {"by_quarter_eur": aeat_q, "total_eur": round(sum(aeat_q.values()), 2)}
        fd_q: dict[str, float | None] = {}
        if not self._configured("facturadirecta"):
            out["facturadirecta"] = {"status": "skipped", "detail": "facturadirecta is not configured."}
        else:
            decl = self._safe(lambda: self._get("facturadirecta", "tax-declarations", {"form": "130", "fiscalYear": str(year), "limit": "50"}, all_pages=True))
            if "error" in decl:
                out["facturadirecta"] = decl
            else:
                for item in decl.get("items", []):
                    content = item.get("content", item)
                    fd_q[content.get("fiscalPeriod") or "?"] = (content.get("result") or {}).get("amount")
                out["facturadirecta"] = {"by_quarter_eur": fd_q, "declarations": len(fd_q)}
                if not fd_q:
                    out["facturadirecta"]["note"] = f"No modelo 130 generated in FacturaDirecta for {year} (or the company is a sandbox)."
        quarters = sorted(set(aeat_q) | set(fd_q))
        out["quarters"] = [
            {
                "quarter": q,
                "aeat_eur": aeat_q.get(q),
                "facturadirecta_eur": fd_q.get(q),
                "status": "match" if q in aeat_q and q in fd_q and fd_q[q] is not None and abs(aeat_q[q] - fd_q[q]) < 0.01
                else "only_aeat" if q not in fd_q else "only_facturadirecta" if q not in aeat_q else "mismatch",
            }
            for q in quarters
        ]
        return out

    @staticmethod
    def _safe(fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except AutonomoError as exc:
            return {"error": exc.message, "hint": exc.hint}


def _year(params: dict[str, str]) -> int:
    raw = params.get("year") or str(dt.date.today().year - 1)
    if not raw.isdigit():
        from ..core.errors import UsageError

        raise UsageError(f"Invalid year '{raw}'.")
    return int(raw)


def _excerpt(text: str, after: str, size: int = 400) -> str:
    i = text.find(after)
    return " ".join((text[i:] if i >= 0 else text).split())[:size]
