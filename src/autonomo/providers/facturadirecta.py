"""FacturaDirecta public REST API (read-only).

Docs: https://www.facturadirecta.com/api  Spec: https://app.facturadirecta.com/openapi.json
Auth: header `facturadirecta-api-key`. Every path starts with the company id.
Create the API key with read scopes only; `autonomo doctor` warns about write scopes.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx

from ..core.config import require_setting, secret, setting
from ..core.errors import ConfigError, UsageError
from ..core.http import make_client, send
from ..core.provider import Binary, Check, FetchOptions, Param, Provider, Resource

API_KEY_ENV = "AUTONOMO_FD_API_KEY"
COMPANY_ENV = "AUTONOMO_FD_COMPANY_ID"
DEFAULT_BASE = "https://app.facturadirecta.com/api"
MAX_LIMIT = 500
MAX_PAGES = 200
# OpenAPI array query params. "a,b" on the CLI becomes ?k=a&k=b.
PATH_PARAMS = {"id", "documentType", "type"}
SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
ARRAY_PARAMS = {"related", "types", "allTheseTags", "anyOfTheseTags", "docTypes"}

# (list name, item name or None, API path, summary, documented filters)
COLLECTIONS: list[tuple[str, str | None, str, str, str]] = [
    ("invoices", "invoice", "invoices", "Facturas de venta", "search minDate maxDate series state contact"),
    ("recurring-invoices", "recurring-invoice", "recurring/invoices", "Facturas recurrentes", "search enabled contact"),
    ("estimates", "estimate", "estimates", "Presupuestos", "search minDate maxDate contact"),
    ("client-orders", "client-order", "clientOrders", "Pedidos de clientes", "search state minDate maxDate contact"),
    ("purchase-orders", "purchase-order", "purchaseOrders", "Órdenes de compra", "search state minDate maxDate contact"),
    ("delivery-notes", "delivery-note", "deliveryNotes", "Albaranes", "search minDate maxDate contact"),
    ("bills", "bill", "bills", "Facturas de compra y tickets (gastos)", "search minDate maxDate contact state"),
    ("payrolls", "payroll", "payrolls", "Nóminas", "search minDate maxDate contact state"),
    ("contacts", "contact", "contacts", "Clientes, proveedores y empleados", "search fiscalId isClient isProvider isEmployee"),
    ("products", "product", "products", "Productos y servicios", "search sku"),
    ("banks", "bank", "banks", "Bancos y cuentas de tesorería con saldo", "currency balanceDate"),
    ("statements", "statement", "statements", "Movimientos de extractos bancarios", "minDate maxDate bank state"),
    ("payment-methods", "payment-method", "paymentMethods", "Métodos de pago", "contact"),
    ("tax-declarations", "tax-declaration", "taxDeclarations", "Modelos de impuestos generados (303, 130, 111...)", "form kind fiscalYear fiscalPeriod status"),
    ("inbox", "inbox-item", "inbox", "Bandeja de documentos pendientes de procesar", "status source minDate maxDate"),
    ("custom-fields", "custom-field", "customFields", "Campos personalizados", ""),
    ("journal", None, "journal", "Libro diario: asientos contables", "minDate maxDate account document"),
    ("activity", None, "activity", "Registro de actividad de la empresa", "type minDate maxDate documentId"),
]

# Document types that expose /{id}/attachments and /{id}/versions.
ATTACHMENT_TYPES = {"invoices", "recurring-invoices", "estimates", "client-orders", "purchase-orders", "delivery-notes", "bills", "payrolls", "tax-declarations"}
VERSION_TYPES = {"invoices", "estimates", "delivery-notes", "client-orders", "bills", "purchase-orders", "contacts", "products", "banks", "payment-methods", "payrolls"}

# (name, API path, summary, params)
SINGLE: list[tuple[str, str, str, tuple[Param, ...]]] = [
    ("results-summary", "reports/resultsSummary", "Resumen de resultados (ingresos, gastos, beneficio)", (Param("startDate"), Param("endDate"))),
    ("results-detail", "reports/resultsDetail", "Detalle de resultados por categoría", (Param("category", required=True), Param("startDate"), Param("endDate"))),
    ("profit-loss", "reports/profitLoss", "Cuenta de pérdidas y ganancias", (Param("startDate"), Param("endDate"))),
    ("balance-sheet", "reports/balanceSheet", "Balance de situación", (Param("date"),)),
    ("trial-balance", "reports/trialBalance", "Balance de sumas y saldos", (Param("startDate"), Param("endDate"))),
    ("company", "settings/company", "Datos de la empresa", ()),
    ("sales-taxes", "settings/taxes/sales", "Impuestos de venta configurados", ()),
    ("purchase-taxes", "settings/taxes/purchases", "Impuestos de compra configurados", ()),
    ("series", "settings/series/{documentType}", "Series de numeración", (Param("documentType", "invoice, estimate, deliveryNote, clientOrder, purchaseOrder", required=True),)),
    ("api-key-info", "apiKeyInfo", "Información y scopes de la API key en uso", ()),
    ("search", "search", "Búsqueda global en la empresa", (Param("q", required=True), Param("types", "Lista separada por comas"))),
]

ID = Param("id", "Id del documento (p. ej. inv_...)", required=True)
RELATED = Param("related", "Datos extra separados por comas (p. ej. balance,state)")


class FacturaDirecta(Provider):
    name = "facturadirecta"
    title = "FacturaDirecta"
    description = "Facturas, gastos, contactos, bancos, contabilidad y modelos de impuestos desde la API pública de FacturaDirecta."

    def __init__(self, settings: dict[str, Any], transport: httpx.BaseTransport | None = None):
        super().__init__(settings)
        self._transport = transport
        self._client: httpx.Client | None = None
        self._routes: dict[str, tuple[str, str]] = {}
        self._resources = self._build_resources()

    # -- catalogue -----------------------------------------------------------

    def _build_resources(self) -> list[Resource]:
        res: list[Resource] = []
        for list_name, item_name, path, summary, filters in COLLECTIONS:
            params = tuple(Param(f) for f in filters.split()) + (Param("limit", f"1-{MAX_LIMIT}"), Param("offset"))
            res.append(Resource(list_name, f"{summary} (lista)", params, open_filters=True))
            self._routes[list_name] = ("list", path)
            if item_name:
                res.append(Resource(item_name, f"{summary} (uno, por id)", (ID, RELATED)))
                self._routes[item_name] = ("item", path)
        for name, path, summary, params in SINGLE:
            res.append(Resource(name, summary, params, open_filters=True))
            self._routes[name] = ("single", path)
        res += [
            Resource("attachments", "Adjuntos de un documento (URLs de descarga)", (Param("type", ", ".join(sorted(ATTACHMENT_TYPES)), required=True), ID)),
            Resource("versions", "Historial de versiones de un documento", (Param("type", ", ".join(sorted(VERSION_TYPES)), required=True), ID)),
            Resource("download", "Descarga un adjunto por su URL (usa --out)", (Param("url", "URL devuelta por attachments", required=True),)),
            Resource("raw", "GET de cualquier ruta de la API bajo /{companyId}/", (Param("path", "p. ej. invoices/inv_x/versions", required=True),), open_filters=True),
        ]
        return res

    def resources(self) -> list[Resource]:
        return self._resources

    # -- http ----------------------------------------------------------------

    @property
    def company_id(self) -> str:
        return require_setting(self.settings, "company_id", COMPANY_ENV, self.name)

    @property
    def base_url(self) -> str:
        return setting(self.settings, "base_url", default=DEFAULT_BASE).rstrip("/")

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            api_key = secret(API_KEY_ENV, "FacturaDirecta API key")
            self._client = make_client(
                base_url=self.base_url,
                headers={"facturadirecta-api-key": api_key, "Accept": "application/json"},
                transport=self._transport,
            )
        return self._client

    def _get(self, path: str, query: dict[str, Any] | None = None) -> Any:
        return send(self.client, "GET", path, params=_query(query or {})).json()

    def _company_path(self, path: str) -> str:
        return f"/{self.company_id}/{path.lstrip('/')}"

    # -- fetch ---------------------------------------------------------------

    def fetch(self, resource: str, params: dict[str, str], options: FetchOptions) -> Any:
        self.resource(resource)  # validates the name
        params = dict(params)
        for key in PATH_PARAMS & params.keys():
            if not SAFE_ID.fullmatch(params[key]):
                raise UsageError(f"Invalid {key} '{params[key]}'.", hint="Ids look like inv_... or con_... (letters, digits, _ and -).")
        if resource in self._routes:
            kind, path = self._routes[resource]
            if kind == "list":
                return self._list(self._company_path(path), params, options.all_pages)
            if kind == "item":
                item_id = params.pop("id")
                return self._get(self._company_path(f"{path}/{item_id}"), params)
            query = {k: v for k, v in params.items() if f"{{{k}}}" not in path}
            return self._get(self._company_path(path.format(**params)), query)
        if resource in ("attachments", "versions"):
            allowed = ATTACHMENT_TYPES if resource == "attachments" else VERSION_TYPES
            doc_type = params.pop("type")
            if doc_type not in allowed:
                raise UsageError(f"type must be one of: {', '.join(sorted(allowed))}")
            path = self._routes[doc_type][1]
            item_id = params.pop("id")
            return self._get(self._company_path(f"{path}/{item_id}/{resource}"), params)
        if resource == "download":
            return self._download(params["url"])
        if resource == "raw":
            path = params.pop("path")
            if ".." in path.split("/") or "://" in path or "?" in path:
                raise UsageError("path must be a plain API path such as invoices/inv_x/versions; pass filters as key=value.")
            return self._list(self._company_path(path), params, options.all_pages)
        raise UsageError(f"Resource '{resource}' is declared but not implemented.")

    def _list(self, path: str, params: dict[str, Any], all_pages: bool) -> Any:
        page = self._get(path, params)
        if not all_pages or not isinstance(page, dict) or "items" not in page:
            return page
        items = list(page["items"])
        for _ in range(MAX_PAGES):
            if "pagination" in page:
                pag = page["pagination"]
                next_offset = pag.get("offset", 0) + pag.get("limit", len(page["items"]))
                if not page["items"] or next_offset >= pag.get("total", 0):
                    break
                page = self._get(path, {**params, "offset": next_offset, "limit": params.get("limit", MAX_LIMIT)})
            elif page.get("hasMore") and page.get("nextCursor"):
                page = self._get(path, {**params, "cursor": page["nextCursor"]})
            else:
                break
            items.extend(page["items"])
        return {"items": items, "count": len(items)}

    def _download(self, url: str) -> Binary:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise UsageError("Only https attachment URLs are allowed.")
        # The API key only goes to FacturaDirecta hosts; presigned storage URLs need no key.
        if parsed.hostname and (parsed.hostname == "facturadirecta.com" or parsed.hostname.endswith(".facturadirecta.com")):
            response = send(self.client, "GET", url)
        else:
            with make_client(transport=self._transport) as anon:
                response = send(anon, "GET", url)
        name = parsed.path.rsplit("/", 1)[-1] or None
        return Binary(response.content, response.headers.get("content-type", "application/octet-stream"), name)

    # -- doctor --------------------------------------------------------------

    def doctor(self, online: bool = False) -> list[Check]:
        checks: list[Check] = []
        try:
            checks.append(Check("company_id", True, self.company_id))
        except ConfigError as exc:
            checks.append(Check("company_id", False, exc.message, exc.hint))
        try:
            secret(API_KEY_ENV, "FacturaDirecta API key")
            checks.append(Check("api_key", True, f"{API_KEY_ENV} is set"))
        except ConfigError as exc:
            checks.append(Check("api_key", False, exc.message, exc.hint))
        if online and all(c.ok for c in checks):
            try:
                info = self._get(self._company_path("apiKeyInfo"))
                scopes = _scopes(info)
                writes = sorted(s for s in scopes if s.endswith(":write"))
                checks.append(Check("api_access", True, f"{len(scopes)} scopes" if scopes else "API key accepted"))
                checks.append(Check(
                    "read_only_key", not writes,
                    "no write scopes" if not writes else f"write scopes: {', '.join(writes)}",
                    "" if not writes else "Create a key with only :read scopes. autonomo blocks writes anyway, but a read-only key is a second barrier.",
                ))
            except Exception as exc:  # report, do not crash doctor
                checks.append(Check("api_access", False, str(exc), getattr(exc, "hint", "")))
        return checks

    def close(self) -> None:
        if self._client is not None:
            self._client.close()


def _query(params: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in params.items():
        if key in ARRAY_PARAMS and isinstance(value, str):
            out[key] = [v for v in value.split(",") if v]
        else:
            out[key] = value
    return out


def _scopes(info: Any) -> list[str]:
    return [str(s) for s in info.get("scopes", [])] if isinstance(info, dict) else []
