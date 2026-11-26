import datetime as dt
import json
import stat
from pathlib import Path

import httpx
import keyring
import keyring.backend
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID

from autonomo.cli import main
from autonomo.core.config import load_config
from autonomo.core.certificate import Certificate, mask_ids
from autonomo.core.errors import ConfigError, ReadOnlyViolation, RemoteError, UsageError
from autonomo.core.http import QUERY, make_client, writes_unlocked
from autonomo.core.provider import FetchOptions
from autonomo.providers.aeat import AEAT
from autonomo.providers.facturadirecta import FacturaDirecta


def ok(request):
    return httpx.Response(200, json={"ok": True})


# -- read-only guard -----------------------------------------------------------


def test_guard_blocks_writes_unless_query_or_unlocked():
    client = make_client(transport=httpx.MockTransport(ok))
    assert client.get("https://x.test/").status_code == 200
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(ReadOnlyViolation):
            client.request(method, "https://x.test/")
    assert client.post("https://x.test/", extensions={QUERY: True}).status_code == 200
    with writes_unlocked():
        assert client.delete("https://x.test/").status_code == 200
    with pytest.raises(ReadOnlyViolation):
        client.delete("https://x.test/")


# -- FacturaDirecta --------------------------------------------------------------


@pytest.fixture
def fd_env(monkeypatch):
    monkeypatch.setenv("AUTONOMO_FD_API_KEY", "test-key")
    monkeypatch.setenv("AUTONOMO_FD_COMPANY_ID", "com_test")


def test_facturadirecta_all_pages_and_auth(fd_env):
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        offset = int(request.url.params.get("offset", 0))
        items = [{"uuid": f"inv_{i}"} for i in range(offset, min(offset + 2, 5))]
        return httpx.Response(200, json={"pagination": {"offset": offset, "limit": 2, "total": 5}, "items": items})

    fd = FacturaDirecta({}, transport=httpx.MockTransport(handler))
    result = fd.fetch("invoices", {"limit": "2", "state": "pending"}, FetchOptions(all_pages=True))

    assert [i["uuid"] for i in result["items"]] == [f"inv_{i}" for i in range(5)]
    assert len(seen) == 3
    assert seen[0].url.path == "/api/com_test/invoices"
    assert seen[0].headers["facturadirecta-api-key"] == "test-key"
    assert all(r.url.params["state"] == "pending" for r in seen)


def test_facturadirecta_item_and_array_params(fd_env):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"uuid": "inv_1"})

    fd = FacturaDirecta({}, transport=httpx.MockTransport(handler))
    fd.fetch("invoice", {"id": "inv_1", "related": "balance,state"}, FetchOptions())
    fd.fetch("series", {"documentType": "invoice"}, FetchOptions())

    assert seen[0].url.path == "/api/com_test/invoices/inv_1"
    assert seen[0].url.params.get_list("related") == ["balance", "state"]
    assert seen[1].url.path == "/api/com_test/settings/series/invoice"
    assert "documentType" not in seen[1].url.params


def test_facturadirecta_download_sends_key_only_to_api_origin(fd_env):
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/api/files/redirect.pdf":
            return httpx.Response(302, headers={"location": "https://storage.example.com/f.pdf"})
        return httpx.Response(200, content=b"%PDF", headers={"content-type": "application/pdf"})

    fd = FacturaDirecta({}, transport=httpx.MockTransport(handler))
    fd.fetch("download", {"url": "https://storage.example.com/f.pdf"}, FetchOptions())
    fd.fetch("download", {"url": "https://evil.facturadirecta.com/f.pdf"}, FetchOptions())
    fd.fetch("download", {"url": "https://app.facturadirecta.com/api/files/redirect.pdf"}, FetchOptions())

    keyed = [r.url.host for r in seen if "facturadirecta-api-key" in r.headers]
    assert keyed == ["app.facturadirecta.com"]
    assert str(seen[-1].url) == "https://storage.example.com/f.pdf"


# -- certificate portals ---------------------------------------------------------


def test_portal_stays_inside_allowlist():
    def handler(request):
        if request.url.path == "/clave":
            return httpx.Response(302, headers={"location": "https://pasarela.clave.gob.es/login"})
        return httpx.Response(302, headers={"location": "https://evil.example.com/"})

    aeat = AEAT({}, transport=httpx.MockTransport(handler))
    with pytest.raises(UsageError):
        aeat.get_page("https://evil.example.com/")
    with pytest.raises(RemoteError, match="login"):
        aeat.get_page("https://www1.agenciatributaria.gob.es/clave")
    with pytest.raises(RemoteError, match="Redirect blocked"):
        aeat.get_page("https://www1.agenciatributaria.gob.es/other")


def test_portal_parses_html():
    html = "<html><head><title> Mis datos </title><script>x()</script></head><body><h1>Hola</h1><a href='/a'>Ir</a></body></html>"
    aeat = AEAT({}, transport=httpx.MockTransport(lambda r: httpx.Response(200, html=html)))
    page = aeat.get_page("https://www1.agenciatributaria.gob.es/x")
    assert page["title"] == "Mis datos"
    assert "Hola" in page["text"] and "x()" not in page["text"]
    assert page["links"] == [{"text": "Ir", "href": "https://www1.agenciatributaria.gob.es/a"}]


def make_p12(path, password=b"pw", days=90):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GARCIA LOPEZ ANA - 12345678Z")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(pkcs12.serialize_key_and_certificates(b"t", key, cert, None, BestAvailableEncryption(password)))
    return path


def test_certificate_loads_p12_and_builds_ssl_context(tmp_path, monkeypatch):
    path = make_p12(tmp_path / "cert.p12")
    monkeypatch.setenv("AUTONOMO_CERT_PASSWORD", "pw")

    loaded = Certificate.from_settings({"path": str(path)})
    info = loaded.describe()

    assert "12345678Z" not in info["holder"] and info["holder"].endswith("78Z")
    assert 88 <= info["days_left"] <= 90
    assert loaded.nif() == "12345678Z"
    loaded.ssl_context()  # raises if the key/cert pair cannot be loaded


def test_mask_ids():
    assert mask_ids("X1234567L y B12345678") == "******67L y ******678"


# -- CLI -------------------------------------------------------------------------


def test_cli_reports_usage_errors_as_json(capsys, fd_env, monkeypatch, tmp_path):
    monkeypatch.setenv("AUTONOMO_CONFIG", str(tmp_path / "none.toml"))
    assert main(["get", "facturadirecta", "invoice"]) == 2
    err = json.loads(capsys.readouterr().err)
    assert "id" in err["error"] and err["type"] == "UsageError"
    assert main(["get", "aeat", "certificate", "foo=bar"]) == 2
    assert main(["get", "facturadirecta", "nope"]) == 2


def test_aeat_never_opens_notifications():
    calls = []
    aeat = AEAT({"nif": "12345678Z"}, transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, html="<p>x</p>")))
    aeat.fetch("notificaciones", {}, FetchOptions())
    with pytest.raises(UsageError, match="comparecencia"):
        aeat.get_page("https://www1.agenciatributaria.gob.es/wlpl/GNNO-JDIT/SvVerNotificacion?id=1")
    assert len(calls) == 1


def test_aeat_domicilio_ratificado_is_an_allowed_query_post():
    def handler(request):
        assert request.method == "POST" and b"NIF=12345678Z" in request.content
        return httpx.Response(200, json={"status": "OK", "respuesta": {"domicilioRatificado": False}})

    aeat = AEAT({"nif": "12345678Z"}, transport=httpx.MockTransport(handler))
    assert aeat.fetch("domicilio-ratificado", {"year": "2024"}, FetchOptions()) == {"year": 2024, "domicilioRatificado": False}


def test_aeat_datos_fiscales_error_text_becomes_error():
    text = "No está autorizado a este Trámite"
    aeat = AEAT({"nif": "12345678Z"}, transport=httpx.MockTransport(lambda r: httpx.Response(200, text=text)))
    with pytest.raises(RemoteError, match="datos fiscales"):
        aeat.fetch("datos-fiscales", {"year": "2024"}, FetchOptions())


# -- certificate import ------------------------------------------------------------


class MemoryKeyring(keyring.backend.KeyringBackend):
    priority = 1

    def __init__(self):
        self.store = {}

    def get_password(self, service, user):
        return self.store.get((service, user))

    def set_password(self, service, user, password):
        self.store[(service, user)] = password

    def delete_password(self, service, user):
        self.store.pop((service, user))


@pytest.fixture
def cert_home(tmp_path, monkeypatch):
    config = tmp_path / "cfg" / "config.toml"
    config.parent.mkdir()
    config.write_text('# mine\n[facturadirecta]\ncompany_id = "com_x"\n')
    monkeypatch.setenv("AUTONOMO_CONFIG", str(config))
    monkeypatch.delenv("AUTONOMO_CERT_PASSWORD", raising=False)
    monkeypatch.delenv("AUTONOMO_CERT_PATH", raising=False)
    ring = MemoryKeyring()
    keyring.set_keyring(ring)
    return config, ring


def test_cert_import_reencrypts_and_uses_keyring(tmp_path, cert_home):
    config, ring = cert_home
    original = make_p12(tmp_path / "Downloads.p12", password=b"user-pw")
    pw_file = tmp_path / "pw"
    pw_file.write_text("user-pw\n")

    assert main(["cert", "import", str(original), "--password-file", str(pw_file)]) == 0

    section = load_config()["certificate"]
    stored = Path(section["path"])
    assert stored.parent == config.parent / "certs" and stat.S_IMODE(stored.stat().st_mode) == 0o600
    assert load_config()["facturadirecta"]["company_id"] == "com_x"  # other tables kept
    assert "# mine" in config.read_text()
    assert b"user-pw" not in repr(ring.store).encode()  # only the random password is kept
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(stored.read_bytes(), b"user-pw")

    cert = Certificate.from_settings(section)
    assert cert.password_source == "OS keyring"

    assert main(["cert", "remove"]) == 0
    assert not stored.exists() and original.exists() and not ring.store
    assert "certificate" not in load_config()


def test_cert_import_rejects_expired_and_wrong_password(tmp_path, cert_home, capsys):
    expired = make_p12(tmp_path / "old.p12", days=-1)
    pw_file = tmp_path / "pw"
    pw_file.write_text("pw")
    assert main(["cert", "import", str(expired), "--password-file", str(pw_file)]) == 3
    assert "expired" in json.loads(capsys.readouterr().err)["error"]

    pw_file.write_text("wrong")
    assert main(["cert", "import", str(make_p12(tmp_path / "ok.p12")), "--password-file", str(pw_file)]) == 3
    assert "wrong password" in json.loads(capsys.readouterr().err)["error"]


# -- AEAT parsing ------------------------------------------------------------------


def test_datos_fiscales_parser_with_official_layout():
    from autonomo.providers.datos_fiscales import parse

    pf = "2PF00001130I1T28" + "1300000000001" + "0000000123456"
    reta = "2RET0001" + "00000000000005050" + "00000000000000000"
    at2 = "2AT20001" + " " * 40  # code with a digit: must match AT2, not AT
    content = "\r\n".join(["0DDFF2025", "1" + " " * 50 + "20261121", pf, reta, at2, "2ZZZ0001xx", "999"])

    result = parse(content, 2025)

    groups = {g["code"]: g for g in result["records"]}
    assert result["fecha_proceso"] == "2026-11-21"
    assert groups["PF"]["items"][0]["importe"] == 1234.56
    assert groups["PF"]["items"][0]["periodo"] == "1T"
    assert groups["RET"]["items"][0] == {"regularizacion_reta_a_ingresar": 50.5, "regularizacion_reta_a_devolver": 0.0}
    assert "AT2" in groups
    assert any("unknown record codes" in w for w in result["warnings"])


def test_datos_fiscales_parser_falls_back_to_older_layout():
    from autonomo.providers.datos_fiscales import parse

    result = parse("0DDFF2031\r\n999", 2031)
    assert result["layout"].startswith("2025") and "No record layout for 2031" in result["warnings"][0]


def test_html_keeps_main_and_tables():
    html = (
        "<header>Logo Área personal</header><main><h1>Mis últimos accesos</h1>"
        "<table><tr><th>Fecha</th><th>Canal</th></tr><tr><td>2026-11-26</td><td>Navegador</td></tr></table></main>"
        "<footer>Aviso legal</footer>"
    )
    from autonomo.core.html import html_to_page

    page = html_to_page(html, "https://www1.agenciatributaria.gob.es/x")
    assert "Logo" not in page["text"] and "Aviso legal" not in page["text"]
    assert page["tables"] == [{"columns": ["Fecha", "Canal"], "rows": [{"Fecha": "2026-11-26", "Canal": "Navegador"}]}]


def test_aeat_deudas_submits_query_form_and_drops_links():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, html="<main><p>No existen deudas para mostrar</p><a href='/pagar'>Pagar</a></main>")

    aeat = AEAT({"nif": "12345678Z"}, transport=httpx.MockTransport(handler))
    page = aeat.fetch("deudas", {}, FetchOptions())

    assert [r.method for r in seen] == ["GET", "POST"]
    assert b"faccion=CONS_DDAS" in seen[1].content and b"fnif=12345678Z" in seen[1].content
    assert "No existen deudas" in page["text"] and page["links"] == []


def test_facturadirecta_rejects_empty_and_unsafe_ids(fd_env, capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("AUTONOMO_CONFIG", str(tmp_path / "none.toml"))
    assert main(["get", "facturadirecta", "product", "id="]) == 2
    fd = FacturaDirecta({}, transport=httpx.MockTransport(ok))
    with pytest.raises(UsageError):
        fd.fetch("invoice", {"id": "../contacts"}, FetchOptions())
    with pytest.raises(UsageError):
        fd.fetch("versions", {"type": "products", "id": "x/y"}, FetchOptions())


def test_secret_set_stores_in_keyring_and_env_wins(tmp_path, cert_home, monkeypatch):
    from autonomo.core.config import secret

    _, ring = cert_home
    monkeypatch.delenv("AUTONOMO_FD_API_KEY", raising=False)
    value = tmp_path / "v"
    value.write_text("fd-key\n")

    assert main(["secret", "set", "AUTONOMO_FD_API_KEY", "--value-file", str(value)]) == 0
    assert secret("AUTONOMO_FD_API_KEY", "x") == "fd-key"
    monkeypatch.setenv("AUTONOMO_FD_API_KEY", "from-env")
    assert secret("AUTONOMO_FD_API_KEY", "x") == "from-env"
    assert main(["secret", "set", "OTHER", "--value-file", str(value)]) == 2
    assert main(["secret", "delete", "AUTONOMO_FD_API_KEY"]) == 0 and not ring.store


# -- Seguridad Social ---------------------------------------------------------------


def test_seguridad_social_certificate_login_chain():
    from autonomo.providers.seguridad_social import SeguridadSocial

    portal = "https://portal.seg-social.gob.es"
    login_page = (
        f'<html><head><title>Iniciar sesión</title><base href="{portal}/wps/portal/importass/!ut/p/z1/abc/"></head>'
        '<body><form id="P017_login" method="post" action="p0/IZ7_X=CZ6_Y/#Z7_X"><input name="loginFormSubmit" type="hidden" value="ACCESO"/></form></body></html>'
    )

    def saml(action, kind):
        return f'<form name="redirectForm" method="POST" action="{action}"><input type="hidden" name="RelayState" value="r"/><input type="hidden" name="{kind}" value="x"/></form>'

    steps = []

    def handler(request):
        url, method = str(request.url), request.method
        steps.append((method, request.url.host, request.url.path))
        if method == "GET" and url.startswith(f"{portal}/wps/myportal/importass/importass/personal"):
            if "LtpaToken2" in request.headers.get("cookie", ""):
                return httpx.Response(200, html="<title>Área personal general</title><main>{}\nHola\nNUSS: 28/12345678/90 NIF 12345678Z</main>")
            return httpx.Response(200, html=login_page)
        if method == "POST" and request.url.path.endswith("/p0/IZ7_X=CZ6_Y/"):
            return httpx.Response(200, html=saml("https://idp.seg-social.es/PGIS/Login", "SAMLRequest"))
        if method == "POST" and url == "https://idp.seg-social.es/PGIS/Login":
            return httpx.Response(200, html="<button formaction='https://idp.seg-social.es/PGIS/Login?seleccion=IPCE'>cert</button>")
        if method == "POST" and url.endswith("seleccion=IPCE"):
            return httpx.Response(200, html=saml("https://ipce.seg-social.es/IPCE/Login", "SAMLRequest"))
        if method == "POST" and request.url.host == "ipce.seg-social.es":
            return httpx.Response(200, html=saml("https://idp.seg-social.es/PGIS/PostLogin?IdSesion=1", "SAMLResponse"))
        if method == "POST" and request.url.path == "/PGIS/PostLogin":
            return httpx.Response(200, html=saml(f"{portal}/wps/portal/importass/acs?loginFormSubmit=LOGIN", "SAMLResponse"))
        if method == "POST" and request.url.path == "/wps/portal/importass/acs":
            return httpx.Response(302, headers={"location": "/wps/myportal/importass/importass/personal/", "set-cookie": "LtpaToken2=t; Path=/"})
        return httpx.Response(404)

    ss = SeguridadSocial({}, transport=httpx.MockTransport(handler))
    page = ss.fetch("resumen", {}, FetchOptions())

    assert [h for _, h, _ in steps].count("ipce.seg-social.es") == 1
    assert page["text"].startswith("Hola") and "12345678Z" not in page["text"] and "12345678/90" not in page["text"]
    with pytest.raises(ReadOnlyViolation):  # only login steps may POST
        ss.client.post(f"{portal}/wps/myportal/importass/importass/tramites/baja")


def test_importass_quota_history_parser():
    from autonomo.providers.importass import page_position, parse_quota_history

    html = """
    <div class="quota-history__year"><span class="ss-h3">2026</span> Total cuotas: 1.122,06 €</div>
    <div class="quota-history__month"><h3> Noviembre </h3></div>
    <div class="quota-history__item"><a class="ss-collapse__btn quota-history__item-title">Cuota autónomos</a>
      <div class="quota-history__item-amount">607,35 €</div>
      <ul class="quota-history__breakdown"><li><div class="quota-history__breakdown-amount"> 545,65 € </div><p class="encabezadoLista">Contingencias Comunes</p></li></ul><hr>
      <ul class="quota-history__breakdown"><li><p class="encabezadoLista">Fecha de cargo en cuenta</p><p>30/11/2026</p></li></ul></div>
    <div class="quota-history__month"><span> Octubre </span></div>
    <div class="quota-history__item"><div class="quota-history__item-title quota-history__item-title-simple"><span>Régimen Especial</span></div>
      <div class="quota-history__item-amount"><span>1.633,99 €</span></div></div>
    <p>1 de 7</p>"""

    items = parse_quota_history(html)

    assert items[0] == {
        "period": "2026-11", "concept": "Cuota autónomos", "amount_eur": 607.35,
        "breakdown_eur": {"Contingencias Comunes": 545.65}, "details": {"Fecha de cargo en cuenta": "30/11/2026"},
    }
    assert items[1] == {"period": "2026-10", "concept": "Régimen Especial", "amount_eur": 1633.99}
    assert page_position("1 de 7") == (1, 7)


def test_prosa_page_parsing():
    from autonomo.providers import prosa

    page = """<html><script id="xslUri" href="/Notificaciones/templates/ListaNotif_ES.xsl" type="text/plain"></script>
    <script id="xml" type="text/plain"><ProsaXMLData><SPM arqobj="ed">
      <NOTIFICACIONES><NOTIFICACION><ID_NOT_GESTION>1</ID_NOT_GESTION><MATERIA><NOMBRE_MATERIA><![CDATA[Recaudación]]></NOMBRE_MATERIA></MATERIA></NOTIFICACION>
      <NOTIFICACION><ID_NOT_GESTION>2</ID_NOT_GESTION></NOTIFICACION></NOTIFICACIONES>
      <ARQ id="ARQ"><SPM.TICKET>t1</SPM.TICKET><SPM.URLFRONTEND>/ProsaInternet/OnlineAccessUtf8</SPM.URLFRONTEND>
        <SPM.IDSESSION>;jsessionid=abc</SPM.IDSESSION><SPM.CONTEXT><![CDATA[internet]]></SPM.CONTEXT>
        <MESSAGES><MESSAGE><TIPO>AVISO</TIPO><TEXTO><![CDATA[No existen  deudas.]]></TEXTO></MESSAGE></MESSAGES></ARQ>
    </SPM></ProsaXMLData></script></html>"""

    parsed = prosa.parse(page)

    assert parsed.view.endswith("ListaNotif_ES.xsl")
    notifs = prosa.as_list(parsed.data["NOTIFICACIONES"]["NOTIFICACION"])
    assert [n["ID_NOT_GESTION"] for n in notifs] == ["1", "2"] and notifs[0]["MATERIA"]["NOMBRE_MATERIA"] == "Recaudación"
    assert parsed.messages == [{"type": "AVISO", "text": "No existen deudas."}]
    assert parsed.form_url("sp.seg-social.es") == "https://sp.seg-social.es/ProsaInternet/OnlineAccessUtf8;jsessionid=abc"
    assert parsed.form_base()["ARQ.SPM.TICKET"] == "t1" and "ARQ" not in parsed.data


# -- panel ---------------------------------------------------------------------------


class FakeProvider:
    def __init__(self, answers, ok=True):
        self.answers, self.ok = answers, ok

    def doctor(self, online=False):
        from autonomo.core.provider import Check

        return [Check("x", self.ok)]

    def fetch(self, resource, params, options):
        value = self.answers[resource]
        if isinstance(value, Exception):
            raise value
        return value

    def close(self):
        pass


def test_panel_pendientes_reports_every_source():
    from autonomo.providers.panel import Panel

    panel = Panel({})
    panel._providers = {
        "aeat": FakeProvider({
            "deudas": {"text": "Avisos\nTiene 1 deuda pendiente: 120,00 €"},  # unknown content -> attention
            "notificaciones": {"text": "No tiene notificaciones pendientes de notificar no leídas\nNo tiene notificaciones notificadas no leídas\nNo tiene comunicaciones no leídas"},
            "alertas": RemoteError("AEAT down"),
        }),
        "seguridad-social": FakeProvider({
            "deudas": {"has_debts": False, "messages": [{"type": "AVISO", "text": "No existen deudas"}]},
            "notificaciones": {"count": 0, "window": {"desde": "a", "hasta": "b"}},
            "avisos": {"text": "Tus avisos\nAvisos no leídos\nAviso X\nAvisos leídos\nViejo"},
            "resumen": {"text": "Tu próxima cuota\n607,35\n€\nPago\n30\nnov\n2026"},
        }),
        "facturadirecta": FakeProvider({}, ok=False),
    }

    result = panel.fetch("pendientes", {}, FetchOptions())
    status = {(c["source"], c["item"]): c["status"] for c in result["checks"]}

    assert status[("aeat", "deudas")] == "attention"
    assert status[("aeat", "notificaciones")] == "ok"
    assert status[("aeat", "alertas")] == "error"
    assert status[("seguridad-social", "avisos no leídos")] == "info"
    assert status[("facturadirecta", "facturas vencidas")] == "skipped"
    assert next(c for c in result["checks"] if c["item"] == "próxima cuota")["detail"] == "607,35 € on 30 nov 2026"


def test_cert_portal_policy_applies_to_every_redirect_hop():
    target = "https://www1.agenciatributaria.gob.es/wlpl/GNNO-JDIT/AbrirNotificacion?id=1"
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": target})

    aeat = AEAT({"nif": "12345678Z"}, transport=httpx.MockTransport(handler))
    with pytest.raises(RemoteError, match="Redirect blocked"):
        aeat.fetch("notificaciones", {}, FetchOptions())
    assert target not in seen  # the notification-opening URL is never requested


def test_seguridad_social_page_and_saml_form_policy():
    from autonomo.providers.seguridad_social import SeguridadSocial, _saml_form

    ss = SeguridadSocial({}, transport=httpx.MockTransport(ok))
    for url in ("https://sp.seg-social.es/ProsaInternet/OnlineAccess", "https://portal.seg-social.gob.es/wps/x/p0/IZ7=Eaccion!BAJA==/"):
        with pytest.raises(UsageError):
            ss.check_page(url)
    page = (
        '<form name="langForm" action="https://idp.seg-social.es/PGIS/Login?seleccion=none"><input type="hidden" name="sessionLocale" value="fr"/></form>'
        '<form name="redirectForm" action="https://ipce.seg-social.es/IPCE/Login"><input type="hidden" name="SAMLRequest" value="x"/>'
        '<input type="hidden" name="RelayState" value="r"/><input type="hidden" name="accion" value="BAJA"/></form>'
    )
    assert _saml_form(page) == ("https://ipce.seg-social.es/IPCE/Login", {"SAMLRequest": "x", "RelayState": "r"})


def test_http_errors_hide_query_and_ids():
    client = make_client(transport=httpx.MockTransport(lambda r: httpx.Response(400, text="NIF 12345678Z no valido")))
    from autonomo.core.http import send

    with pytest.raises(RemoteError) as err:
        send(client, "GET", "https://x.test/a?nif=12345678Z")
    assert "12345678Z" not in err.value.message and "12345678Z" not in err.value.body


def test_cert_reimport_keeps_working_copy_when_keyring_fails(tmp_path, cert_home, monkeypatch):
    from autonomo.core import certstore

    original = make_p12(tmp_path / "c.p12", password=b"pw")
    pw = tmp_path / "pw"
    pw.write_text("pw")
    assert main(["cert", "import", str(original), "--password-file", str(pw)]) == 0
    section = load_config()["certificate"]

    def broken(*args):
        raise ConfigError("keyring down")

    monkeypatch.setattr(certstore, "keyring_set", broken)
    # Same certificate: the stored password is reused, so the keyring is not touched.
    assert main(["cert", "import", str(original), "--password-file", str(pw)]) == 0
    # Different certificate: keyring failure aborts before the active copy changes.
    other = make_p12(tmp_path / "other.p12", password=b"pw")
    assert main(["cert", "import", str(other), "--password-file", str(pw), "--replace"]) == 3
    assert load_config()["certificate"] == section
    assert Certificate.from_settings(section).password_source == "OS keyring"
    assert not list(Path(section["path"]).parent.glob("*.tmp"))


def test_policy_checks_normalized_url_and_page_policy_on_every_hop():
    from autonomo.providers.seguridad_social import SeguridadSocial

    seen = []
    aeat = AEAT({"nif": "12345678Z"}, transport=httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200, html="<p>x</p>")))
    with pytest.raises(UsageError, match="comparecencia"):
        aeat.get_page("https://www1.agenciatributaria.gob.es/x/../wlpl/gnno-JDIT/Abrir?nif=12345678Z")
    assert not seen

    def importass(request):
        return httpx.Response(302, headers={"location": "https://sp.seg-social.es/ProsaInternet/OnlineAccess"})

    ss = SeguridadSocial({}, transport=httpx.MockTransport(importass))
    ss._logged_in = True
    with pytest.raises(RemoteError, match="Redirect blocked"):
        ss.fetch("page", {"url": "https://portal.seg-social.gob.es/wps/myportal/x"}, FetchOptions())


def test_saml_form_rejects_unknown_endpoint_and_ambiguity():
    from autonomo.providers.seguridad_social import _saml_form

    form = '<form action="{}"><input type="hidden" name="SAMLResponse" value="x"/></form>'
    with pytest.raises(RemoteError, match="unexpected endpoint"):
        _saml_form(form.format("https://portal.seg-social.gob.es/wps/myportal/importass/importass/tramites/baja"))
    with pytest.raises(RemoteError, match="more than one"):
        _saml_form(form.format("https://idp.seg-social.es/PGIS/Login") * 2)
    for bad in ("https://idp.seg-social.es/PGIS/Login/extra", "https://idp.seg-social.es:8443/PGIS/Login"):
        with pytest.raises(RemoteError, match="unexpected endpoint"):
            _saml_form(form.format(bad))
    assert _saml_form(form.format("https://idp.seg-social.es:443/PGIS/Login"))[0] == "https://idp.seg-social.es/PGIS/Login"


def test_facturadirecta_download_refuses_plain_http_redirect(fd_env):
    def handler(request):
        if request.url.host == "app.facturadirecta.com":
            return httpx.Response(302, headers={"location": "http://storage.example.com/f.pdf"})
        return httpx.Response(200, content=b"%PDF")

    fd = FacturaDirecta({}, transport=httpx.MockTransport(handler))
    with pytest.raises(RemoteError, match="non-https"):
        fd.fetch("download", {"url": "https://app.facturadirecta.com:443/api/f.pdf"}, FetchOptions())


def test_facturadirecta_download_follows_up_to_the_redirect_limit(fd_env):
    def handler(request):
        hop = int(request.url.path.rsplit("/", 1)[-1] or 0)
        if hop < 5:
            return httpx.Response(302, headers={"location": f"https://storage.example.com/{hop + 1}"})
        return httpx.Response(200, content=b"%PDF")

    fd = FacturaDirecta({}, transport=httpx.MockTransport(handler))
    assert fd.fetch("download", {"url": "https://storage.example.com/0"}, FetchOptions()).content == b"%PDF"
