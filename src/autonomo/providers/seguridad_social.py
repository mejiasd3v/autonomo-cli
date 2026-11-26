"""Seguridad Social (TGSS/INSS), read-only. Experimental.

Status: there is no documented machine interface for individuals. Importass
and the sede run on IBM WebSphere Portal with a JavaScript login step, so plain
mTLS requests usually end on a login page. ipce.seg-social.es asks for a
client certificate at TLS level and is the likely certificate login point,
but the flow is not mapped yet.

What works now: `certificate` and `page` (GET with the certificate inside the
allowlist). Next step: map the login flow with a browser session, then add
services here (recibos de cuotas, vida laboral, deudas).
"""

from __future__ import annotations

from ._cert_portal import CertPortal


class SeguridadSocial(CertPortal):
    name = "seguridad-social"
    title = "Seguridad Social"
    description = "Experimental. Sede e Importass con certificado digital. Solo `page` por ahora: el login de la Seguridad Social aún no está mapeado."
    hosts = (
        "sede.seg-social.gob.es",
        "portal.seg-social.gob.es",
        "ipce.seg-social.es",
    )
    probe_url = "https://ipce.seg-social.es/"
