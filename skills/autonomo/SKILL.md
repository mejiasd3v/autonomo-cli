---
name: autonomo
description: Read the user's Spanish self-employed (autónomo) data with the autonomo CLI. FacturaDirecta invoices, expenses, contacts, banks, accounting, and generated tax forms; AEAT debts, unread notifications, alerts, recent logins, Renta datos fiscales (modelo 130 payments, RETA contributions, income, properties), and fiscal address status; Seguridad Social pages (experimental). Read-only. Use for questions about the user's invoices, taxes, Hacienda, Seguridad Social, or cuotas.
---

# autonomo

`autonomo` is on PATH. It only reads. Every remote write is blocked in the HTTP
layer, so never look for a way to create, change, send, or pay anything.
Output is JSON on stdout. Errors are JSON on stderr with `error`, `hint`, and
an exit code: 2 usage, 3 configuration, 4 read-only violation, 5 remote error.

## Discover

```sh
autonomo providers                    # providers and whether they are configured
autonomo resources facturadirecta     # resources, params, status (stable/experimental)
autonomo doctor [PROVIDER] --online   # credentials, certificate expiry, live access
```

Run `autonomo resources PROVIDER` before you guess a resource or parameter name.
On a configuration error, show the `hint` to the user. Do not ask the user to
paste secrets into the chat.

## Certificate setup (AEAT, Seguridad Social)

Start here when `doctor` reports `No certificate configured`, or when the user
asks to connect Hacienda or Seguridad Social.

1. **Check first.** `autonomo cert status`. If a valid certificate is
   configured, stop. Do not import again.
2. **Find candidates.** `autonomo cert find` (add `--dir PATH` if the user
   names a folder). It returns `files` (.p12/.pfx; most are `locked`, so
   expiry is unknown until import) and `os_store` (identities in the macOS
   Keychain with issuer and expiry).
3. **Pick with the user.** Show a short list: path or store, holder (already
   masked), issuer, `not_after`. Prefer `spanish_ca: true`, `client_auth: true`,
   not expired, newest. Skip developer certificates (Apple, mkcert, mitmproxy).
   Ask the user to confirm which one. Never guess between two valid ones.
4. **Only in an OS store?** A Keychain/Windows-store identity must be exported
   to a .p12 first. Give the user the export steps from `hints`. The user sets
   the export password; tell them not to send it to you.
5. **Import.** The import needs the certificate password. Use the first option
   that is available to you:
   - **The user runs it.** Ask the user to run this in their own terminal; it
     shows a hidden prompt:
     `autonomo cert import "PATH"`
   - **Secure secret input.** If your harness has a private secret-input tool
     that writes the value to a file, request the password with it, then run
     `autonomo cert import "PATH" --password-file "FILE"`.

   Never ask for the password in chat. Never put it in a command line,
   environment variable you print, or file you create. Never `cat`, `echo`, or
   log the password file. If the password is wrong (exit 3, "wrong password"),
   ask the user to retry the same way; do not try guesses.
6. **Verify.** `autonomo cert status`, then `autonomo doctor aeat --online`.
   `mtls: ok` means AEAT accepted the certificate.
7. **Tidy up.** Tell the user that autonomo keeps its own AES-256-encrypted copy
   and the original file is no longer needed. Suggest they delete copies left
   in Downloads or Desktop. Do not delete them yourself.

Errors: `expired` means renew at the issuer (FNMT: sede.fnmt.gob.es), then
import the new one. `OS keyring unavailable` (headless Linux) means skip import:
set `[certificate].path` and provide `AUTONOMO_CERT_PASSWORD` from the user's
secret manager. `Another certificate is already imported` means ask the user
before you use `--replace`. To undo an import: `autonomo cert remove`.

## Read

```sh
autonomo get PROVIDER RESOURCE [key=value ...] [--all] [--out FILE_OR_DIR]
```

### FacturaDirecta (stable)

```sh
autonomo get facturadirecta invoices minDate=2026-01-01 maxDate=2026-03-31 --all
autonomo get facturadirecta invoices state=pending
autonomo get facturadirecta invoice id=inv_... related=balance,state
autonomo get facturadirecta bills minDate=2026-01-01 --all        # gastos
autonomo get facturadirecta tax-declarations fiscalYear=2026      # 303, 130... generated
autonomo get facturadirecta results-summary startDate=2026-01-01 endDate=2026-12-31
autonomo get facturadirecta banks
autonomo get facturadirecta search q="texto"
autonomo get facturadirecta attachments type=invoices id=inv_...
autonomo get facturadirecta download url=https://... --out /tmp/
autonomo get facturadirecta raw path=invoices/inv_.../versions
```

Lists return `{pagination, items}`. `--all` follows pagination and returns
`{items, count}`. Without `--all`, do not claim you saw every item. List
resources accept any filter documented in https://app.facturadirecta.com/openapi.json
(dates are `YYYY-MM-DD`).

### AEAT (needs the digital certificate; see Certificate setup)

```sh
autonomo get aeat deudas                             # pending debts (query only)
autonomo get aeat notificaciones                     # unread notifications summary, never opens one
autonomo get aeat alertas                            # personal alerts
autonomo get aeat ultimos-accesos                    # recent logins to the sede (table)
autonomo get aeat datos-fiscales year=2025           # Renta data as JSON, amounts in euros
autonomo get aeat domicilio-ratificado year=2025
autonomo get aeat certificate                        # no network
autonomo get aeat page url=https://www1.agenciatributaria.gob.es/...
```

HTML pages come back as `{title, text, tables, links}`. `text` holds only the
page's main content. Empty states are plain sentences such as
"No existen deudas para mostrar". Quote them rather than inferring.

`datos-fiscales` returns `records`, one group per AEAT record type, each with
`code`, `title`, and `items`. Useful codes for an autónomo: `PF` (modelo 130
pagos fraccionados, `periodo` 1T-4T), `CT` (RETA contributions), `RET` (RETA
regularization), `RTA`/`RTC` (income and withholdings reported by payers),
`UR` (properties), `PHD` (mortgage), `DN` (donations), `TI`/`DE` (holder and
descendants). The file only exists for fiscal years AEAT has published; a
missing year is exit 5 with a hint. NIF and IBAN are masked unless the user
asks; `mascara=no` shows them. `formato=raw` returns the official fixed-width
file. If `warnings` says the layout year differs, flag the numbers as
unverified.

Do not follow links from `deudas` (they lead to payment flows) or from
`notificaciones`.

**Notifications: never try to open one.** Opening the content of a
notification counts as legal receipt (comparecencia) and starts deadlines. The
CLI blocks those URLs. Report the list to the user and tell them to open the
notification themselves when they decide to.

### Seguridad Social (experimental)

Only `certificate` and `page` exist. The login flow is not mapped yet, so pages
usually end on a login screen (exit 5 with a hint). Say so to the user instead
of retrying.

## Privacy

Results contain personal tax data. Quote only what the task needs. Do not
paste NIFs, IBANs, or full addresses into external services.
