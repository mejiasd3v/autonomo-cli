---
name: autonomo
description: Read the user's Spanish self-employed (autónomo) data with the autonomo CLI. FacturaDirecta invoices, expenses, contacts, banks, accounting, and generated tax forms; AEAT debts, unread notifications, alerts, recent logins, Verifactu invoice records, Renta datos fiscales (modelo 130 payments, RETA contributions, income, properties), and fiscal address status; Seguridad Social (Importass: next cuota, RETA receipts, vida laboral, contribution bases, regularization, notices, files). Read-only. Use for questions about the user's invoices, taxes, Hacienda, Seguridad Social, or cuotas.
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

## Start here: panel

For "anything pending?", "do I owe anything?", or a general status question,
run the panel first. It checks every source in one call (about 10 seconds):

```sh
autonomo get panel pendientes        # debts, notifications, alerts, unread notices, next cuota, overdue invoices
autonomo get panel reta year=2025    # RETA paid (Importass receipts) vs reported to AEAT; regularizations
autonomo get panel pagos-130 year=2025   # modelo 130 per quarter: AEAT vs FacturaDirecta
```

Each `pendientes` check has `status`: `ok`, `attention` (act or tell the
user), `info`, `unknown` (say you could not tell), `error` (that source
failed; report it), `skipped` (source not configured). Never present `error`,
`unknown` or `skipped` as "nothing pending". `reta` returns `status` `match`,
`mismatch` (with `difference_eur` and a note on why amounts can shift between
years) or `incomplete`. Drill down with the provider resources below.

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
(dates are `YYYY-MM-DD`). Each list item is `{content, creationDate,
modificationDate, webUrl}`; the id for `invoice id=...` and friends is
`items[].content.uuid`. `search q=` needs at least 2 characters. A 400 error
carries the API's own validation message in `body`: read it before retrying.

Setup, when `doctor facturadirecta` fails: the user copies the company id from
Ajustes > API e integraciones into `[facturadirecta] company_id` in the config
file, and creates an API key with only `:read` scopes. Store the key like the
certificate password: the user runs `autonomo secret set AUTONOMO_FD_API_KEY`
(hidden prompt), or you use a private secret-input tool and
`--value-file FILE`. Never ask for the key in chat.

### AEAT (needs the digital certificate; see Certificate setup)

```sh
autonomo get aeat deudas                             # pending debts (query only)
autonomo get aeat notificaciones                     # unread notifications summary, never opens one
autonomo get aeat alertas                            # personal alerts
autonomo get aeat ultimos-accesos                    # recent logins to the sede (table)
autonomo get aeat datos-fiscales year=2025           # Renta data as JSON, amounts in euros
autonomo get aeat domicilio-ratificado year=2025
autonomo get aeat verifactu year=2026 mes=03          # Verifactu invoice records you issued, as AEAT has them
autonomo get aeat verifactu rol=recibidas year=2026 --all   # records where you are the recipient
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

`verifactu` (experimental) runs the official `ConsultaFactuSistemaFacturacion`
query, one request per month. Params: `rol` (`emitidas` default, `recibidas`),
`year`, `mes` (01-12; without it, every month of the year up to now), `numserie`,
`desde`/`hasta` (`YYYY-MM-DD`, same year). It returns `{rol, year, periodos,
count, more, items}`. Each item has `periodo`, `IDFactura`,
`DatosRegistroFacturacion` (TipoFactura, Desglose, CuotaTotal, ImporteTotal,
Huella...) and `EstadoRegistro` (`Correcto`, `AceptadoConErrores`, `Anulado`),
with AEAT's own field names; amounts are strings in euros. `more: true` means a
month has more than one page: repeat with `--all` before you sum. `count: 0`
means AEAT has no Verifactu records for that period: invoices from a non
Verifactu system (or before the obligation applies) do not appear here, so do
not read it as "no invoices". It only queries; the CLI never sends or cancels
records.

Do not follow links from `deudas` (they lead to payment flows) or from
`notificaciones`.

**Notifications: never try to open one.** Opening the content of a
notification counts as legal receipt (comparecencia) and starts deadlines. The
CLI blocks those URLs. Report the list to the user and tell them to open the
notification themselves when they decide to.

### Seguridad Social (Importass, needs the digital certificate)

```sh
autonomo get seguridad-social resumen            # alta status, days, current base, next cuota + breakdown
autonomo get seguridad-social recibos --all      # every RETA receipt since 2018: period, amount, breakdown, charge date
autonomo get seguridad-social recibos desde=2025-01 hasta=2025-12 --all
autonomo get seguridad-social vida-laboral       # table: employer/regime, dates, days per period
autonomo get seguridad-social bases-cotizacion --all   # every monthly base, by regime or employer
autonomo get seguridad-social regularizacion     # yearly regularization results (a ingresar / a devolver)
autonomo get seguridad-social avisos             # Importass notices (not legal notifications)
autonomo get seguridad-social expedientes        # files and requests before the TGSS
autonomo get seguridad-social notificaciones     # pending sede notifications (list only, last 60 days)
autonomo get seguridad-social notificaciones historico=si                    # history, last 12 months
autonomo get seguridad-social notificaciones historico=si desde=2018-01-01  # history since a date (YYYY-MM-DD)
autonomo get seguridad-social deudas             # pending debts: has_debts + the sede's own messages
```

Each call logs in with the certificate (about 10 seconds). Pages come back as
`{title, text, tables, links}`; amounts are Spanish formatted text such as
`607,35 €`. NIF and NUSS are masked. `recibos` and `bases-cotizacion` return
`{items, count, page, pages}` with `period` (YYYY-MM) and `amount_eur` per
entry, 12 per page. Without `--all` you only have the newest page: check
`more` before you sum or claim completeness. A period with no entries returns
`count: 0` and a `note`. Receipts include regularization charges as separate
concepts ("Regularización cuotas ...").

`notificaciones` and `deudas` come from the sede (about 7 seconds each). For
`deudas`, trust `has_debts` and quote `messages`: `false` comes with the
sede's "No existen liquidaciones ni deudas" text; `true` returns the sede's
screen data under `data`; `null` means the answer was unclear, so say so.
Notifications: never try to open or sign one (comparecencia); tell the user to
do it in the sede. Without `historico` the list covers the sede's default
window only (pending, last 60 days). `historico=si` reads the history tab:
notifications already notified by acceptance or rejection, rejected after the
deadline, published or archived. Pending ones are not in it. The sede limits a
search to 60 days, so the CLI runs one search per 60-day window (`searches`).
Each item has `FECHA_PUESTA_DISPOSICION`, `MATERIA`,
`ORGANISMO`, `ASUNTO` and the state under `ACUSE/CLAVE_ACUSE/TEXTO_TIPO_ACUSE`.
If `incomplete` is present, a window had more than one page and only the first
was read: repeat with a narrower `desde`/`hasta`. Do not use
`page` to follow links into trámites (altas, bajas, modificaciones, "Informar
error"): the CLI blocks their form submissions anyway.

## Privacy

Results contain personal tax data. Quote only what the task needs. Do not
paste NIFs, IBANs, or full addresses into external services.
