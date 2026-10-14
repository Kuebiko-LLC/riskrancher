# RiskRancher

Vulnerability management in a single Go binary. Self-hosted, air-gapped, free.

Ingest findings from any scanner, map the fields once, and run the whole program out of one tracker: triage, owners, SLAs, exceptions, metrics. Pentesters get the same engine pointed the other way: upload an engagement report, promote its findings into tickets, and generate the client report back out.

No Postgres, no Redis, no Docker Compose, no Kubernetes, no license key, no telemetry. Apache License 2.0.

## Quick start

Requires Go 1.26 or later.

```bash
git clone https://github.com/Kuebiko-LLC/riskrancher.git
cd riskrancher
go build -o rr ./cmd/rr
./rr
```

Open http://localhost:8080, register the first user (that account is the admin), then go to **Ingest**. Pick the built-in **Trivy Container Scan** adapter and upload [`examples/trivy-sample.json`](examples/trivy-sample.json) to see findings become tickets.

To seed a full demo environment instead:

```bash
go run ./cmd/mint
```

It wipes the ticket table, seeds every dashboard tab, and prints working portal links for each role.

## What it does

**Ingest.** Upload any export (Qualys, Nessus, Trivy, Semgrep, Prowler, Dependabot, or your own CSV and JSON), map title, asset, severity, description, and remediation in the Adapter Builder, and ingest. No custom parsers. Findings are deduplicated on source, asset, and title, so a re-scan never doubles a ticket. A finding that disappears from the next scan closes as patched; one that comes back reopens.

**Track.** An asset-grouped ticket dashboard with severities, SLA clocks, inline edits, assignment, and each finding's history in the drawer. SLA days per severity and per domain are yours to set; a scanner's spelling of severity (CRITICAL, critical) is normalized so the matrix matches. Load the CISA KEV catalog and findings naming a listed CVE are flagged as they arrive.

**Prioritize.** Load the asset inventory (a CSV with asset, criticality, exposure, owner, notes; the one chapter two of the book has you write) under Admin, Configuration. A finding on a listed asset is scored at ingest: the scanner's severity as the base, times the asset's exposure and criticality, banded into Critical, High, Medium or Low. The drawer shows the arithmetic. An asset the tool does not know keeps the scanner's word. The weights and bands are yours to edit; saving them, or loading a new inventory, rescores the open findings and writes a line in each finding's history. A severity an analyst set by hand is rescored too, so a standing exception belongs in a severity rule.

**Route.** Rules that match a source or an asset assign incoming findings to the right owner at ingest, and pick up unowned findings already on the asset. Severity rules rewrite the severity of everything from a source or on an asset, and win over the rubric. Suppression rules close known noise at ingest.

**Hand off without accounts.** The people who fix things get a link (`/share/{token}`) to submit a fix with evidence, send a finding back, or ask for more time or for the risk to be accepted. Risk approvers get a link of their own kind (`/review/{token}`), minted by the Sheriff from Risk Reviews with context for the approver, to approve or deny one finding at a time. An owner's link cannot decide and an approver's link cannot fix, and a link ends as soon as its findings have left that person. Nobody outside the security team needs a login.

**Accept risk on the record.** The approver's decision either pushes the due date, counted against the SLA policy's extension cap, or holds the finding as Risk Accepted with the approver and an expiry recorded. When the expiry passes, the next restart or upload puts the finding back on the queue with a fresh clock. Every step is in the audit log.

**Flag what is exploited.** Load the CISA Known Exploited Vulnerabilities catalog JSON from Admin, Configuration. Findings naming a listed CVE are flagged, now and as they arrive, and a flagged finding is Critical whatever the rubric or a rule says: the load raises every open finding it newly flags and restarts its clock from the day it was found. A CVE that leaves the catalog is unflagged but not lowered. Nothing is fetched; the tool makes no network calls.

**Pentest workflow.** Upload an engagement report (DOCX) at `/reports/upload`; it is rendered beside a draft form, and the findings you write up are promoted through the same rules engine as scanner findings. Engagements hold findings until release; finding templates carry CVSS vector, CWE and business impact and stop you retyping the same write-up; screenshots attach as evidence. Then go the other way: select findings and generate a branded engagement report as Markdown or a self-contained, print-ready HTML document (`POST /api/reports/branded`, fetch with `GET /api/reports/branded/{id}?format=md|html`). Print the HTML to PDF for the client deliverable.

**API keys.** A Sheriff mints a key (`POST /api/admin/apikeys`, shown once) and a scanner or pipeline sends it as `Authorization: Bearer <key>` on any API route. A key acts as the user who created it; a ReadOnly key can only GET. List and revoke under `/api/admin/apikeys`.

**Log a false positive.** `POST /api/admin/suppression` with the finding's source, asset and title (or its dedupe hash) and a rationale. That finding lands closed as False Positive on every scan after, on that asset, until the rule is deleted.

**Roles, keys, audit.** Five roles enforced by middleware: Sheriff (admin), RangeHand (analyst), Wrangler (fixer), Magistrate (risk approver), Bounty Hunter (pentester). API keys act as the user who minted them. Every change, every refusal and every sign-in lands in an append-only audit log, by the person who did it, including the owner behind a link; successful reads are left out.

## API

Everything the pages do is a route a script can call with a session cookie or a bearer key. The ones not covered above:

- `GET /api/tickets?limit=100&offset=0` lists released findings with asset, source, owner, status and clock; `GET /api/tickets/{id}/activity` is one finding's history; `POST /api/tickets` creates one; `PATCH /api/tickets/{id}` edits severity, text and comment; `PATCH /api/tickets/bulk` changes status or owner for many and mints the owner's link; `POST /api/tickets/review-link` mints the approver's link over findings waiting for a decision; `PATCH /api/tickets/{id}/review` is the Sheriff deciding one from the office.
- `POST /api/ingest/{adapter}` (JSON), `POST /api/ingest/csv` (multipart `file` + `adapter_name`), `POST /api/ingest` (raw JSON array). `GET`/`POST /api/adapters`, `DELETE /api/adapters/{id}`.
- `GET /api/admin/users`, `GET`/`POST /api/admin/routing`, `GET`/`POST`/`DELETE /api/admin/triage` (severity rules), `GET`/`POST`/`DELETE /api/admin/suppression`, `GET`/`POST`/`DELETE /api/admin/apikeys`, `GET`/`PUT /api/config` (SLA matrix and defaults), `GET /api/admin/assets`, `POST /api/admin/assets/csv` (multipart `file`: the inventory with `asset,criticality,exposure,owner,notes`), `DELETE /api/admin/assets/{asset}`, `GET`/`PUT /api/admin/rubric` (the fourteen weights and bands; saving rescores the open findings on inventoried assets), `GET /api/admin/logs`, `GET /api/admin/export`.
- `GET`/`POST /api/integrations/cisa` (status; `cisa/sync` takes the catalog as multipart `cisa_catalog_file`).
- Pentest: `/api/engagements`, `/api/finding-templates`, `PUT /api/findings/{id}` (CVSS, CWE, impact), `/api/findings/{id}/evidence`, `/api/reports/upload`, `GET /api/reports/view/{id}`, `/api/reports/branded`.
- `POST /api/admin/shutdown` stops the server, for swapping the binary on an air-gapped box.

A test reads every call the pages make and checks the router has it, and lists any API route no page reaches and this README does not mention.

## Schema changes

`pkg/datastore/schema.sql` is the baseline: the whole schema for a fresh install, applied as version 1. Changes to a database that already exists in the field go in as migrations in `pkg/datastore/db.go`, one entry per version, and the `schema_migrations` table records how far each database has been upgraded.

While nothing runs in production, the simpler path is fine: edit the baseline, delete `data/riskrancher.db`, start again. Once an install exists that must keep its data, leave the baseline alone and append a migration.

## How it is built

- One Go module, `github.com/Kuebiko-LLC/riskrancher`: `cmd/rr` boots it, `pkg/` is the product (one store, `pkg/datastore.SQLiteStore`, behind one interface, `pkg/domain.Store`), `ui/` is the templates and scripts.
- Pure-Go SQLite (`modernc.org/sqlite`), so no CGO and no external database. One file holds everything.
- Server-rendered Go templates and plain scripts on native `net/http`. No SPA, no build step, no outbound calls.
- Tests run against a real SQLite database: `go test ./...`.

## Not finished yet

- **Direct PDF export.** Reports come out as Markdown and self-contained HTML today. Print the HTML to PDF. In-process PDF rendering is not wired, to keep the binary CGO-free.

## The book

The method behind the tool is written up, free, as [The Risk Rancher Field Manual](https://t0ul.com/blog/risk-rancher-field-manual-intro/). It works a sample scanner export by hand across the whole program, then runs that file and a million-row export through this tool, step by step.

## License

Apache License 2.0. See [LICENSE](LICENSE).
