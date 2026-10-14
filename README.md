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

**Track.** An asset-grouped ticket dashboard with severities, SLA clocks, inline edits, assignment, and activity history. SLA days per severity are yours to set.

**Route.** Rules that match a source, an asset, or a CVE assign incoming findings to the right owner. Suppression rules filter known noise at ingest.

**Hand off without accounts.** The people who fix things get a magic-link portal (`/share/{token}`) to submit a fix or request more time. Risk approvers get their own (`/review/{token}`) to approve or deny. Nobody outside the security team needs a login.

**Accept risk on the record.** A request, review, approve or deny pipeline for exceptions, with the SLA effects applied and every step in the audit log.

**Flag what is exploited.** Load the CISA Known Exploited Vulnerabilities catalog yourself and matching findings are flagged. Nothing is fetched; the tool never leaves your network.

**Pentest workflow.** Upload an engagement report at `/reports/upload`, parse it, and promote findings through a draft queue into real tickets, with CVSS vector, CWE, business impact, and screenshots on each. Reusable finding templates stop you retyping the same write-up. Then go the other way: select findings and generate a branded engagement report as Markdown or a self-contained, print-ready HTML document (`POST /api/reports/branded`, fetch with `GET /api/reports/branded/{id}?format=md|html`). Print the HTML to PDF for the client deliverable.

**Roles, keys, audit.** Four roles (Sheriff, RangeHand, Wrangler, Magistrate) enforced by middleware, service accounts with API keys, and an immutable audit log.

## How it is built

- One Go module, `github.com/Kuebiko-LLC/riskrancher`.
- Pure-Go SQLite (`modernc.org/sqlite`), so no CGO and no external database. One file holds everything.
- Server-rendered Go templates with htmx on native `net/http`. No SPA, no build step.
- Tests run against a real SQLite database: `go test ./...`.

## Not finished yet

Scaffolded, off the critical path, and does not affect boot:

- **Direct PDF export.** Reports come out as Markdown and self-contained HTML today. Print the HTML to PDF. In-process PDF rendering is not wired, to keep the binary CGO-free.
- **Local-embedding triage and asset matchmaking.** `pro/storage/pro_embeddings.go` and `pro/storage/pro_matchmaker.go` sketch the idea; their tables are not created by the schema and no local model is wired. A design sketch, not a feature.

## The book

The method behind the tool is written up, free, as [The Risk Rancher Field Manual](https://t0ul.com/blog/risk-rancher-field-manual-intro/). It works a sample scanner export by hand across the whole program, then runs the same file through this tool.

## License

Apache License 2.0. See [LICENSE](LICENSE).
