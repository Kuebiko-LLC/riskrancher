# RiskRancher

Open-source **vulnerability management** in a single Go binary. Core plus every Pro and Auditor feature, folded into one project and switched on by default. No Postgres, no Redis, no Docker Compose, no Kubernetes, no license key, no telemetry.

Apache License 2.0

## What it is

RiskRancher is a self-hosted, air-gapped vulnerability-management platform for security engineers and pentesters. Ingest findings from any scanner (Qualys, Nessus, Trivy, Semgrep, Prowler, Dependabot, or custom JSON/CSV), map fields in a no-code Adapter Builder, and drive remediation through a ticket workflow with asset grouping, SLAs, risk exceptions, and magic-link portals for the people who do the work.

This repository is the merge of the former `risk-rancher-core` (the free OSS tier) and `risk-rancher-pro` (the commercial tier) into one codebase. The commercial paywall is gone: the binary boots with all Pro and Auditor capabilities active.

## The open edition

The license manager still ships, but it boots already unlocked (`license.NewManager` is active out of the gate) so nothing is gated. The RSA verification code is kept intact but dormant, so a commercial fork could re-enable gating by booting the manager inactive. Day to day you never touch a key. `RR_PRO_LICENSE_KEY`, if set, only labels the company banner.

## Features

### Core platform (always was open)
- **Single binary + SQLite.** Pure-Go SQLite via `modernc.org/sqlite`, so there is no CGO and no external database.
- **No-code scanner connectors.** Upload any export, map title / asset / severity / description / remediation in the Adapter Builder, ingest. No custom parsers.
- **Asset-grouped ticket dashboard.** Severities, SLAs, inline edits, and activity history.
- **100% air-gapped.** Zero telemetry, zero outbound calls. Findings stay on your machine.

### Pentesting workflow
- **Engagement report intake.** Pentesters upload a report (`/reports/upload`), parse it, and promote findings into real tickets through a draft queue, instead of leaving them in a Word document.
- **Findings as tickets.** Every finding lands in the same tracker the rest of the program runs on.

### Enterprise features (now open, on by default)
- **Four-persona RBAC.** A bouncer middleware enforces Sheriff, RangeHand, Wrangler, and Magistrate roles across the app.
- **Magic-link portals.** IT reviewers get a `/share/{token}` portal to submit fixes or request exceptions; risk approvers get a `/review/{token}` portal to approve or deny. No account needed for the external parties.
- **Auto-assign rules engine.** Route incoming findings by source, asset, or CVE.
- **Suppression + global suppression rules.** Filter known-noise at ingest.
- **Risk-exception pipeline.** End to end request, review, approve/deny, with SLA effects.
- **CISA KEV catalog.** Air-gapped known-exploited-vulnerability flagging.
- **Service accounts (API keys)** and an **immutable audit log**.

## Quick start

Requires **Go 1.26+**.

```bash
git clone https://github.com/Kuebiko-LLC/riskrancher.git
cd riskrancher
go build -o rr ./cmd/rr
./rr
# open http://localhost:8080, register the first user (admin), then Ingest
```

Ingest a sample in five minutes: go to **Ingest**, pick or build the **Trivy Container Scan** adapter, and upload [`examples/trivy-sample.json`](examples/trivy-sample.json).

### Seed a demo environment

```bash
go run ./cmd/mint   # wipes tickets, seeds all dashboard tabs + working magic portals
```

It prints the Analyst dashboard, Wrangler (`/share/...`), and Magistrate (`/review/...`) URLs to open.

## Architecture

- **One Go module** (`github.com/Kuebiko-LLC/riskrancher`). The former two repos are now `pkg/...` (core) and `pro/...` (the folded-in enterprise layer).
- **Composition, not duplication.** `cmd/rr` boots the core `datastore`, layers the Pro schema over the same SQLite file (`storage.InjectProSchema`), wraps the core store in the Pro store, registers both route sets, and injects the Pro templates over the core UI map.
- **Server-rendered Go + htmx.** Native `net/http` routing, Go templates, no SPA.
- **Testing.** BDD-style (`Given / When / Then`) against a real SQLite database. Run `go test ./...`.

## Roadmap (honest status)

These are scaffolded but not finished. They are off the critical path and do not affect boot:

- **Auditor branded-PDF export.** `pro/reporting` is a stub today; report intake and viewing work, branded PDF generation does not.
- **AI SOC Brain (experimental).** `pro/storage/pro_embeddings.go` and `pro/storage/pro_matchmaker.go` sketch local-embedding triage and ASPM asset matchmaking, but their backing tables (`pro_ticket_embeddings`, `matchmaker_proposals`) are not created by the schema yet and no local-LLM sidecar is wired. Treat this as a design sketch, not a shipped feature.

## License

Apache License 2.0. See [LICENSE](LICENSE).
