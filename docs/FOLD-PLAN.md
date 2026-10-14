# One RiskRancher: folding the `pro/` layer into the product

Status: Stages 1 and 2 landed 2026-10-14. Stages land as
separate commits, suite green between each, so any stage can be bisected or reverted on its own.

## Goal

There is one product. The words Pro, Core, OSS, Enterprise, open edition, license,
paywall, and the gem emoji stop appearing in code, comments, templates, scripts,
logs, and docs. The package tree says what things are, not which tier they came from.

## What exists today (inventory, 2026-10-14)

Two layers that were two repositories:

| layer | packages | files | what it holds |
|---|---|---|---|
| `pkg/` + `ui/` | adapters, admin, analytics, auth, datastore, domain, ingest, report, server, sla, tickets; ui | base product | ingest, tickets, SLA, auth, the base UI |
| `pro/` | admin (13), api (1), evidence (1), license (1), middleware (3), models (6), reporting (1), storage (16), tickets (1), ui (1) | the folded-in layer | rules engine, magic portals, exceptions, KEV, audit, reporting, engagements, finding templates, severity proposals, evidence |

How they are wired:

- `pro/storage.ProSQLiteStore` embeds `pkg/datastore.SQLiteStore` and adds 51 methods behind `ProStoreInterface`.
- `pro/api.RegisterProRoutes` registers a second route set on the same `*http.ServeMux`; `ProUIInterceptor` wraps the handler to serve the second template set.
- `pro/ui` carries a full copy of the templates and static files (15 pages vs 11; 9 components vs 8; adds `engagements`, `severity_reviews`, `setup`, `magic/`, `pro_dashboard`, `admin_reviews`, `magic.js`, `pro_admin.js`). The core copies are the ones that are dead.
- `pro/license` + `pro/middleware/license.go` + `pro/admin/license_handler.go` + `pro/storage/pro_license.go`: a license manager that boots unlocked; `isProActive` and `getCompanyName` template funcs; `RR_PRO_LICENSE_KEY`.
- Nothing in `pkg/` or `ui/` imports `pro/`; only `cmd/{rr,seed,mint}` do. The dependency direction is clean, which is what makes the fold mechanical.
- `workspace_id` is hard-coded to 1 in 13 places. Workspaces are not a product feature today.

Counts: 22 distinct `Pro*`/`pro*` identifiers (169 uses of `proModels`, 75 of `ProHandler`, 69 of `ProSQLiteStore`, 60 of `ProStore`, 24 of `ProStoreInterface`); tier wording on roughly 90 lines across 30 files.

## Target layout

```
cmd/rr, cmd/seed, cmd/mint
pkg/
  datastore/   SQLiteStore (one type, all 51 methods merged in), schema.sql, migrate.go
  domain/      all models (pro/models folded in), Store interface (one), SLACalculator
  server/      App, routes.go (one route set), middleware (audit, auth gates)
  admin/       sheriff handlers (core + pro/admin merged)
  tickets/     ticket + portal handlers (pro/tickets merged)
  ingest/, adapters/, analytics/, auth/, report/, sla/   (unchanged)
  evidence/    (from pro/evidence)
  reporting/   (from pro/reporting)
ui/
  templates/   the pro set, renamed (pro_dashboard -> dashboard, etc.), one base.gohtml
  static/      the pro set (admin.js absorbs pro_admin.js)
```

Deleted outright: `pro/license`, `pro/middleware/license.go`, `pro/admin/license_handler.go`,
`pro/storage/pro_license.go`, the `license_key` config, `RR_PRO_LICENSE_KEY`, `setup.gohtml`
(activation page), `isProActive`, `getCompanyName`.

## Stages

### Stage 1: remove the tier (no package moves) -- DONE

1. Delete the license manager and everything that references it. `cmd/rr` boots
   `server.NewApp(store)`, registers routes, serves. No interceptor, no gate.
2. Templates: drop `isProActive` branches (always the full product) and
   `getCompanyName` (the header is the brand; a company label can return later as
   a plain config setting if wanted). Delete the dead core copies of templates and
   static files that the pro copies override.
3. Wording scrub: PRO, Core, OSS, Enterprise, open edition, paywall, gem emoji,
   "THE FIX" comments. Comments say what the code does.
4. Rename files `pro_*.go` to what they hold (`pro_sqlite.go` -> `rules.go`,
   `portals.go`, etc.).
5. Gate: `go test ./...` green, `go vet` clean, boot a fresh DB, ingest
   `examples/trivy-sample.json`, click through dashboard, admin, ingest, a magic link.

### Stage 2: one store, one domain -- DONE (51e0e57 models, storage fold)

1. Move `pro/models/*` into `pkg/domain` (rename `proModels` imports; 169 sites, `gofmt -r`
   or `gopls rename`).
2. Move the 16 `pro/storage` files into `pkg/datastore`; make the methods hang off
   `*SQLiteStore` directly; delete `ProSQLiteStore`, `NewProSQLiteStore`, `ProStoreInterface`;
   fold the 51 methods into `domain.Store`. Suppression/triage/routing layers in
   `CreateTicket` and `ProcessIngestionBatch` become the only implementation.
3. Gate: suite green. This is the stage with real merge risk: two `CreateTicket`
   and two `ProcessIngestionBatch` paths become one. Write the tests for the merged
   behavior before moving (suppression marks False Positive, severity rule applies,
   routing assigns) so the merge is checked, not assumed.

### Stage 3: one server

1. `pro/api/pro_routes.go` -> `pkg/server/routes.go` (one `RegisterRoutes`), handler
   packages merged: `pro/admin` -> `pkg/admin`, `pro/tickets` -> `pkg/tickets`,
   `pro/middleware/audit.go` -> `pkg/server`, `pro/evidence` -> `pkg/evidence`,
   `pro/reporting` -> `pkg/reporting`.
2. `pro/ui` -> `ui`: one template FS, one FuncMap, files renamed.
3. `cmd/seed` and `cmd/mint` updated. `pro/` directory deleted.
4. Gate: suite green; fresh boot; the chapter 9 walkthrough (adapter, ingest the
   million, pen, bulk, configuration) repeated on the folded build and screenshots
   retaken if anything moved.

### Stage 4: loose ends

- `workspace_id`: keep the column, drop the 13 hard-coded `= 1` by defaulting in
  one place, or remove workspaces entirely. Decide then.
- README and this doc: remove the "merge of two repositories" history once nothing
  in the tree refers to it.
- `docs/SECURITY-REVIEW.md` and `docs/REPORT-ROADMAP.md`: re-read for tier wording.

## Rules while doing it

- One stage per commit (or a few commits per stage), each with the suite green.
- `gopls rename` for identifiers; never sed a Go identifier.
- No behavior change inside a rename stage. If a bug is found, fix it in its own
  commit with its own test, before or after, never inside the move.
- The million-row database in the lab is the performance ruler: pen page under a
  second, ingest under two minutes, before and after.

## Found and fixed on the way (own commits, not inside the moves)

- The `/static/pro/` mount served the whole embedded UI filesystem, exposing template source over HTTP; it now serves scripts only (caa7f03).
- The ingest page's script pointed at a path that 404'd (caa7f03).
- Adapter findings paths could not index arrays, so the shipped Trivy adapter never ingested the shipped sample (fixed with a test, after Stage 1).
- Verified no performance change: pen page on the million-row lab DB 0.5-0.7 s warm before and after.
- The two create paths disagreed (Stage 2 prep, 583df0a): batch ingest skipped per-finding suppression, severity rules and routing; a global suppression match set a status the schema rejects and rolled back the ingest; the per-finding suppression check ran before the hash existed. One rules engine now runs on both paths. Million-row ingest 77 s (was 68 s); a routing rule set before the upload assigned all 200 findings on its asset.
- Stage 2 also deleted the embedding and matchmaker sketches (they queried tables the schema never had and nothing called them) and a base GetGlobalActivityFeed that returned an upsell message instead of the audit log.
