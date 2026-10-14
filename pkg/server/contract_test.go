package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/ui"
)

// uiCall is one fetch() in the shipped scripts.
type uiCall struct {
	file, method, path string
}

var (
	fetchRe  = regexp.MustCompile("fetch\\(\\s*((?:[`'\"][^`'\"]*[`'\"]|[^,()`'\"]+)+)")
	methodRe = regexp.MustCompile(`method:\s*['"](\w+)['"]`)
	interpRe = regexp.MustCompile(`\$\{[^}]*\}`)
	// api('METHOD', '/path/'+id+'/more', ...) is the helper the page scripts use
	helperRe = regexp.MustCompile(`\bapi\(\s*'(\w+)'\s*,\s*((?:'[^']*'|[^,()]+)+)`)
	hrefRe   = regexp.MustCompile("(?:href|src)=\"(/api/[^\"?]+)")
)

// concatPath turns '/api/x/'+id+'/y' into /api/x/1/y.
func concatPath(expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "`") {
		return strings.Trim(expr, "`")
	}
	var b strings.Builder
	for _, part := range strings.Split(expr, "+") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "'") || strings.HasPrefix(part, "\"") {
			b.WriteString(strings.Trim(part, "'\""))
		} else if part != "" {
			b.WriteString("1")
		}
	}
	return b.String()
}

func normalizePath(path string) string {
	path = interpRe.ReplaceAllString(path, "1")
	if q := strings.Index(path, "?"); q >= 0 {
		path = path[:q]
	}
	return path
}

// uiFetchCalls lists every API call the pages make: fetch() and the api()
// helper in ui/static and in the inline scripts of the templates, plus
// links straight to an API path. Template segments become a literal.
func uiFetchCalls(t *testing.T) []uiCall {
	t.Helper()
	var calls []uiCall
	for _, dir := range []string{"static", "templates", "templates/components", "templates/magic"} {
		entries, err := fs.ReadDir(ui.UIFS, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !(strings.HasSuffix(e.Name(), ".js") || strings.HasSuffix(e.Name(), ".gohtml")) {
				continue
			}
			src, err := fs.ReadFile(ui.UIFS, dir+"/"+e.Name())
			if err != nil {
				t.Fatal(err)
			}
			text := string(src)
			locs := fetchRe.FindAllStringSubmatchIndex(text, -1)
			for i, loc := range locs {
				raw := concatPath(text[loc[2]:loc[3]])
				if !strings.HasPrefix(raw, "/") {
					continue // fetch(url, opt) inside a helper
				}
				end := len(text)
				if i+1 < len(locs) {
					end = locs[i+1][0]
				}
				if end-loc[1] > 400 {
					end = loc[1] + 400
				}
				method := http.MethodGet
				if m := methodRe.FindStringSubmatch(text[loc[1]:end]); m != nil {
					method = strings.ToUpper(m[1])
				}
				calls = append(calls, uiCall{e.Name(), method, normalizePath(raw)})
			}
			for _, m := range helperRe.FindAllStringSubmatch(text, -1) {
				calls = append(calls, uiCall{e.Name(), strings.ToUpper(m[1]), normalizePath(concatPath(m[2]))})
			}
			for _, m := range hrefRe.FindAllStringSubmatch(text, -1) {
				calls = append(calls, uiCall{e.Name(), http.MethodGet, normalizePath(m[1])})
			}
		}
	}
	return calls
}

func routerApp(t *testing.T) *App {
	t.Helper()
	db := datastore.InitDB(":memory:")
	t.Cleanup(func() { db.Close() })
	app := NewApp(datastore.NewSQLiteStore(db))
	RegisterRoutes(app)
	return app
}

// Every fetch the browser makes must land on a registered route with that
// method. Go's mux returns an empty pattern for both an unknown path and a
// wrong method, so one check catches both kinds of drift.
func TestUIFetchCallsHaveRoutes(t *testing.T) {
	app := routerApp(t)
	var missing []string
	for _, c := range uiFetchCalls(t) {
		req := httptest.NewRequest(c.method, c.path, nil)
		if _, pattern := app.Router.Handler(req); pattern == "" {
			missing = append(missing, c.file+": "+c.method+" "+c.path)
		}
	}
	sort.Strings(missing)
	if strings.Join(missing, "\n") != strings.Join(knownDrift, "\n") {
		t.Fatalf("scripts call routes the server does not have:\n  %s\nexpected exactly the known drift list:\n  %s", strings.Join(missing, "\n  "), strings.Join(knownDrift, "\n  "))
	}
}

// knownDrift is the burn-down list: calls the pages make today that the
// server does not answer. Each fix deletes its line. The test fails when a
// new one appears or when a listed one is fixed without being removed here.
var knownDrift = []string{
	"admin.js: PATCH /api/risk/1/review",
	"admin.js: PUT /api/admin/backup-policy",
	"magic.js: POST /api/share/1/review",
}

// knownOrphans is the same burn-down for routes nothing reaches: each is
// either wired to a page, documented in the README, or removed.
var knownOrphans = []string{
	"DELETE /api/adapters/{id}",
	"DELETE /api/admin/triage/{id}",
	"GET /api/adapters",
	"GET /api/admin/routing",
	"GET /api/admin/triage",
	"GET /api/admin/users",
	"GET /api/config",
	"GET /api/finding-templates/{id}",
	"GET /api/integrations/cisa",
	"GET /api/reports/view/{id}",
	"GET /api/tickets",
	"GET /api/wranglers",
	"PATCH /api/share/{token}/review",
	"POST /api/admin/shutdown",
	"POST /api/admin/triage",
	"POST /api/integrations/cisa/sync",
	"PUT /api/finding-templates/{id}",
	"PUT /api/findings/{id}",
}

var routePatternRe = regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE) (/api/[^"]+)"`)
var segmentRe = regexp.MustCompile(`\{[^}]+\}`)

// serverOnly routes are for scanners, pipelines and scripts, not the pages.
var serverOnly = map[string]bool{
	"POST /api/ingest":           true, // raw JSON array
	"GET /api/analytics/summary": true,
}

// Every API route is reached by a page script or documented in the README,
// so a route nothing uses cannot linger.
func TestAPIRoutesAreUsedOrDocumented(t *testing.T) {
	src, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, c := range uiFetchCalls(t) {
		used[c.method+" "+c.path] = true
	}
	var orphans []string
	for _, m := range routePatternRe.FindAllStringSubmatch(string(src), -1) {
		pattern := m[1] + " " + m[2]
		if serverOnly[pattern] {
			continue
		}
		normalized := m[1] + " " + segmentRe.ReplaceAllString(m[2], "1")
		if used[normalized] {
			continue
		}
		family := strings.TrimRight(segmentRe.ReplaceAllString(m[2], ""), "/")
		if strings.Contains(string(readme), "`"+m[2]) || strings.Contains(string(readme), family) {
			continue
		}
		orphans = append(orphans, pattern)
	}
	sort.Strings(orphans)
	if strings.Join(orphans, "\n") != strings.Join(knownOrphans, "\n") {
		t.Fatalf("routes no page calls and the README does not mention:\n  %s\nexpected exactly the known orphan list:\n  %s", strings.Join(orphans, "\n  "), strings.Join(knownOrphans, "\n  "))
	}
}
