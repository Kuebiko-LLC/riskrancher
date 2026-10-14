package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The Configuration tab offers the inventory upload and the rubric, and shows
// what is loaded.
func TestAdminConfigShowsInventoryAndRubric(t *testing.T) {
	app, cookie := appWithUser(t, "Sheriff")
	get := func() string {
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.Router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("admin page: %d", rec.Code)
		}
		return rec.Body.String()
	}
	page := get()
	for _, want := range []string{`id="assetCsvFile"`, "loadAssetInventory()", `class="rubric-weight"`, "saveRubric()", "No inventory loaded", `data-kind="band"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("config tab lacks %q", want)
		}
	}
	if err := app.Store.UpsertAssets(context.Background(), []domain.Asset{{AssetIdentifier: "payments-api", Exposure: "internet", Criticality: "crown-jewel", Owner: "Payments"}}); err != nil {
		t.Fatal(err)
	}
	page = get()
	for _, want := range []string{"payments-api", "crown-jewel", "deleteAsset('payments-api')", "1 assets in the inventory"} {
		if !strings.Contains(page, want) {
			t.Fatalf("after a load the config tab lacks %q", want)
		}
	}
	src, _ := fsReadUI("static/admin.js")
	for _, want := range []string{"/api/admin/assets/csv", `"file"`, "/api/admin/rubric", "raised"} {
		if !strings.Contains(src, want) {
			t.Fatalf("admin.js lacks %q", want)
		}
	}
}
