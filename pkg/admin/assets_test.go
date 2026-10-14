package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The Sheriff loads the book's inventory file as it is, and edits the rubric
// over the API. Both rescore the open findings they touch.

const sampleAssets = `asset,criticality,exposure,owner,notes
payments-api,crown-jewel,internet,Payments,Processes card transactions. PCI scope.
customer-db,crown-jewel,internal,Data,Primary customer PII store.
vpn-gateway,crown-jewel,internet,Infra,Remote access for all staff.
legacy-billing,crown-jewel,internal,Finance,Old but still invoices every customer.
marketing-site,standard,internet,Marketing,Static site behind a CDN.
hr-portal,standard,internal,People,SSO-protected; no card data.
build-server,standard,internal,Platform,CI runner; holds deploy keys.
dev-sandbox,dev,isolated,Platform,Throwaway. Rebuilt weekly.
`

func TestParseAssetCSV_ReadsTheBooksFile(t *testing.T) {
	assets, err := parseAssetCSV(strings.NewReader(sampleAssets))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 8 {
		t.Fatalf("want 8 assets, got %d", len(assets))
	}
	last := assets[7]
	if last.AssetIdentifier != "dev-sandbox" || last.Criticality != "dev" || last.Exposure != "isolated" || last.Owner != "Platform" || !strings.HasPrefix(last.Notes, "Throwaway") {
		t.Fatalf("last row: %+v", last)
	}
}

func TestParseAssetCSV_HeaderVariants(t *testing.T) {
	in := "\ufeffAsset, Exposure ,Criticality\npayments-api, Internet ,Crown Jewel\nbuild-server,internal,crown_jewel\n"
	assets, err := parseAssetCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 || assets[0].Exposure != "internet" || assets[0].Criticality != "crown-jewel" || assets[1].Criticality != "crown-jewel" || assets[0].Owner != "" {
		t.Fatalf("variants: %+v", assets)
	}
}

func TestParseAssetCSV_RejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"exposure off the scale": "asset,criticality,exposure\na,standard,internet\nb,standard,dmz\n",
		"missing column":         "asset,exposure\na,internet\n",
		"empty file":             "",
		"blank asset":            "asset,criticality,exposure\n,standard,internet\n",
	}
	for name, in := range cases {
		_, err := parseAssetCSV(strings.NewReader(in))
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	_, err := parseAssetCSV(strings.NewReader("asset,criticality,exposure\na,standard,internet\nb,standard,dmz\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("the error names the line: %v", err)
	}
}

func multipartCSV(t *testing.T, body string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, _ := w.CreateFormFile("file", "sample-assets.csv")
	part.Write([]byte(body))
	w.Close()
	return &buf, w.FormDataContentType()
}

func TestLoadAssetsCSV_UpsertsAndRescores(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()
	ctx := context.Background()
	batch := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "Outdated OpenSSL", Severity: "High"}}
	if err := h.Store.ProcessIngestionBatch(ctx, "Nessus", "payments-api", batch); err != nil {
		t.Fatal(err)
	}
	buf, ctype := multipartCSV(t, sampleAssets)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/assets/csv", buf)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.HandleLoadAssetsCSV(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]int
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["loaded"] != 8 || out["rescored"] != 1 {
		t.Fatalf("want loaded 8, rescored 1; got %v", out)
	}
	var severity string
	db.QueryRow(`SELECT severity FROM tickets WHERE title = 'Outdated OpenSSL'`).Scan(&severity)
	if severity != "Critical" {
		t.Fatalf("High on internet x crown-jewel is Critical after the load, got %s", severity)
	}
	// A bad file is refused with the line that is wrong
	buf, ctype = multipartCSV(t, "asset,criticality,exposure\na,standard,dmz\n")
	req = httptest.NewRequest(http.MethodPost, "/api/admin/assets/csv", buf)
	req.Header.Set("Content-Type", ctype)
	rec = httptest.NewRecorder()
	h.HandleLoadAssetsCSV(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "line 2") {
		t.Fatalf("bad file: %d %s", rec.Code, rec.Body.String())
	}
	// The list route shows what was loaded
	rec = httptest.NewRecorder()
	h.HandleListAssets(rec, httptest.NewRequest(http.MethodGet, "/api/admin/assets", nil))
	var listed []domain.Asset
	json.Unmarshal(rec.Body.Bytes(), &listed)
	if len(listed) != 8 {
		t.Fatalf("list: %d", len(listed))
	}
}

func TestPutRubric_ValidatesThenSavesAndRescores(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()
	ctx := context.Background()
	h.Store.UpsertAssets(ctx, []domain.Asset{{AssetIdentifier: "payments-api", Exposure: "internet", Criticality: "crown-jewel"}})
	batch := []domain.Ticket{{Source: "Nessus", AssetIdentifier: "payments-api", Title: "Outdated OpenSSL", Severity: "High"}}
	h.Store.ProcessIngestionBatch(ctx, "Nessus", "payments-api", batch)

	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/admin/rubric", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.HandlePutRubric(rec, req)
		return rec
	}
	weights, _ := h.Store.GetRubric(ctx)
	// Thirteen weights: refused
	short, _ := json.Marshal(weights[:13])
	if rec := put(string(short)); rec.Code != http.StatusBadRequest {
		t.Fatalf("13 weights: %d", rec.Code)
	}
	// Bands out of order: refused
	bad := append([]domain.RubricWeight{}, weights...)
	for i := range bad {
		if bad[i].Kind == "band" && bad[i].Key == "High" {
			bad[i].Weight = 20
		}
	}
	badJSON, _ := json.Marshal(bad)
	if rec := put(string(badJSON)); rec.Code != http.StatusBadRequest {
		t.Fatalf("High band above Critical: %d", rec.Code)
	}
	// Critical band raised to 20: the finding scored 12 drops to High
	good := append([]domain.RubricWeight{}, weights...)
	for i := range good {
		if good[i].Kind == "band" && good[i].Key == "Critical" {
			good[i].Weight = 20
		}
	}
	goodJSON, _ := json.Marshal(good)
	rec := put(string(goodJSON))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid rubric: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]int
	json.Unmarshal(rec.Body.Bytes(), &out)
	var severity string
	db.QueryRow(`SELECT severity FROM tickets WHERE title = 'Outdated OpenSSL'`).Scan(&severity)
	if out["rescored"] != 1 || severity != "High" {
		t.Fatalf("after the save: rescored=%d severity=%s", out["rescored"], severity)
	}
	rec = httptest.NewRecorder()
	h.HandleGetRubric(rec, httptest.NewRequest(http.MethodGet, "/api/admin/rubric", nil))
	var back []domain.RubricWeight
	json.Unmarshal(rec.Body.Bytes(), &back)
	if len(back) != 14 || back[11].Kind != "band" || back[11].Weight != 20 {
		t.Fatalf("GET returns the saved rubric in display order: %+v", back)
	}
}

func TestDeleteAsset_UnknownIs404(t *testing.T) {
	h, db := setupTestAdmin(t)
	defer db.Close()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/assets/nope", nil)
	req.SetPathValue("asset", "nope")
	rec := httptest.NewRecorder()
	h.HandleDeleteAsset(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown asset: %d", rec.Code)
	}
	h.Store.UpsertAssets(context.Background(), []domain.Asset{{AssetIdentifier: "x", Exposure: "internet", Criticality: "standard"}})
	req = httptest.NewRequest(http.MethodDelete, "/api/admin/assets/x", nil)
	req.SetPathValue("asset", "x")
	rec = httptest.NewRecorder()
	h.HandleDeleteAsset(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("known asset: %d", rec.Code)
	}
}
