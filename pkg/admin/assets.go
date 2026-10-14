package admin

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Kuebiko-LLC/riskrancher/pkg/datastore"
	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// The asset inventory and the priority rubric, over the API. The inventory
// is the book's chapter-two file, loaded as it is; the rubric is the book's
// chapter-six numbers, edited in place. Both rescore what they touch.

// parseAssetCSV reads an inventory file: a header with asset, criticality and
// exposure in any order and case (owner and notes optional), a BOM and spaces
// ignored, values folded to the tool's spelling. The first bad row names its
// line number.
func parseAssetCSV(r io.Reader) ([]domain.Asset, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("not a CSV file: %v", err)
	}
	if len(rows) == 0 {
		return nil, errors.New("the file is empty")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	for _, need := range []string{"asset", "criticality", "exposure"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("the header needs a %q column (asset, criticality, exposure, and optionally owner and notes)", need)
		}
	}
	field := func(row []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	fold := func(v string) string {
		v = strings.ToLower(strings.TrimSpace(v))
		return strings.NewReplacer(" ", "-", "_", "-").Replace(v)
	}
	var out []domain.Asset
	for n, row := range rows[1:] {
		line := n + 2
		if len(row) == 0 || (len(row) == 1 && strings.TrimSpace(row[0]) == "") {
			continue
		}
		a := domain.Asset{
			AssetIdentifier: field(row, "asset"),
			Criticality:     fold(field(row, "criticality")),
			Exposure:        fold(field(row, "exposure")),
			Owner:           field(row, "owner"),
			Notes:           field(row, "notes"),
		}
		if a.AssetIdentifier == "" {
			return nil, fmt.Errorf("line %d: the asset is blank", line)
		}
		if !contains(domain.Exposures, a.Exposure) {
			return nil, fmt.Errorf("line %d: exposure %q is not one of internet, internal, isolated", line, a.Exposure)
		}
		if !contains(domain.Criticalities, a.Criticality) {
			return nil, fmt.Errorf("line %d: criticality %q is not one of crown-jewel, standard, dev", line, a.Criticality)
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("the file has a header and no rows")
	}
	return out, nil
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// HandleListAssets is the inventory.
func (h *Handler) HandleListAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := h.Store.ListAssets(r.Context())
	if err != nil {
		httpServerError(w, "assets", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assets)
}

// HandleLoadAssetsCSV takes the inventory file as multipart "file", loads it,
// and rescores the open findings on the assets it names.
func (h *Handler) HandleLoadAssetsCSV(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		http.Error(w, "Could not read the upload (5 MB limit)", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Missing 'file' in request", http.StatusBadRequest)
		return
	}
	defer file.Close()
	assets, err := parseAssetCSV(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.Store.UpsertAssets(r.Context(), assets); err != nil {
		httpServerError(w, "assets", err)
		return
	}
	ids := make([]string, len(assets))
	for i, a := range assets {
		ids[i] = a.AssetIdentifier
	}
	rescored, err := h.Store.RescoreAssets(r.Context(), ids)
	if err != nil {
		httpServerError(w, "rescore", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"loaded": len(assets), "rescored": rescored})
}

// HandleDeleteAsset forgets one asset; its open findings go back to the
// scanner's word.
func (h *Handler) HandleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	rescored, err := h.Store.DeleteAsset(r.Context(), r.PathValue("asset"))
	if errors.Is(err, datastore.ErrNoSuchAsset) {
		http.Error(w, "No such asset in the inventory", http.StatusNotFound)
		return
	}
	if err != nil {
		httpServerError(w, "assets", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"rescored": rescored})
}

// HandleGetRubric is the fourteen weights, in display order.
func (h *Handler) HandleGetRubric(w http.ResponseWriter, r *http.Request) {
	weights, err := h.Store.GetRubric(r.Context())
	if err != nil {
		httpServerError(w, "rubric", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(weights)
}

// HandlePutRubric saves all fourteen weights and rescores every open finding
// on an inventoried asset.
func (h *Handler) HandlePutRubric(w http.ResponseWriter, r *http.Request) {
	var weights []domain.RubricWeight
	if err := json.NewDecoder(r.Body).Decode(&weights); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if err := validateRubric(weights); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.Store.UpdateRubric(r.Context(), weights); err != nil {
		httpServerError(w, "rubric", err)
		return
	}
	rescored, err := h.Store.RescoreAssets(r.Context(), nil)
	if err != nil {
		httpServerError(w, "rescore", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"rescored": rescored})
}

// validateRubric wants exactly the fourteen seeded weights, none negative,
// with the bands in order: Critical above High above Medium above zero.
func validateRubric(weights []domain.RubricWeight) error {
	have := map[string]float64{}
	for _, w := range weights {
		if w.Weight < 0 {
			return fmt.Errorf("%s %s: a weight cannot be negative", w.Kind, w.Key)
		}
		have[w.Kind+"/"+w.Key] = w.Weight
	}
	if len(have) != len(domain.RubricOrder) || len(weights) != len(domain.RubricOrder) {
		return fmt.Errorf("the rubric has %d weights; send all of them", len(domain.RubricOrder))
	}
	for _, want := range domain.RubricOrder {
		if _, ok := have[want.Kind+"/"+want.Key]; !ok {
			return fmt.Errorf("missing %s %s", want.Kind, want.Key)
		}
	}
	c, hi, m := have["band/Critical"], have["band/High"], have["band/Medium"]
	if !(c > hi && hi > m && m > 0) {
		return errors.New("the bands must run Critical above High above Medium above zero")
	}
	return nil
}
