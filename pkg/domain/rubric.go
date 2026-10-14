package domain

// Rubric is the book's priority formula: a base from the scanner's severity,
// multiplied by the asset's exposure and criticality, then banded. The tool
// ships with the book's numbers and the Sheriff can change them.
type Rubric struct {
	Base, Exposure, Criticality map[string]float64
	Bands                       map[string]float64 // Critical, High, Medium: the lowest score for each; below Medium is Low
}

// NewRubric builds a rubric from the stored weights. ok is false when any of
// the fourteen is missing, and then no rubric is applied: a half-set rubric
// must not decide anything.
func NewRubric(weights []RubricWeight) (*Rubric, bool) {
	r := &Rubric{Base: map[string]float64{}, Exposure: map[string]float64{}, Criticality: map[string]float64{}, Bands: map[string]float64{}}
	for _, w := range weights {
		switch w.Kind {
		case "base":
			r.Base[w.Key] = w.Weight
		case "exposure":
			r.Exposure[w.Key] = w.Weight
		case "criticality":
			r.Criticality[w.Key] = w.Weight
		case "band":
			r.Bands[w.Key] = w.Weight
		}
	}
	for _, want := range RubricOrder {
		var have map[string]float64
		switch want.Kind {
		case "base":
			have = r.Base
		case "exposure":
			have = r.Exposure
		case "criticality":
			have = r.Criticality
		default:
			have = r.Bands
		}
		if _, ok := have[want.Key]; !ok {
			return nil, false
		}
	}
	return r, true
}

// Score is the score and the band for a scanner severity on an asset. ok is
// false when the severity has no base weight or the asset's exposure or
// criticality is off the scale; the caller then keeps the scanner's word. A
// base of zero (Info) scores zero and keeps the scanner's severity: there is
// nothing to prioritize.
func (r *Rubric) Score(severity, exposure, criticality string) (score float64, band string, ok bool) {
	base, okB := r.Base[severity]
	exp, okE := r.Exposure[exposure]
	crit, okC := r.Criticality[criticality]
	if !okB || !okE || !okC {
		return 0, "", false
	}
	if base == 0 {
		return 0, severity, true
	}
	score = base * exp * crit
	switch {
	case score >= r.Bands["Critical"]:
		band = "Critical"
	case score >= r.Bands["High"]:
		band = "High"
	case score >= r.Bands["Medium"]:
		band = "Medium"
	default:
		band = "Low"
	}
	return score, band, true
}
