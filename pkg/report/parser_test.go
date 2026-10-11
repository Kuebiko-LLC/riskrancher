package report

import (
	"encoding/json"
	"testing"
)

func TestExtractJSONField(t *testing.T) {
	semgrepRaw := []byte(`{
		"check_id": "crypto-bad-mac",
		"extra": {
			"severity": "WARNING",
			"message": "Use of weak MAC"
		}
	}`)
	var semgrep map[string]any
	json.Unmarshal(semgrepRaw, &semgrep)

	trivyRaw := []byte(`{
		"VulnerabilityID": "CVE-2021-44228",
		"PkgName": "log4j-core",
		"Severity": "CRITICAL"
	}`)
	var trivy map[string]any
	json.Unmarshal(trivyRaw, &trivy)

	openvasRaw := []byte(`{
		"name": "Cleartext Transmission",
		"host": {
			"details": [
				{"ip": "192.168.1.50"},
				{"ip": "10.0.0.5"}
			]
		},
		"threat": "High"
	}`)
	var openvas map[string]any
	json.Unmarshal(openvasRaw, &openvas)

	tests := []struct {
		name     string
		finding  any
		path     string
		expected string
	}{
		{"Semgrep Flat", semgrep, "check_id", "crypto-bad-mac"},
		{"Semgrep Nested", semgrep, "extra.severity", "WARNING"},
		{"Semgrep Deep Nested", semgrep, "extra.message", "Use of weak MAC"},

		{"Trivy Flat 1", trivy, "VulnerabilityID", "CVE-2021-44228"},
		{"Trivy Flat 2", trivy, "Severity", "CRITICAL"},

		{"OpenVAS Flat", openvas, "threat", "High"},
		{"OpenVAS Array Index", openvas, "host.details.0.ip", "192.168.1.50"},

		{"Missing Field", trivy, "does.not.exist", ""},
		{"Empty Path", trivy, "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractJSONField(tc.finding, tc.path)
			if result != tc.expected {
				t.Errorf("Path '%s': expected '%s', got '%s'", tc.path, tc.expected, result)
			}
		})
	}
}
