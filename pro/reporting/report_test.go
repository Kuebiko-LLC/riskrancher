package reporting_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
	"github.com/Kuebiko-LLC/riskrancher/pro/reporting"
)

func sampleFindings() []domain.Ticket {
	return []domain.Ticket{
		{Title: "Weak TLS ciphers", Severity: "Low", AssetIdentifier: "edge-lb", Source: "testssl", Status: "Open", RecommendedRemediation: "Disable TLS 1.0/1.1."},
		{Title: "SQL injection in /login", Severity: "Critical", AssetIdentifier: "web-app", Source: "Burp", Status: "Open", Description: "Unparameterised query.", RecommendedRemediation: "Use prepared statements."},
		{Title: "Verbose error messages", Severity: "Medium", AssetIdentifier: "web-app", Source: "manual", Status: "Open"},
	}
}

func fixedInput() reporting.ReportInput {
	return reporting.ReportInput{
		Title:            "Acme External Test",
		ClientName:       "Acme Corp",
		Author:           "t",
		Scope:            "app.acme.test",
		ExecutiveSummary: "One critical issue needs urgent attention.",
		GeneratedAt:      time.Date(2026, 2, 1, 9, 0, 0, 0, time.UTC),
	}
}

func TestBuildMarkdown(t *testing.T) {
	md := reporting.BuildMarkdown(fixedInput(), sampleFindings())

	for _, want := range []string{
		"# Acme External Test",
		"**Client:** Acme Corp",
		"**Date:** 2026-02-01",
		"## Scope",
		"## Executive Summary",
		"One critical issue needs urgent attention.",
		"SQL injection in /login",
		"Weak TLS ciphers",
		"Use prepared statements.",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown is missing %q", want)
		}
	}

	t.Run("findings are ordered most-severe first", func(t *testing.T) {
		crit := strings.Index(md, "SQL injection in /login") // Critical
		med := strings.Index(md, "Verbose error messages")   // Medium
		low := strings.Index(md, "Weak TLS ciphers")         // Low
		if !(crit < med && med < low) {
			t.Errorf("expected Critical < Medium < Low ordering, got positions %d/%d/%d", crit, med, low)
		}
	})

	t.Run("severity summary counts each bucket", func(t *testing.T) {
		for _, row := range []string{"| Critical | 1 |", "| Medium | 1 |", "| Low | 1 |"} {
			if !strings.Contains(md, row) {
				t.Errorf("summary table missing row %q", row)
			}
		}
	})
}

func TestBuildMarkdownEmpty(t *testing.T) {
	md := reporting.BuildMarkdown(fixedInput(), nil)
	if !strings.Contains(md, "No findings were selected") {
		t.Errorf("expected empty-state note, got:\n%s", md)
	}
}

func TestBuildHTMLEscapesContent(t *testing.T) {
	findings := []domain.Ticket{
		{Title: "XSS <script>alert(1)</script>", Severity: "High", AssetIdentifier: "web-app"},
	}
	html := reporting.BuildHTML(fixedInput(), findings)

	if !strings.Contains(html, "<!doctype html>") || !strings.Contains(html, "<title>Acme External Test</title>") {
		t.Errorf("expected a self-contained HTML document")
	}
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Errorf("finding content was not escaped: raw <script> leaked into the HTML")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("expected the script tag to be HTML-escaped")
	}
}

func TestEvidenceRendersInReport(t *testing.T) {
	in := fixedInput()
	in.Evidence = map[int][]reporting.EvidenceImage{
		7: {{DataURI: "data:image/png;base64,AAAABBBB", Caption: "login popup"}},
	}
	findings := []domain.Ticket{{ID: 7, Title: "XSS", Severity: "High", AssetIdentifier: "web"}}

	md := reporting.BuildMarkdown(in, findings)
	if !strings.Contains(md, "![login popup](data:image/png;base64,AAAABBBB)") {
		t.Errorf("markdown should embed the screenshot:\n%s", md)
	}

	html := reporting.BuildHTML(in, findings)
	if !strings.Contains(html, "src=\"data:image/png;base64,AAAABBBB\"") {
		t.Errorf("html should embed the screenshot as a trusted data URI:\n%s", html)
	}
	if !strings.Contains(html, "login popup") {
		t.Errorf("html should include the caption")
	}
}

func TestStructuredFieldsRenderInReport(t *testing.T) {
	in := fixedInput()
	findings := []domain.Ticket{{
		ID: 1, Title: "SQLi", Severity: "Critical", AssetIdentifier: "web",
		CVSSVector: "CVSS:3.1/AV:N/AC:L", CVSSScore: 9.1, CWE: "CWE-89",
		BusinessImpact: "Full database compromise",
	}}

	md := reporting.BuildMarkdown(in, findings)
	for _, want := range []string{"**CVSS:** 9.1 CVSS:3.1/AV:N/AC:L", "**CWE:** CWE-89", "**Business impact**", "Full database compromise"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	html := reporting.BuildHTML(in, findings)
	for _, want := range []string{"CWE-89", "9.1 CVSS:3.1/AV:N/AC:L", "Business impact", "Full database compromise"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestBuildHTMLDefaultsTitle(t *testing.T) {
	html := reporting.BuildHTML(reporting.ReportInput{}, sampleFindings())
	if !strings.Contains(html, "Penetration Test Report") {
		t.Errorf("expected a default title when none supplied")
	}
}
