// Package reporting turns a set of findings (tickets) into a pentest engagement
// report. It renders the same content two ways, both pure Go with no external
// dependencies: Markdown (for diffing/versioning or downstream conversion) and a
// self-contained, print-ready HTML document (open it and "Print to PDF").
package reporting

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/Kuebiko-LLC/riskrancher/pkg/domain"
)

// ReportInput is the engagement metadata that wraps the findings.
type ReportInput struct {
	Title            string
	ClientName       string
	Author           string
	Scope            string
	ExecutiveSummary string
	Body             string // author prose/narrative (Markdown), rendered as-is
	GeneratedAt      time.Time
	// Evidence maps a finding's ticket id to its screenshots (as data URIs), so
	// the rendered report is self-contained.
	Evidence map[int][]EvidenceImage
}

// EvidenceImage is one screenshot embedded in a report, carried as a data URI.
type EvidenceImage struct {
	DataURI string
	Caption string
}

// severityOrder ranks severities most-serious first; anything unrecognised
// sorts last under "Informational".
var severityOrder = map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4, "Info": 4}

func rankOf(sev string) int {
	if r, ok := severityOrder[sev]; ok {
		return r
	}
	return 5
}

func normalizeSeverity(sev string) string {
	if sev == "" {
		return "Informational"
	}
	return sev
}

// group holds one severity bucket for rendering.
type group struct {
	Severity string
	Findings []domain.Ticket
}

// organize sorts findings most-serious first (ties broken by asset then title)
// and buckets them by severity, preserving that order.
func organize(findings []domain.Ticket) []group {
	sorted := make([]domain.Ticket, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := rankOf(sorted[i].Severity), rankOf(sorted[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if sorted[i].AssetIdentifier != sorted[j].AssetIdentifier {
			return sorted[i].AssetIdentifier < sorted[j].AssetIdentifier
		}
		return sorted[i].Title < sorted[j].Title
	})

	var groups []group
	for _, f := range sorted {
		sev := normalizeSeverity(f.Severity)
		if n := len(groups); n > 0 && groups[n-1].Severity == sev {
			groups[n-1].Findings = append(groups[n-1].Findings, f)
			continue
		}
		groups = append(groups, group{Severity: sev, Findings: []domain.Ticket{f}})
	}
	return groups
}

// counts returns severity -> number of findings.
func counts(findings []domain.Ticket) map[string]int {
	c := map[string]int{}
	for _, f := range findings {
		c[normalizeSeverity(f.Severity)]++
	}
	return c
}

func defaulted(in ReportInput) ReportInput {
	if in.Title == "" {
		in.Title = "Penetration Test Report"
	}
	if in.GeneratedAt.IsZero() {
		in.GeneratedAt = time.Now()
	}
	return in
}

// BuildMarkdown renders the engagement report as Markdown.
func BuildMarkdown(in ReportInput, findings []domain.Ticket) string {
	in = defaulted(in)
	var b strings.Builder

	fmt.Fprintf(&b, "# %s\n\n", in.Title)
	if in.ClientName != "" {
		fmt.Fprintf(&b, "**Client:** %s  \n", in.ClientName)
	}
	if in.Author != "" {
		fmt.Fprintf(&b, "**Prepared by:** %s  \n", in.Author)
	}
	fmt.Fprintf(&b, "**Date:** %s  \n", in.GeneratedAt.Format("2006-01-02"))
	fmt.Fprintf(&b, "**Findings:** %d\n\n", len(findings))

	if in.Scope != "" {
		fmt.Fprintf(&b, "## Scope\n\n%s\n\n", in.Scope)
	}
	if in.ExecutiveSummary != "" {
		fmt.Fprintf(&b, "## Executive Summary\n\n%s\n\n", in.ExecutiveSummary)
	}
	if in.Body != "" {
		// Author prose is Markdown; emit it as-is (the author owns its headings).
		fmt.Fprintf(&b, "%s\n\n", in.Body)
	}

	b.WriteString("## Findings at a Glance\n\n")
	b.WriteString("| Severity | Count |\n|----------|-------|\n")
	c := counts(findings)
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Informational"} {
		if c[sev] > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", sev, c[sev])
		}
	}
	b.WriteString("\n")

	if len(findings) == 0 {
		b.WriteString("_No findings were selected for this report._\n")
		return b.String()
	}

	b.WriteString("## Findings\n\n")
	n := 0
	for _, g := range organize(findings) {
		for _, f := range g.Findings {
			n++
			fmt.Fprintf(&b, "### %d. [%s] %s\n\n", n, g.Severity, f.Title)
			fmt.Fprintf(&b, "- **Asset:** %s\n", orDash(f.AssetIdentifier))
			fmt.Fprintf(&b, "- **Source:** %s\n", orDash(f.Source))
			fmt.Fprintf(&b, "- **Status:** %s\n\n", orDash(f.Status))
			if f.Description != "" {
				fmt.Fprintf(&b, "**Description**\n\n%s\n\n", f.Description)
			}
			if f.RecommendedRemediation != "" {
				fmt.Fprintf(&b, "**Recommended remediation**\n\n%s\n\n", f.RecommendedRemediation)
			}
			for _, img := range in.Evidence[f.ID] {
				cap := img.Caption
				if cap == "" {
					cap = "Evidence"
				}
				fmt.Fprintf(&b, "![%s](%s)\n\n_%s_\n\n", cap, img.DataURI, cap)
			}
		}
	}
	return b.String()
}

// toHTMLEvidence converts evidence data URIs into template.URL so html/template
// trusts the data: image src instead of filtering it.
func toHTMLEvidence(imgs []EvidenceImage) []htmlEvidence {
	out := make([]htmlEvidence, 0, len(imgs))
	for _, img := range imgs {
		cap := img.Caption
		if cap == "" {
			cap = "Evidence"
		}
		out = append(out, htmlEvidence{SrcURL: template.URL(img.DataURI), Caption: cap})
	}
	return out
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

type htmlFinding struct {
	Num                                    int
	Severity, Title, Asset, Source, Status string
	Description, Remediation               string
	Images                                 []htmlEvidence
}

type htmlEvidence struct {
	SrcURL  template.URL
	Caption string
}

type htmlData struct {
	In       ReportInput
	DateStr  string
	Total    int
	Summary  []summaryRow
	Findings []htmlFinding
}

type summaryRow struct {
	Severity string
	Count    int
}

var htmlTmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.In.Title}}</title>
<style>
  :root { --crit:#b4232c; --high:#c75000; --med:#b8860b; --low:#2f6f4f; --info:#555; }
  * { box-sizing: border-box; }
  body { font: 15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#1b1b1b; margin:0; padding:2.5rem; }
  main { max-width: 52rem; margin: 0 auto; }
  h1 { font-size: 2rem; margin:0 0 .25rem; }
  h2 { margin-top:2.2rem; border-bottom:2px solid #eee; padding-bottom:.25rem; }
  h3 { margin-top:1.6rem; }
  .meta { color:#555; margin:0 0 1.5rem; }
  table { border-collapse: collapse; width: auto; }
  th,td { border:1px solid #ddd; padding:.4rem .8rem; text-align:left; }
  .finding { border-left:4px solid #ccc; padding:.2rem 0 .2rem 1rem; margin:1.2rem 0; }
  .badge { display:inline-block; color:#fff; border-radius:4px; padding:.05rem .5rem; font-size:.8rem; font-weight:600; }
  .sev-Critical{background:var(--crit)} .sev-High{background:var(--high)} .sev-Medium{background:var(--med)} .sev-Low{background:var(--low)} .sev-Informational{background:var(--info)}
  .finding.sev-Critical{border-left-color:var(--crit)} .finding.sev-High{border-left-color:var(--high)} .finding.sev-Medium{border-left-color:var(--med)} .finding.sev-Low{border-left-color:var(--low)} .finding.sev-Informational{border-left-color:var(--info)}
  .kv { color:#444; font-size:.9rem; margin:.3rem 0 .6rem; }
  pre { white-space: pre-wrap; background:#f7f7f4; padding:.6rem .8rem; border-radius:6px; }
  @media print { body { padding:0; } a { color:inherit; } }
</style>
</head>
<body>
<main>
  <h1>{{.In.Title}}</h1>
  <p class="meta">
    {{if .In.ClientName}}<strong>Client:</strong> {{.In.ClientName}}<br>{{end}}
    {{if .In.Author}}<strong>Prepared by:</strong> {{.In.Author}}<br>{{end}}
    <strong>Date:</strong> {{.DateStr}}<br>
    <strong>Findings:</strong> {{.Total}}
  </p>

  {{if .In.Scope}}<h2>Scope</h2><pre>{{.In.Scope}}</pre>{{end}}
  {{if .In.ExecutiveSummary}}<h2>Executive Summary</h2><pre>{{.In.ExecutiveSummary}}</pre>{{end}}
  {{if .In.Body}}<pre class="report-body">{{.In.Body}}</pre>{{end}}

  <h2>Findings at a Glance</h2>
  {{if .Summary}}
  <table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>
  {{range .Summary}}<tr><td><span class="badge sev-{{.Severity}}">{{.Severity}}</span></td><td>{{.Count}}</td></tr>{{end}}
  </tbody></table>
  {{else}}<p><em>No findings were selected for this report.</em></p>{{end}}

  {{if .Findings}}
  <h2>Findings</h2>
  {{range .Findings}}
  <div class="finding sev-{{.Severity}}">
    <h3>{{.Num}}. <span class="badge sev-{{.Severity}}">{{.Severity}}</span> {{.Title}}</h3>
    <div class="kv"><strong>Asset:</strong> {{.Asset}} &nbsp;·&nbsp; <strong>Source:</strong> {{.Source}} &nbsp;·&nbsp; <strong>Status:</strong> {{.Status}}</div>
    {{if .Description}}<p><strong>Description</strong></p><pre>{{.Description}}</pre>{{end}}
    {{if .Remediation}}<p><strong>Recommended remediation</strong></p><pre>{{.Remediation}}</pre>{{end}}
    {{range .Images}}<figure style="margin:1rem 0;"><img src="{{.SrcURL}}" alt="{{.Caption}}" style="max-width:100%;border:1px solid #ddd;border-radius:6px;"><figcaption style="color:#555;font-size:.85rem;margin-top:.25rem;">{{.Caption}}</figcaption></figure>{{end}}
  </div>
  {{end}}
  {{end}}
</main>
</body>
</html>
`))

// BuildHTML renders the engagement report as a self-contained HTML document.
// All finding content is auto-escaped by html/template.
func BuildHTML(in ReportInput, findings []domain.Ticket) string {
	in = defaulted(in)

	c := counts(findings)
	var summary []summaryRow
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Informational"} {
		if c[sev] > 0 {
			summary = append(summary, summaryRow{Severity: sev, Count: c[sev]})
		}
	}

	var rows []htmlFinding
	n := 0
	for _, g := range organize(findings) {
		for _, f := range g.Findings {
			n++
			rows = append(rows, htmlFinding{
				Num:         n,
				Severity:    g.Severity,
				Title:       f.Title,
				Asset:       orDash(f.AssetIdentifier),
				Source:      orDash(f.Source),
				Status:      orDash(f.Status),
				Description: f.Description,
				Remediation: f.RecommendedRemediation,
				Images:      toHTMLEvidence(in.Evidence[f.ID]),
			})
		}
	}

	var b strings.Builder
	_ = htmlTmpl.Execute(&b, htmlData{
		In:       in,
		DateStr:  in.GeneratedAt.Format("2006-01-02"),
		Total:    len(findings),
		Summary:  summary,
		Findings: rows,
	})
	return b.String()
}
