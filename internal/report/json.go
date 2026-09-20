// Package report — JSON renderer.
package report

import (
	"encoding/json"
	"fmt"
	"time"

	"secretguard/internal/normalizer"
)

// JSONReport is the top-level structure emitted by `secretguard scan --format json`.
// Raw secrets are NEVER included in this structure.
type JSONReport struct {
	Scanner  string          `json:"scanner"`
	Version  string          `json:"version"`
	Detector string          `json:"detector"`
	ScanTime string          `json:"scan_time"`
	Findings []jsonFinding   `json:"findings"`
	Summary  jsonSummary     `json:"summary"`
}

// jsonFinding is the JSON-serialisable shape of a single finding.
// It is a projection of normalizer.Finding — the raw secret is absent.
type jsonFinding struct {
	ID          string `json:"id"`
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Detector    string `json:"detector"`
	SecretType  string `json:"secret_type,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Redacted    string `json:"redacted_value"`
	Severity    string `json:"severity"`
}

type jsonSummary struct {
	FilesScanned int `json:"files_scanned"`
	Findings     int `json:"findings"`
}

// RenderJSON serialises the report to indented JSON bytes.
// It returns an error only if serialisation fails, which should never happen
// with this struct layout.
func RenderJSON(findings []normalizer.Finding, summary Summary) ([]byte, error) {
	jf := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		jf = append(jf, jsonFinding{
			ID:          f.ID,
			File:        f.File,
			StartLine:   f.StartLine,
			EndLine:     f.EndLine,
			StartColumn: f.StartColumn,
			EndColumn:   f.EndColumn,
			RuleID:      f.RuleID,
			Description: f.Description,
			Detector:    f.Detector,
			SecretType:  f.SecretType,
			Fingerprint: f.Fingerprint,
			Redacted:    f.Redacted,
			Severity:    f.Severity,
		})
	}

	report := JSONReport{
		Scanner:  "secretguard",
		Version:  summary.Version,
		Detector: "gitleaks",
		ScanTime: time.Now().UTC().Format(time.RFC3339),
		Findings: jf,
		Summary: jsonSummary{
			FilesScanned: summary.FilesScanned,
			Findings:     len(findings),
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialise JSON report: %w", err)
	}
	return data, nil
}
