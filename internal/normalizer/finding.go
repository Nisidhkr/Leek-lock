// Package normalizer converts detector-specific output into SecretGuard's
// canonical Finding model.
package normalizer

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"secretguard/internal/redact"
)

// Finding is the canonical internal representation of a detected secret.
// It is the only structure that flows from the scanner layer to the report
// layer.  The original secret is NEVER stored here.
type Finding struct {
	ID          string `json:"id"`
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`

	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Detector    string `json:"detector"`

	SecretType  string `json:"secret_type,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Redacted    string `json:"redacted_value"`

	Severity string `json:"severity"`
}

// gitleaksFinding mirrors the JSON emitted by `gitleaks --report-format json`.
// Fields are kept as pointers / optional so malformed output doesn't crash.
type gitleaksFinding struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	SymlinkFile string `json:"SymlinkFile"`
	Commit      string `json:"Commit"`
	Entropy     float64 `json:"Entropy"`
	Author      string `json:"Author"`
	Email       string `json:"Email"`
	Date        string `json:"Date"`
	Message     string `json:"Message"`
	Tags        []string `json:"Tags"`
	RuleID      string `json:"RuleID"`
	Fingerprint string `json:"Fingerprint"`
}

// NormalizeGitleaks parses raw Gitleaks JSON output and converts every finding
// into a canonical Finding.  It is safe to call with nil or malformed input.
func NormalizeGitleaks(raw []byte) ([]Finding, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	// Gitleaks can return either a JSON array or null.
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" || trimmed == "" {
		return nil, nil
	}

	var glFindings []gitleaksFinding
	if err := json.Unmarshal(raw, &glFindings); err != nil {
		return nil, fmt.Errorf("invalid gitleaks JSON: %w", err)
	}

	findings := make([]Finding, 0, len(glFindings))
	for i, gl := range glFindings {
		f := Finding{
			ID:          fmt.Sprintf("finding-%03d", i+1),
			File:        normalizeFilePath(gl.File),
			StartLine:   gl.StartLine,
			EndLine:     gl.EndLine,
			StartColumn: gl.StartColumn,
			EndColumn:   gl.EndColumn,
			RuleID:      gl.RuleID,
			Description: gl.Description,
			Detector:    "gitleaks",
			Fingerprint: choosefingerprint(gl.Fingerprint, gl.Secret),
			Redacted:    redact.RedactSecret(gl.Secret),
			Severity:    MapSeverity(gl.RuleID, gl.Description, gl.Tags),
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// normalizeFilePath converts OS-specific separators and cleans the path so
// output is consistent across platforms.
func normalizeFilePath(p string) string {
	if p == "" {
		return "<unknown>"
	}
	// Use forward slashes everywhere in output.
	return filepath.ToSlash(filepath.Clean(p))
}

// choosefingerprint prefers the fingerprint Gitleaks computed (which is stable
// across runs) but falls back to hashing the secret when absent.
func choosefingerprint(glFingerprint, secret string) string {
	if strings.TrimSpace(glFingerprint) != "" {
		return glFingerprint
	}
	return redact.Fingerprint(secret)
}

// severityRule maps substrings of rule IDs / descriptions to severities.
type severityRule struct {
	keyword  string
	severity string
}

var severityRules = []severityRule{
	// CRITICAL — private keys and certificates
	{"private-key", "CRITICAL"},
	{"privatekey", "CRITICAL"},
	{"private_key", "CRITICAL"},
	{"pem", "CRITICAL"},
	{"certificate", "CRITICAL"},
	{"pkcs", "CRITICAL"},
	{"rsa", "CRITICAL"},
	{"ssh-private", "CRITICAL"},
	{"openssh", "CRITICAL"},

	// HIGH — cloud-provider credentials
	{"aws-access", "HIGH"},
	{"aws-secret", "HIGH"},
	{"gcp", "HIGH"},
	{"azure", "HIGH"},
	{"digitalocean", "HIGH"},
	{"alibaba", "HIGH"},
	{"heroku", "HIGH"},
	{"twilio", "HIGH"},
	{"sendgrid", "HIGH"},
	{"stripe", "HIGH"},
	{"github-pat", "HIGH"},
	{"gitlab", "HIGH"},
	{"jwt", "HIGH"},

	// MEDIUM — generic API keys and passwords
	{"api-key", "MEDIUM"},
	{"apikey", "MEDIUM"},
	{"api_key", "MEDIUM"},
	{"password", "MEDIUM"},
	{"passwd", "MEDIUM"},
	{"secret", "MEDIUM"},
	{"token", "MEDIUM"},
	{"credential", "MEDIUM"},
	{"oauth", "MEDIUM"},
	{"auth", "MEDIUM"},
	{"bearer", "MEDIUM"},
}

// MapSeverity produces a deterministic severity string from a rule ID,
// description, and optional tags.  It is exported so Milestone 2's Risk Engine
// can call it directly or replace it entirely.
func MapSeverity(ruleID, description string, tags []string) string {
	lower := strings.ToLower(ruleID + " " + description)
	for _, tag := range tags {
		lower += " " + strings.ToLower(tag)
	}

	for _, rule := range severityRules {
		if strings.Contains(lower, rule.keyword) {
			return rule.severity
		}
	}
	return "LOW"
}
