package normalizer_test

import (
	"strings"
	"testing"

	"secretguard/internal/normalizer"
)

// ── NormalizeGitleaks ─────────────────────────────────────────────────────────

func TestNormalizeGitleaks_EmptyInput(t *testing.T) {
	findings, err := normalizer.NormalizeGitleaks(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestNormalizeGitleaks_NullJSON(t *testing.T) {
	findings, err := normalizer.NormalizeGitleaks([]byte("null"))
	if err != nil {
		t.Fatalf("unexpected error for null input: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestNormalizeGitleaks_MalformedJSON(t *testing.T) {
	_, err := normalizer.NormalizeGitleaks([]byte("{bad json"))
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestNormalizeGitleaks_ValidSingleFinding(t *testing.T) {
	raw := []byte(`[
	  {
	    "Description": "AWS Access Key",
	    "StartLine": 18,
	    "EndLine": 18,
	    "StartColumn": 1,
	    "EndColumn": 20,
	    "Match": "aws_access_key_id = FAKEKEYID12345FAKE",
	    "Secret": "FAKEKEYID12345FAKE",
	    "File": "config/example.yaml",
	    "RuleID": "aws-access-token",
	    "Fingerprint": "abc123fingerprint"
	  }
	]`)

	findings, err := normalizer.NormalizeGitleaks(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.File != "config/example.yaml" {
		t.Errorf("file mismatch: %q", f.File)
	}
	if f.StartLine != 18 {
		t.Errorf("line mismatch: %d", f.StartLine)
	}
	if f.RuleID != "aws-access-token" {
		t.Errorf("rule mismatch: %q", f.RuleID)
	}
	if f.Detector != "gitleaks" {
		t.Errorf("detector mismatch: %q", f.Detector)
	}
	// Secret must NEVER be in the redacted value in full.
	if f.Redacted == "FAKEKEYID12345FAKE" {
		t.Error("raw secret leaked into Redacted field")
	}
	// Severity should be HIGH for aws-access-token.
	if f.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %q", f.Severity)
	}
}

func TestNormalizeGitleaks_MultipleFindings(t *testing.T) {
	raw := []byte(`[
	  {
	    "Description": "AWS Access Key",
	    "Secret": "FAKEKEYID00000FAKE",
	    "File": "a.yaml",
	    "RuleID": "aws-access-token",
	    "StartLine": 1
	  },
	  {
	    "Description": "Generic API Key",
	    "Secret": "stripe_fake_placeholder",
	    "File": "b.go",
	    "RuleID": "generic-api-key",
	    "StartLine": 5
	  }
	]`)

	findings, err := normalizer.NormalizeGitleaks(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].ID != "finding-001" {
		t.Errorf("expected finding-001, got %q", findings[0].ID)
	}
	if findings[1].ID != "finding-002" {
		t.Errorf("expected finding-002, got %q", findings[1].ID)
	}
}

func TestNormalizeGitleaks_MissingOptionalFields(t *testing.T) {
	// Only required fields populated — optional fields should default gracefully.
	raw := []byte(`[{"Secret": "tiny"}]`)
	findings, err := normalizer.NormalizeGitleaks(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.File == "" {
		t.Error("File should have a default value when missing")
	}
	if f.Detector != "gitleaks" {
		t.Errorf("Detector must always be 'gitleaks', got %q", f.Detector)
	}
}

// ── MapSeverity ───────────────────────────────────────────────────────────────

func TestMapSeverity_AWSAccessKey(t *testing.T) {
	sev := normalizer.MapSeverity("aws-access-token", "AWS Access Key", nil)
	if sev != "HIGH" {
		t.Errorf("expected HIGH, got %q", sev)
	}
}

func TestMapSeverity_PrivateKey(t *testing.T) {
	sev := normalizer.MapSeverity("private-key", "RSA Private Key", nil)
	if sev != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %q", sev)
	}
}

func TestMapSeverity_GenericAPIKey(t *testing.T) {
	sev := normalizer.MapSeverity("generic-api-key", "Generic API Key", nil)
	if sev != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %q", sev)
	}
}

func TestMapSeverity_Unknown(t *testing.T) {
	sev := normalizer.MapSeverity("xyzzy", "Unknown thing", nil)
	if sev != "LOW" {
		t.Errorf("expected LOW, got %q", sev)
	}
}

func TestNormalize_SecretNeverInOutput(t *testing.T) {
	secret := "SUPER_SECRET_VALUE_SHOULD_NOT_APPEAR"
	raw := []byte(`[{"Secret": "` + secret + `", "RuleID": "test-rule", "File": "test.go", "StartLine": 1}]`)
	findings, err := normalizer.NormalizeGitleaks(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	f := findings[0]
	if strings.Contains(f.Redacted, secret) {
		t.Errorf("raw secret leaked into Redacted: %q", f.Redacted)
	}
	if strings.Contains(f.Fingerprint, secret) {
		t.Errorf("raw secret leaked into Fingerprint: %q", f.Fingerprint)
	}
}
