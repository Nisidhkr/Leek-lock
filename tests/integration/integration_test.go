// Package integration provides end-to-end tests for the SecretGuard CLI.
// These tests require that gitleaks is installed and available in PATH.
// Run them with: go test ./tests/integration/...
package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"secretguard/internal/config"
	"secretguard/internal/normalizer"
	"secretguard/internal/scanner"
)

// skipIfToolsMissing skips the test when required tools are absent.
func skipIfToolsMissing(t *testing.T) {
	t.Helper()
	cfg := config.Default()
	if _, err := scanner.CheckGitleaks(cfg.GitleaksBinary); err != nil {
		t.Skip("gitleaks not installed; skipping integration tests")
	}
}

// sampleRepoPath returns the absolute path to the sample-repo directory.
func sampleRepoPath(t *testing.T) string {
	t.Helper()
	// Walk up from tests/integration to find sample-repo.
	dir, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "sample-repo")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("sample-repo directory not found")
	return ""
}

// TestSampleRepo_HasFindings verifies that scanning the sample-repo detects
// the deliberately embedded fake credentials.
func TestSampleRepo_HasFindings(t *testing.T) {
	skipIfToolsMissing(t)

	repoPath := sampleRepoPath(t)
	if !scanner.IsGitRepo(repoPath) {
		t.Skip("sample-repo is not a Git repository (needs git init + commit)")
	}

	cfg := config.Default()
	s := scanner.NewGitleaksScanner(cfg)
	result := s.Scan(context.Background(), repoPath)

	if result.Error != nil {
		t.Fatalf("unexpected scan error: %v", result.Error)
	}
	if len(result.Findings) == 0 {
		t.Error("expected at least one finding in sample-repo, got none")
	}
}

// TestSampleRepo_NoRawSecrets verifies that no finding's Redacted field
// contains a full raw secret (basic sanity check).
func TestSampleRepo_NoRawSecrets(t *testing.T) {
	skipIfToolsMissing(t)

	repoPath := sampleRepoPath(t)
	if !scanner.IsGitRepo(repoPath) {
		t.Skip("sample-repo is not a Git repository")
	}

	cfg := config.Default()
	s := scanner.NewGitleaksScanner(cfg)
	result := s.Scan(context.Background(), repoPath)
	if result.Error != nil {
		t.Fatalf("unexpected scan error: %v", result.Error)
	}

	knownFakeSecrets := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"SuperSecr3tP@ssw0rd_FAKE_DO_NOT_USE",
		"stripe_test_key_placeholder",
		"SG.FakeExampleSendGridKeyForTestingOnly.NotReal123456789",
		"ghp_FakeExampleGitHubTokenForTestingOnly123",
	}

	for _, f := range result.Findings {
		for _, secret := range knownFakeSecrets {
			if f.Redacted == secret {
				t.Errorf("raw secret %q leaked into finding %s Redacted field", secret, f.ID)
			}
		}
	}
}

// TestFindingModel_Fields verifies that all mandatory Finding fields are populated.
func TestFindingModel_Fields(t *testing.T) {
	skipIfToolsMissing(t)

	repoPath := sampleRepoPath(t)
	if !scanner.IsGitRepo(repoPath) {
		t.Skip("sample-repo is not a Git repository")
	}

	cfg := config.Default()
	s := scanner.NewGitleaksScanner(cfg)
	result := s.Scan(context.Background(), repoPath)
	if result.Error != nil {
		t.Fatalf("unexpected scan error: %v", result.Error)
	}
	if len(result.Findings) == 0 {
		t.Skip("no findings to check")
	}

	for _, f := range result.Findings {
		assertNonEmpty(t, f, "ID", f.ID)
		assertNonEmpty(t, f, "File", f.File)
		assertNonEmpty(t, f, "Detector", f.Detector)
		assertNonEmpty(t, f, "Fingerprint", f.Fingerprint)
		assertNonEmpty(t, f, "Severity", f.Severity)
		if f.Detector != "gitleaks" {
			t.Errorf("finding %s: expected Detector=gitleaks, got %q", f.ID, f.Detector)
		}
	}
}

func assertNonEmpty(t *testing.T, f normalizer.Finding, field, value string) {
	t.Helper()
	if value == "" {
		t.Errorf("finding %s: field %q must not be empty", f.ID, field)
	}
}
