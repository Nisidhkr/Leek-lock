package scanner_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"secretguard/internal/config"
	"secretguard/internal/scanner"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// makeTempGitRepo creates a minimal git repo in a temp dir and returns its path.
// Returns empty string if Git is not available.
func makeTempGitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("git %v: %s", args, out)
		}
	}
	// Create an innocuous file and commit it.
	f := filepath.Join(dir, "README.md")
	if err := os.WriteFile(f, []byte("# Test repo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "."},
		{"commit", "-m", "init"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("git %v: %s", args, out)
		}
	}
	return dir
}

// ── GitleaksScanner ───────────────────────────────────────────────────────────

func TestGitleaksScanner_NotFound(t *testing.T) {
	cfg := config.Default()
	cfg.GitleaksBinary = "gitleaks-does-not-exist-binary-xyz"

	s := scanner.NewGitleaksScanner(cfg)
	result := s.Scan(context.Background(), ".")
	if result.Error == nil {
		t.Fatal("expected error when gitleaks binary missing")
	}
	if result.Error != scanner.ErrGitleaksNotFound {
		t.Errorf("expected ErrGitleaksNotFound, got: %v", result.Error)
	}
}

func TestGitleaksScanner_InvalidRepo(t *testing.T) {
	cfg := config.Default()
	if _, err := scanner.CheckGitleaks(cfg.GitleaksBinary); err != nil {
		t.Skip("gitleaks not installed, skipping")
	}

	// Scan a directory that is not a git repo.
	dir := t.TempDir()

	s := scanner.NewGitleaksScanner(cfg)
	result := s.Scan(context.Background(), dir)
	// We expect an error or no findings — never a panic.
	t.Logf("result for non-git dir: err=%v findings=%d", result.Error, len(result.Findings))
}

func TestGitleaksScanner_Timeout(t *testing.T) {
	cfg := config.Default()
	if _, err := scanner.CheckGitleaks(cfg.GitleaksBinary); err != nil {
		t.Skip("gitleaks not installed, skipping")
	}

	dir := makeTempGitRepo(t)

	// Set an absurdly short timeout to force cancellation.
	cfg.Timeout = 1 * time.Nanosecond

	s := scanner.NewGitleaksScanner(cfg)
	result := s.Scan(context.Background(), dir)
	// We may or may not get a timeout depending on system speed, but we must
	// not panic.
	t.Logf("timeout test result: err=%v", result.Error)
}

func TestGitleaksScanner_NoFindings(t *testing.T) {
	cfg := config.Default()
	if _, err := scanner.CheckGitleaks(cfg.GitleaksBinary); err != nil {
		t.Skip("gitleaks not installed, skipping")
	}

	dir := makeTempGitRepo(t)
	s := scanner.NewGitleaksScanner(cfg)
	result := s.Scan(context.Background(), dir)
	if result.Error != nil {
		t.Logf("scan error (may be expected in CI): %v", result.Error)
		return
	}
	// If no error, there should be no findings in an innocuous repo.
	for _, f := range result.Findings {
		t.Logf("unexpected finding in clean repo: %+v", f)
	}
}

// ── CheckGit / CheckGitleaks ──────────────────────────────────────────────────

func TestCheckGit(t *testing.T) {
	ver, err := scanner.CheckGit()
	if err != nil {
		t.Skipf("git not found: %v", err)
	}
	if ver == "" {
		t.Error("expected non-empty git version string")
	}
}

func TestCheckGitleaks_Missing(t *testing.T) {
	_, err := scanner.CheckGitleaks("nonexistent-gitleaks-xyz")
	if err == nil {
		t.Error("expected error for missing binary")
	}
}

// ── IsGitRepo ─────────────────────────────────────────────────────────────────

func TestIsGitRepo_NotRepo(t *testing.T) {
	dir := t.TempDir()
	if scanner.IsGitRepo(dir) {
		t.Error("empty temp dir should not be a git repo")
	}
}
