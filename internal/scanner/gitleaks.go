// Package scanner — Gitleaks concrete implementation.
package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"secretguard/internal/config"
	"secretguard/internal/normalizer"
)

// ErrGitleaksNotFound is returned when the gitleaks binary cannot be found.
var ErrGitleaksNotFound = errors.New("gitleaks not found in PATH; install gitleaks and retry")

// ErrNotGitRepo is returned when the target directory is not a Git repository.
var ErrNotGitRepo = errors.New("target path is not a Git repository")

// ErrScanTimeout is returned when the subprocess exceeds the configured timeout.
var ErrScanTimeout = errors.New("scan timed out")

// GitleaksScanner implements Scanner using the installed gitleaks binary.
type GitleaksScanner struct {
	cfg config.Config
}

// NewGitleaksScanner constructs a scanner from the supplied config.
func NewGitleaksScanner(cfg config.Config) *GitleaksScanner {
	return &GitleaksScanner{cfg: cfg}
}

// Scan executes gitleaks against repoPath and normalises the results.
// It never panics; all errors are returned inside Result.Error.
func (g *GitleaksScanner) Scan(ctx context.Context, repoPath string) Result {
	// ── 1. Validate the binary is available ─────────────────────────────────
	binary, err := exec.LookPath(g.cfg.GitleaksBinary)
	if err != nil {
		return Result{Error: ErrGitleaksNotFound}
	}

	// ── 2. Validate repo path ────────────────────────────────────────────────
	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		return Result{Error: fmt.Errorf("invalid repo path %q: %w", repoPath, err)}
	}

	// ── 3. Build the command — NO string concatenation ───────────────────────
	//  gitleaks git --source <repo> --report-format json --exit-code 1
	//
	//  --exit-code 1 means gitleaks exits 1 when it finds secrets (default).
	//  We handle the exit code ourselves below.
	args := []string{
		"git",
		"--source", absRepo,
		"--report-format", "json",
		"--report-path", "stdout",
		"--exit-code", "1",
		"--no-banner",
	}

	scanCtx, cancel := context.WithTimeout(ctx, g.cfg.Timeout)
	defer cancel()

	//nolint:gosec // args are constructed from validated values, not user strings
	cmd := exec.CommandContext(scanCtx, binary, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// ── 4. Handle exit codes ─────────────────────────────────────────────────
	if scanCtx.Err() != nil {
		return Result{Error: ErrScanTimeout}
	}

	if runErr != nil {
		exitCode := exitCodeOf(runErr)
		switch exitCode {
		case 1:
			// Findings were detected — expected; parse stdout below.
		default:
			// Gitleaks reported a genuine error.
			// Do NOT forward stderr directly as it may contain secret content.
			stderrText := sanitiseStderr(stderr.String())
			if strings.Contains(strings.ToLower(stderrText), "not a git repository") ||
				strings.Contains(strings.ToLower(stderrText), "no git history") ||
				strings.Contains(strings.ToLower(stderrText), "does not exist") {
				return Result{Error: ErrNotGitRepo}
			}
			return Result{Error: fmt.Errorf("gitleaks execution failed (exit %d): %s", exitCode, stderrText)}
		}
	}

	// ── 5. Parse JSON output ─────────────────────────────────────────────────
	rawJSON := stdout.Bytes()

	findings, parseErr := normalizer.NormalizeGitleaks(rawJSON)
	if parseErr != nil {
		return Result{Error: fmt.Errorf("invalid gitleaks output: %w", parseErr)}
	}

	return Result{
		Findings:     findings,
		FilesScanned: 0, // populated in future milestones via gitleaks stats
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// exitCodeOf extracts the integer exit code from an *exec.ExitError.
func exitCodeOf(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// sanitiseStderr strips lines that might contain secret-like content before
// exposing the error to the caller.
func sanitiseStderr(s string) string {
	lines := strings.Split(s, "\n")
	safe := make([]string, 0, len(lines))
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "secret") ||
			strings.Contains(lower, "password") ||
			strings.Contains(lower, "token") ||
			strings.Contains(lower, "key=") {
			safe = append(safe, "<redacted line>")
			continue
		}
		safe = append(safe, line)
	}
	return strings.Join(safe, "\n")
}

// ── tool checks ──────────────────────────────────────────────────────────────

// CheckGitleaks verifies that gitleaks is installed and returns its version
// string.  Returns ("", ErrGitleaksNotFound) when not found.
func CheckGitleaks(binary string) (string, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return "", ErrGitleaksNotFound
	}

	// Try "version" subcommand first, fall back to "--version".
	out, err := exec.Command(path, "version").Output() //nolint:gosec
	if err != nil {
		out, err = exec.Command(path, "--version").Output() //nolint:gosec
		if err != nil {
			return "unknown", nil
		}
	}
	return strings.TrimSpace(string(out)), nil
}

// CheckGit verifies that git is installed and returns its version string.
func CheckGit() (string, error) {
	out, err := exec.Command("git", "version").Output()
	if err != nil {
		return "", fmt.Errorf("git not found in PATH")
	}
	return strings.TrimSpace(string(out)), nil
}

// IsGitRepo checks whether a directory is a Git repository.
func IsGitRepo(path string) bool {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}
