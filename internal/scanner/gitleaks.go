// Package scanner — Gitleaks concrete implementation.
package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
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

	// ── 3. Create a temp file for the JSON report ────────────────────────────
	// Gitleaks writes its JSON report to --report-path (a file).
	// We use a temp file and read it after the scan completes.
	reportFile, err := os.CreateTemp("", "secretguard-gitleaks-*.json")
	if err != nil {
		return Result{Error: fmt.Errorf("failed to create temp report file: %w", err)}
	}
	reportPath := reportFile.Name()
	reportFile.Close() // gitleaks will write to it
	defer os.Remove(reportPath)

	// ── 4. Build the command — NO string concatenation ───────────────────────
	//  gitleaks git <repo> --report-format json --report-path <tempfile>
	//
	//  In Gitleaks 8.x the repo path is a positional argument to `git`.
	//  We write to a temp file and read it back — gitleaks does not support
	//  writing JSON to stdout directly.
	//  --exit-code 1 means gitleaks exits 1 when it finds secrets (default).
	args := []string{
		"git",
		absRepo, // positional repo path
		"--report-format", "json",
		"--report-path", reportPath,
		"--exit-code", "1",
		"--no-banner",
		"--log-level", "warn",
	}

	scanCtx, cancel := context.WithTimeout(ctx, g.cfg.Timeout)
	defer cancel()

	//nolint:gosec // args are constructed from validated values, not user strings
	cmd := exec.CommandContext(scanCtx, binary, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// ── 5. Handle exit codes ─────────────────────────────────────────────────
	if scanCtx.Err() != nil {
		return Result{Error: ErrScanTimeout}
	}

	if runErr != nil {
		exitCode := exitCodeOf(runErr)
		switch exitCode {
		case 1:
			// Findings were detected — expected; read report file below.
		default:
			// Gitleaks reported a genuine error.
			// Do NOT forward stderr directly as it may contain secret content.
			stderrText := sanitiseStderr(stderr.String())
			lower := strings.ToLower(stderrText)
			if strings.Contains(lower, "not a git repository") ||
				strings.Contains(lower, "no git history") ||
				strings.Contains(lower, "does not exist") {
				return Result{Error: ErrNotGitRepo}
			}
			return Result{Error: fmt.Errorf("gitleaks execution failed (exit %d): %s", exitCode, stderrText)}
		}
	}

	// ── 6. Read and parse the JSON report file ───────────────────────────────
	rawJSON, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		// If gitleaks found no leaks it may not write the file at all.
		if os.IsNotExist(readErr) {
			return Result{Findings: nil}
		}
		return Result{Error: fmt.Errorf("failed to read gitleaks report: %w", readErr)}
	}

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
