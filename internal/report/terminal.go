// Package report — terminal renderer.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"secretguard/internal/normalizer"
)

// ANSI colour codes — kept minimal so the output works in CI terminals too.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[32m"
	ansiGray   = "\033[90m"
	ansiWhite  = "\033[97m"
)

// Summary carries scan-level statistics for display.
type Summary struct {
	FilesScanned int
	Version      string
}

// RenderTerminal writes a human-readable scan report to w (usually os.Stdout).
func RenderTerminal(w io.Writer, findings []normalizer.Finding, summary Summary) {
	if w == nil {
		w = os.Stdout
	}

	divider := strings.Repeat("─", 50)

	// ── Header ───────────────────────────────────────────────────────────────
	fmt.Fprintf(w, "\n%sSecretGuard v%s%s\n", ansiBold+ansiWhite, summary.Version, ansiReset)
	fmt.Fprintln(w, ansiGray+divider+ansiReset)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scanning repository…")
	fmt.Fprintln(w)

	// ── Stats ─────────────────────────────────────────────────────────────────
	if summary.FilesScanned > 0 {
		fmt.Fprintf(w, "  %-18s %s%d%s\n", "Files scanned", ansiBold, summary.FilesScanned, ansiReset)
	}
	fmt.Fprintf(w, "  %-18s %s%d%s\n", "Findings", ansiBold, len(findings), ansiReset)
	fmt.Fprintln(w)

	if len(findings) == 0 {
		fmt.Fprintf(w, "%s✓ No findings detected.%s\n", ansiGreen, ansiReset)
		fmt.Fprintln(w)
		fmt.Fprintln(w, ansiGray+divider+ansiReset)
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Result  %s0 findings%s\n\n", ansiGreen+ansiBold, ansiReset)
		return
	}

	// ── Findings ─────────────────────────────────────────────────────────────
	for _, f := range findings {
		sev, colour := severityStyle(f.Severity)
		fmt.Fprintf(w, "%s%-10s%s %s%s%s\n",
			colour+ansiBold, sev, ansiReset,
			ansiBold, f.Description, ansiReset,
		)
		fmt.Fprintf(w, "          %s%s%s:%d\n", ansiCyan, f.File, ansiReset, f.StartLine)
		fmt.Fprintf(w, "          Rule      %s\n", f.RuleID)
		fmt.Fprintf(w, "          Detector  %s\n", f.Detector)
		fmt.Fprintf(w, "          Value     %s%s%s\n", ansiYellow, f.Redacted, ansiReset)
		fmt.Fprintln(w)
	}

	// ── Footer ────────────────────────────────────────────────────────────────
	fmt.Fprintln(w, ansiGray+divider+ansiReset)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Result  %s%d finding(s)%s\n\n", ansiRed+ansiBold, len(findings), ansiReset)
}

// severityStyle maps a severity string to a display label and ANSI colour.
func severityStyle(severity string) (string, string) {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "CRITICAL", "\033[35m" // magenta
	case "HIGH":
		return "HIGH", ansiRed
	case "MEDIUM":
		return "MEDIUM", ansiYellow
	case "LOW":
		return "LOW", ansiGray
	default:
		return "UNKNOWN", ansiGray
	}
}
