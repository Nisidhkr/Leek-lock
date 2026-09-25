// main is the entry-point for the secretguard CLI.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"secretguard/internal/config"
	"secretguard/internal/report"
	"secretguard/internal/scanner"
)

// version is injected at build time via -ldflags.
var version = "0.1.0"

func main() {
	cfg := config.Default()
	cfg.Version = version

	root := buildRoot(cfg)
	if err := root.Execute(); err != nil {
		os.Exit(2)
	}
}

// buildRoot constructs the full Cobra command tree.
func buildRoot(cfg config.Config) *cobra.Command {
	root := &cobra.Command{
		Use:           "secretguard",
		Short:         "SecretGuard — secrets scanner powered by Gitleaks",
		Long:          "SecretGuard scans Git repositories for leaked secrets and sensitive credentials.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(buildScan(cfg))
	root.AddCommand(buildVersion(cfg))
	root.AddCommand(buildDoctor(cfg))

	return root
}

// ── scan ─────────────────────────────────────────────────────────────────────

func buildScan(cfg config.Config) *cobra.Command {
	var repoPath string
	var format string
	var gitleaksBinary string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a Git repository for leaked secrets",
		Long: `Scan runs Gitleaks against the target repository, normalises findings,
redacts secret values, and renders a clean report.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if gitleaksBinary != "" {
				cfg.GitleaksBinary = gitleaksBinary
			}
			return runScan(cfg, repoPath, format)
		},
	}

	cmd.Flags().StringVar(&repoPath, "repo", ".", "Path to the Git repository to scan")
	cmd.Flags().StringVar(&format, "format", "terminal", "Output format: terminal or json")
	cmd.Flags().StringVar(&gitleaksBinary, "gitleaks", "", "Path to the gitleaks binary (default: 'gitleaks' in PATH)")

	return cmd
}

func runScan(cfg config.Config, repoPath, format string) error {
	// ── Validate repo path ───────────────────────────────────────────────────
	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		return fmt.Errorf("repository not found: %w", err)
	}

	info, err := os.Stat(absRepo)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("repository not found: %s", absRepo)
	}

	if !scanner.IsGitRepo(absRepo) {
		return fmt.Errorf("not a Git repository: %s", absRepo)
	}

	// ── Run scanner ──────────────────────────────────────────────────────────
	s := scanner.NewGitleaksScanner(cfg)
	result := s.Scan(context.Background(), absRepo)

	if result.Error != nil {
		// Surface the error with a meaningful message.
		switch result.Error {
		case scanner.ErrGitleaksNotFound:
			fmt.Fprintln(os.Stderr, "✗ Gitleaks not found.\n\nInstall Gitleaks and ensure it is available in PATH.\n  https://github.com/gitleaks/gitleaks#installing")
			os.Exit(2)
		case scanner.ErrNotGitRepo:
			fmt.Fprintf(os.Stderr, "✗ Not a Git repository: %s\n", absRepo)
			os.Exit(2)
		case scanner.ErrScanTimeout:
			fmt.Fprintln(os.Stderr, "✗ Scan timed out.")
			os.Exit(2)
		default:
			fmt.Fprintf(os.Stderr, "✗ Scan failed: %v\n", result.Error)
			os.Exit(2)
		}
	}

	summary := report.Summary{
		FilesScanned: result.FilesScanned,
		Version:      cfg.Version,
	}

	// ── Render ───────────────────────────────────────────────────────────────
	switch strings.ToLower(format) {
	case "json":
		data, err := report.RenderJSON(result.Findings, summary)
		if err != nil {
			return fmt.Errorf("failed to render JSON: %w", err)
		}
		fmt.Println(string(data))

	case "terminal", "":
		report.RenderTerminal(os.Stdout, result.Findings, summary)

	default:
		return fmt.Errorf("unknown format %q: must be \"terminal\" or \"json\"", format)
	}

	// ── Exit code ─────────────────────────────────────────────────────────────
	//  0 = no findings
	//  1 = findings detected
	//  2 = error (handled above)
	if len(result.Findings) > 0 {
		os.Exit(1)
	}
	return nil
}

// ── version ──────────────────────────────────────────────────────────────────

func buildVersion(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print SecretGuard version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("SecretGuard v%s\n", cfg.Version)
		},
	}
}

// ── doctor ───────────────────────────────────────────────────────────────────

func buildDoctor(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check that all required tools are installed",
		Run: func(cmd *cobra.Command, args []string) {
			runDoctor(cfg)
		},
	}
}

func runDoctor(cfg config.Config) {
	divider := strings.Repeat("─", 40)
	fmt.Println()
	fmt.Printf("\033[1m\033[97mSecretGuard Doctor\033[0m\n")
	fmt.Println("\033[90m" + divider + "\033[0m")
	fmt.Println()

	allOK := true

	// ── Git ──────────────────────────────────────────────────────────────────
	gitVer, err := scanner.CheckGit()
	if err != nil {
		fmt.Printf("  \033[31m✗\033[0m Git         not found\n")
		allOK = false
	} else {
		short := shortVersion(gitVer)
		fmt.Printf("  \033[32m✓\033[0m Git         %s\n", short)
	}

	// ── Gitleaks ─────────────────────────────────────────────────────────────
	glVer, err := scanner.CheckGitleaks(cfg.GitleaksBinary)
	if err != nil {
		fmt.Printf("  \033[31m✗\033[0m Gitleaks    not found\n")
		allOK = false
	} else {
		short := shortVersion(glVer)
		fmt.Printf("  \033[32m✓\033[0m Gitleaks    %s\n", short)
	}

	// ── Repository ───────────────────────────────────────────────────────────
	cwd, _ := os.Getwd()
	if scanner.IsGitRepo(cwd) {
		fmt.Printf("  \033[32m✓\033[0m Repository detected\n")
	} else {
		fmt.Printf("  \033[33m⚠\033[0m No Git repository in current directory\n")
	}

	fmt.Println()
	if allOK {
		fmt.Println("\033[32m\033[1mSystem ready.\033[0m")
	} else {
		fmt.Println("\033[31mSome checks failed. See above for details.\033[0m")
		if _, err := scanner.CheckGitleaks(cfg.GitleaksBinary); err != nil {
			fmt.Println()
			fmt.Println("Install Gitleaks:")
			fmt.Println("  https://github.com/gitleaks/gitleaks#installing")
		}
	}
	fmt.Println()
}

// shortVersion trims verbose version strings like "git version 2.x.y" to "2.x.y".
func shortVersion(v string) string {
	// Handle JSON-formatted version output
	var obj map[string]interface{}
	if json.Unmarshal([]byte(v), &obj) == nil {
		if ver, ok := obj["version"].(string); ok {
			return ver
		}
	}
	// Strip common prefixes
	v = strings.TrimPrefix(v, "git version ")
	v = strings.TrimPrefix(v, "gitleaks version ")
	v = strings.TrimPrefix(v, "v")
	// Take only the first line
	if idx := strings.IndexAny(v, "\n\r"); idx != -1 {
		v = v[:idx]
	}
	return strings.TrimSpace(v)
}
