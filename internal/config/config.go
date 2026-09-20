// Package config holds all configurable knobs for SecretGuard.
// Future milestones extend this struct rather than hard-coding values elsewhere.
package config

import "time"

// Config carries every user-facing setting for a scan run.
type Config struct {
	// GitleaksBinary is the name (or full path) of the gitleaks executable.
	// Defaults to "gitleaks" so the system PATH is used.
	GitleaksBinary string

	// RepoPath is the directory to scan. Defaults to ".".
	RepoPath string

	// Format controls output: "terminal" or "json".
	Format string

	// Timeout is the maximum time allowed for the gitleaks subprocess.
	Timeout time.Duration

	// Version is the SecretGuard release string injected at build time.
	Version string
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	return Config{
		GitleaksBinary: "gitleaks",
		RepoPath:       ".",
		Format:         "terminal",
		Timeout:        5 * time.Minute,
		Version:        "0.1.0",
	}
}
