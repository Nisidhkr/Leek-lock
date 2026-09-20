// Package scanner defines the Scanner interface and shared types.
// All concrete detectors (gitleaks, future ML detector, etc.) implement this
// interface so the rest of the codebase stays detector-agnostic.
package scanner

import (
	"context"

	"secretguard/internal/normalizer"
)

// Result is returned by every Scanner implementation.
type Result struct {
	Findings     []normalizer.Finding
	FilesScanned int
	Error        error
}

// Scanner is the detection interface.  Milestone 2 will add a second
// implementation that walks Git history.
type Scanner interface {
	// Scan runs detection against the repository at repoPath.
	Scan(ctx context.Context, repoPath string) Result
}
