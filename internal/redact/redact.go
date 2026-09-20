// Package redact provides secret-value sanitisation helpers.
// The original secret MUST NEVER leave this package unredacted.
package redact

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// visiblePrefix is the number of runes shown at the start of a long secret.
	visiblePrefix = 4
	// visibleSuffix is the number of runes shown at the end of a long secret.
	visibleSuffix = 4
	// minLengthForPartial is the minimum rune-count where partial redaction is
	// used.  Secrets shorter than this are fully masked.
	minLengthForPartial = visiblePrefix + visibleSuffix + 4
	// maskChar is the placeholder character.
	maskChar = "*"
)

// RedactSecret replaces the bulk of a secret string with asterisks.
// Only the first and last few characters are retained so that analysts can
// visually match a finding without seeing the full value.
//
//   - Empty / whitespace-only strings → "<empty>"
//   - Short strings (fewer than minLengthForPartial runes) → "****"
//   - Long strings → first 4 chars + "****" + last 4 chars
func RedactSecret(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return "<empty>"
	}

	runes := []rune(trimmed)
	length := len(runes)

	if length < minLengthForPartial {
		return strings.Repeat(maskChar, 4)
	}

	prefix := string(runes[:visiblePrefix])
	suffix := string(runes[length-visibleSuffix:])
	return prefix + strings.Repeat(maskChar, 4) + suffix
}

// Fingerprint returns a stable SHA-256 hash of the secret.
// The hash is returned as a hex string prefixed with "sha256:".
// The raw secret is never stored or logged by this function.
func Fingerprint(secret string) string {
	if secret == "" {
		// Deterministic fingerprint for empty input.
		return "sha256:" + fmt.Sprintf("%x", sha256.Sum256([]byte("")))
	}
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + fmt.Sprintf("%x", sum)
}

// SafeLength returns the rune-count of a string without exposing its contents.
func SafeLength(s string) int {
	return utf8.RuneCountInString(s)
}
