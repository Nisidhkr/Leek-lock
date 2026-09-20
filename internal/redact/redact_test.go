package redact_test

import (
	"strings"
	"testing"

	"secretguard/internal/redact"
)

// ── RedactSecret ─────────────────────────────────────────────────────────────

func TestRedactSecret_Empty(t *testing.T) {
	got := redact.RedactSecret("")
	if got != "<empty>" {
		t.Errorf("expected <empty>, got %q", got)
	}
}

func TestRedactSecret_Whitespace(t *testing.T) {
	got := redact.RedactSecret("   ")
	if got != "<empty>" {
		t.Errorf("expected <empty>, got %q", got)
	}
}

func TestRedactSecret_Short(t *testing.T) {
	cases := []string{"abc", "ab12", "12345", "abc123"}
	for _, tc := range cases {
		got := redact.RedactSecret(tc)
		if strings.Contains(got, tc) {
			t.Errorf("short secret %q was not redacted: got %q", tc, got)
		}
		if got == "" {
			t.Errorf("short secret %q produced empty output", tc)
		}
	}
}

func TestRedactSecret_Long(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	got := redact.RedactSecret(secret)

	// Must not contain full secret.
	if got == secret {
		t.Error("secret was not redacted")
	}
	// Must contain first 4 chars.
	if !strings.HasPrefix(got, "AKIA") {
		t.Errorf("expected prefix AKIA, got %q", got)
	}
	// Must contain last 4 chars.
	if !strings.HasSuffix(got, "MPLE") {
		t.Errorf("expected suffix MPLE, got %q", got)
	}
	// Must not be the full string.
	if got == secret {
		t.Error("full secret leaked into redacted output")
	}
}

func TestRedactSecret_Unicode(t *testing.T) {
	// emoji + latin mix — verify no panic and output does not equal input
	secret := "🔑🔑🔑🔑abcdefgh🔑🔑🔑🔑"
	got := redact.RedactSecret(secret)
	if got == secret {
		t.Error("unicode secret was not redacted")
	}
}

func TestRedactSecret_LongString(t *testing.T) {
	secret := strings.Repeat("x", 256)
	got := redact.RedactSecret(secret)
	if got == secret {
		t.Error("long secret was not redacted")
	}
	// Redacted form must be shorter than the original.
	if len(got) >= len(secret) {
		t.Errorf("redacted value (%d chars) is not shorter than secret (%d chars)", len(got), len(secret))
	}
}

// ── Fingerprint ──────────────────────────────────────────────────────────────

func TestFingerprint_Deterministic(t *testing.T) {
	secret := "super-secret-value"
	fp1 := redact.Fingerprint(secret)
	fp2 := redact.Fingerprint(secret)
	if fp1 != fp2 {
		t.Errorf("fingerprint not deterministic: %q vs %q", fp1, fp2)
	}
}

func TestFingerprint_DifferentInputs(t *testing.T) {
	fp1 := redact.Fingerprint("secret-a")
	fp2 := redact.Fingerprint("secret-b")
	if fp1 == fp2 {
		t.Error("different secrets produced the same fingerprint")
	}
}

func TestFingerprint_Prefix(t *testing.T) {
	fp := redact.Fingerprint("any-value")
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint must start with sha256:, got %q", fp)
	}
}

func TestFingerprint_Empty(t *testing.T) {
	fp := redact.Fingerprint("")
	if fp == "" {
		t.Error("fingerprint for empty string must not be empty")
	}
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint must start with sha256:, got %q", fp)
	}
}

func TestFingerprint_DoesNotContainSecret(t *testing.T) {
	secret := "my-very-secret-value"
	fp := redact.Fingerprint(secret)
	if strings.Contains(fp, secret) {
		t.Errorf("fingerprint must not contain the raw secret: %q", fp)
	}
}
