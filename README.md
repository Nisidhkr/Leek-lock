# SecretGuard

SecretGuard is a Go CLI that detects leaked secrets and sensitive credentials in Git repositories. It uses [Gitleaks](https://github.com/gitleaks/gitleaks) as its detection engine, normalises findings into a clean internal model, safely redacts secret values so they are never exposed in output, and renders results as readable terminal output or structured JSON.

---

## Current Milestone — Milestone 1

Milestone 1 delivers a clean, reliable foundation:

- ✅ **Go CLI** — Cobra-based `secretguard` command with `scan`, `version`, and `doctor` sub-commands
- ✅ **Gitleaks integration** — safe subprocess execution via `exec.CommandContext` with timeout and context cancellation
- ✅ **Finding normalisation** — Gitleaks JSON → canonical `Finding` struct
- ✅ **Secret redaction** — original values are never stored or printed
- ✅ **Deterministic fingerprinting** — SHA-256 based, enables cross-scan correlation in future milestones
- ✅ **Terminal output** — colour-coded, severity-labelled, readable at a glance
- ✅ **JSON output** — structured, machine-readable, CI-friendly
- ✅ **Sample repository** — deliberately fake credentials for safe demonstration
- ✅ **Unit tests** — redaction, fingerprinting, normalisation, scanner error paths

---

## Installation

### Prerequisites

| Tool | Install |
|------|---------|
| **Go 1.21+** | https://go.dev/dl/ |
| **Git** | https://git-scm.com/ |
| **Gitleaks** | https://github.com/gitleaks/gitleaks#installing |

### Quick install (Gitleaks)

```bash
# macOS / Linux (Homebrew)
brew install gitleaks

# Windows (Scoop)
scoop install gitleaks

# Direct download
# https://github.com/gitleaks/gitleaks/releases
```

### Build SecretGuard

```bash
git clone <this-repo>
cd secretguard
make build
# Binary at ./bin/secretguard
```

---

## Usage

```bash
# Check system readiness
./bin/secretguard doctor

# Scan the current Git repository (terminal output)
./bin/secretguard scan

# Scan a specific repository
./bin/secretguard scan --repo /path/to/repo

# JSON output (CI-friendly)
./bin/secretguard scan --format json

# Print version
./bin/secretguard version
```

### Sample repository demo

```bash
./bin/secretguard scan --repo sample-repo
```

Expected: 3–4 findings (all fake credentials).

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed — no findings |
| `1` | Scan completed — findings detected |
| `2` | Configuration or tool error |

This enables future CI integration:

```yaml
# GitHub Actions (Milestone 5)
- run: secretguard scan --format json
  # Non-zero exit blocks the merge
```

---

## Security

> **SecretGuard never intentionally stores or prints raw detected secrets.**

- The `internal/redact` package is the single place where the original secret value is consumed and masked.
- The canonical `Finding` struct contains only the `redacted_value` field — the raw secret is discarded immediately.
- JSON and terminal renderers receive `Finding` values, never raw subprocess output.
- Stderr from Gitleaks is sanitised before being included in error messages.

---

## Project Structure

```
secretguard/
├── cmd/secretguard/main.go      # Cobra CLI entry-point
├── internal/
│   ├── config/config.go         # All configurable knobs
│   ├── scanner/
│   │   ├── scanner.go           # Scanner interface
│   │   └── gitleaks.go          # Gitleaks subprocess wrapper
│   ├── normalizer/finding.go    # Canonical Finding model + Gitleaks mapper
│   ├── redact/redact.go         # Secret redaction + fingerprinting
│   └── report/
│       ├── terminal.go          # Colour terminal renderer
│       └── json.go              # JSON renderer
├── sample-repo/                 # Demo repo with fake credentials
├── Makefile
└── go.mod
```

---

## Future Roadmap

| Milestone | Feature |
|-----------|---------|
| **2** | Git history scanning + Risk Engine (severity scoring v2) |
| **3** | ML false-positive classifier (training data collection) |
| **4** | ML integration into scan pipeline |
| **5** | Pre-commit hooks + GitHub Actions CI integration |
| **6** | Automated remediation workflows |
| **7** | Web dashboard (Next.js + PostgreSQL) |
| **8** | Optional AI assistant for triage |

---

## Development

```bash
make build    # Build the binary
make test     # Run all unit tests
make lint     # Run go vet
make scan     # Scan this repository with the built binary
make clean    # Remove build artefacts
```
