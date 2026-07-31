package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	hostileRoot = "../../testdata/fixtures/hostile-profile-proposal"
	validRoot   = "../../testdata/fixtures/valid-profile-proposal"

	hostileProposal = "proposals/GHSA-xxxx-yyyy-zzzz/clawscan.yml"
	validProposal   = "proposals/GHSA-abcd-efgh-ijkl/clawscan.yml"
)

// TestHostileProposalIsTreatedAsData is the regression for the profile-gate
// trust boundary. Validation must parse an attacker-authored profile without
// executing any of its fields, so the canary is never read and the execution
// marker is never created.
func TestHostileProposalIsTreatedAsData(t *testing.T) {
	dir := t.TempDir()
	canaryPath := filepath.Join(dir, "canary.txt")
	markerPath := filepath.Join(dir, "marker.txt")
	const canaryValue = "clawscan-canary-6b0f0b6f"
	if err := os.WriteFile(canaryPath, []byte(canaryValue), 0o600); err != nil {
		t.Fatalf("write canary: %v", err)
	}
	t.Setenv("CLAWSCAN_TEST_CANARY", canaryValue)
	t.Setenv("CLAWSCAN_TEST_CANARY_FILE", canaryPath)
	t.Setenv("CLAWSCAN_TEST_MARKER_FILE", markerPath)

	var stdout, stderr bytes.Buffer
	err := run([]string{"--root", hostileRoot, "--proposal", hostileProposal}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("hostile proposal should validate as data: %v (stderr=%s)", err, stderr.String())
	}
	if _, statErr := os.Stat(markerPath); statErr == nil {
		t.Fatal("hostile proposal produced an execution marker; the proposal lane executed untrusted profile fields")
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, canaryValue) {
		t.Fatal("validator output leaked the canary value")
	}
	if !strings.Contains(stdout.String(), "no profile field was executed") {
		t.Fatalf("unexpected validator output: %q", stdout.String())
	}
}

func TestValidProposalPasses(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--root", validRoot, "--proposal", validProposal}, &stdout, &stderr); err != nil {
		t.Fatalf("valid proposal rejected: %v (stderr=%s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "profile clawhub: scanners=virustotal,skillspector,clawscan-static") {
		t.Fatalf("unexpected summary: %q", stdout.String())
	}
}

func TestProposalPathIsConstrained(t *testing.T) {
	cases := []string{
		"clawscan.yml",
		"proposals/clawscan.yml",
		"proposals/GHSA-xxxx-yyyy-zzzz/../../etc/clawscan.yml",
		"/etc/clawscan.yml",
		"proposals/GHSA-xxxx-yyyy-zzzz/other.yml",
	}
	for _, candidate := range cases {
		if err := validateProposalPath(candidate); err == nil {
			t.Fatalf("expected rejection for %q", candidate)
		}
	}
	if err := validateProposalPath(hostileProposal); err != nil {
		t.Fatalf("expected acceptance for %q: %v", hostileProposal, err)
	}
}

func TestProposalRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	proposalDir := filepath.Join(dir, "proposals", "GHSA-xxxx-yyyy-zzzz")
	if err := os.MkdirAll(proposalDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	secret := filepath.Join(dir, "secret.yml")
	if err := os.WriteFile(secret, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(secret, filepath.Join(proposalDir, "clawscan.yml")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"--root", dir, "--proposal", hostileProposal}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected regular-file rejection, got %v", err)
	}
}

func TestChangedFileScope(t *testing.T) {
	proposal := validProposal
	allowed := []string{
		proposal,
		"internal/profiles/clawhub/clawscan.yml",
		"internal/profiles/clawhub/prompt.md",
		"internal/profiles/clawhub/output.schema.json",
		"benchmarks/skilltrustbench-leaderboard-10pct/2026-07-30.json",
		"",
	}
	if err := validateChangedFiles(proposal, "2026-07-31", allowed); err != nil {
		t.Fatalf("expected allowed scope: %v", err)
	}

	rejected := [][]string{
		{".github/workflows/ci.yml"},
		{"cmd/clawscan/main.go"},
		{"benchmarks/skilltrustbench-leaderboard-10pct/2026-08-05.json"},
		{"proposals/GHSA-0000-0000-0000/clawscan.yml"},
	}
	for _, changed := range rejected {
		if err := validateChangedFiles(proposal, "2026-07-31", changed); err == nil {
			t.Fatalf("expected rejection for %v", changed)
		}
	}
}

func TestMultiDocumentProposalIsRejected(t *testing.T) {
	dir := t.TempDir()
	proposalDir := filepath.Join(dir, "proposals", "GHSA-abcd-efgh-ijkl")
	if err := os.MkdirAll(proposalDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "version: 1\nprofiles:\n  clawhub:\n    scanners:\n      - clawscan-static\n---\nversion: 1\nprofiles:\n  clawhub:\n    scanners:\n      - skillspector\n"
	if err := os.WriteFile(filepath.Join(proposalDir, "clawscan.yml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"--root", dir, "--proposal", validProposal}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "exactly one YAML document") {
		t.Fatalf("expected single-document rejection, got %v", err)
	}
}
