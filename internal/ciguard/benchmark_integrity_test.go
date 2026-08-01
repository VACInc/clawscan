package ciguard

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBenchmarkIDVerifierRejectsFlippedJudgmentBeforeScannerStep(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "subset.jsonl")
	original := `{"id":"case_00001","judgment":"normal","risk_labels":[],"skill_path":"benchmark_full_v1.0/case_00001"}` + "\n"
	if err := os.WriteFile(fixture, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	expectedSHA256 := fmt.Sprintf("%x", sha256.Sum256([]byte(original)))
	flipped := strings.Replace(original, `"judgment":"normal"`, `"judgment":"malicious"`, 1)
	if err := os.WriteFile(fixture, []byte(flipped), 0o600); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(dir, "scanner-executed")
	command := exec.Command("bash", "-c", `bash "$VERIFY_SCRIPT" && touch "$SCANNER_MARKER"`)
	command.Env = append(os.Environ(),
		"VERIFY_SCRIPT=../../scripts/verify-benchmark-id-source.sh",
		"IDS_SOURCE="+fixture,
		"IDS_SHA256="+expectedSHA256,
		"GITHUB_ENV="+filepath.Join(dir, "github-env"),
		"RUNNER_TEMP="+dir,
		"SCANNER_MARKER="+marker,
	)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "benchmark IDs SHA-256 mismatch") {
		t.Fatalf("verifier error = %v, output = %s", err, output)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("scanner step ran after flipped judgment: %v", statErr)
	}
	t.Logf("verifier output: %s; scanner marker absent", strings.TrimSpace(string(output)))
}
