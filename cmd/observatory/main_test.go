package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openclaw/clawscan/internal/observatory"
)

func cliEvidence(runID string, completedAt string) observatory.Evidence {
	return observatory.Evidence{
		SchemaVersion:       observatory.EvidenceSchemaVersion,
		CaptureConfigSHA256: "sha256:" + strings.Repeat("d", 64),
		Target: observatory.TargetEvidence{
			Name: "fixture-skill", Kind: "skill", ID: "fixture-skill", Lineage: "example/fixture-skill",
			SHA256: "sha256:" + strings.Repeat("a", 64), FileCount: 1, DirectoryCount: 1, TotalBytes: 10,
			Files:       []observatory.TargetFile{{Path: "SKILL.md", Bytes: 10, Mode: "0644"}},
			Directories: []observatory.TargetDirectory{{Path: ".", Mode: "0755"}},
		},
		Run: observatory.RunEvidence{
			ID: runID, Status: "completed", StartedAt: "2026-07-10T11:59:59Z", CompletedAt: completedAt, Executor: "fixture",
			Isolation: observatory.IsolationEvidence{
				Substrate: "proxmox-vm", NetworkMode: "deny-except-model", ContainmentProfile: "fixture",
				GuestFirewallSHA256: "sha256:" + strings.Repeat("b", 64), GuestFirewallPolicySHA256: "sha256:" + strings.Repeat("e", 64), Verification: "fixture",
			},
			Runtime: observatory.RuntimeEvidence{OpenClawVersion: "OpenClaw fixture", StraceVersion: "strace fixture", ModelProvider: "local", ModelID: "fixture", ModelEndpoint: "private"},
		},
		Exercise:     observatory.ExerciseEvidence{PromptSHA256: "sha256:" + strings.Repeat("c", 64), TurnLimit: 1},
		Observations: []observatory.Observation{},
		Canaries:     []observatory.CanaryObservation{{ID: "cloud-credentials", Surface: "home file"}},
		Coverage:     observatory.CoverageEvidence{SyscallScope: "selected-mvp-syscalls", FileSyscalls: true, ProcessSyscalls: true, NetworkSyscalls: true, BaselinePaired: true, Limitations: []string{"Fixture limitation."}},
	}
}

func writeEvidenceFile(t *testing.T, path string, evidence observatory.Evidence) {
	t.Helper()
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeHistoryConfig(t *testing.T, dir string, artifactsDir string) string {
	t.Helper()
	config := "version: 1\n" +
		"targetLineage: example/fixture-skill\n" +
		"artifactsDir: " + artifactsDir + "\n" +
		"executor:\n  kind: crabbox\n  command: crabbox\n  crabboxConfig: crabbox.yml\n" +
		"runtime:\n  model:\n    id: fixture-model\n    baseUrl: http://10.0.0.2:8000/v1\n    api: openai-completions\n"
	path := filepath.Join(dir, "observatory.yml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRenderAutoPreviousSelectsHistoryPredecessor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secure site rendering requires Linux")
	}
	dir := t.TempDir()
	artifactsDir := filepath.Join(dir, "artifacts")
	store, err := observatory.OpenHistoryStore(artifactsDir)
	if err != nil {
		t.Fatal(err)
	}
	previous := cliEvidence("obs_prev", "2026-07-10T12:00:00Z")
	if err := store.Record(previous, 10); err != nil {
		t.Fatal(err)
	}
	current := cliEvidence("obs_cur", "2026-07-11T12:00:00Z")
	current.Target.SHA256 = "sha256:" + strings.Repeat("f", 64)
	current.Observations = append(current.Observations, observatory.Observation{
		Kind: "network", Operation: "connect", Subject: "93.184.216.34:443", Outcome: "succeeded", Role: "external", ExerciseCount: 1, DeltaCount: 1,
	})
	inputPath := filepath.Join(dir, "current.json")
	writeEvidenceFile(t, inputPath, current)
	configPath := writeHistoryConfig(t, dir, artifactsDir)
	site := filepath.Join(dir, "site")

	var stdout, stderr bytes.Buffer
	err = run(context.Background(), []string{"render", "--input", inputPath, "--output", site, "--auto-previous", "--config", configPath}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("render --auto-previous: %v (stderr=%s)", err, stderr.String())
	}
	html, err := os.ReadFile(filepath.Join(site, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToUpper(string(html))
	if !strings.Contains(text, "VERSION DELTA") || !strings.Contains(text, "93.184.216.34:443") {
		t.Fatalf("rendered site missing auto-selected version delta: %s", html)
	}
}

func TestRenderAutoPreviousRendersCurrentOnlyWithoutPredecessor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secure site rendering requires Linux")
	}
	dir := t.TempDir()
	artifactsDir := filepath.Join(dir, "artifacts")
	if _, err := observatory.OpenHistoryStore(artifactsDir); err != nil {
		t.Fatal(err)
	}
	current := cliEvidence("obs_cur", "2026-07-11T12:00:00Z")
	inputPath := filepath.Join(dir, "current.json")
	writeEvidenceFile(t, inputPath, current)
	configPath := writeHistoryConfig(t, dir, artifactsDir)
	site := filepath.Join(dir, "site")

	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"render", "--input", inputPath, "--output", site, "--auto-previous", "--config", configPath}, &stdout, &stderr); err != nil {
		t.Fatalf("render --auto-previous: %v", err)
	}
	if !strings.Contains(stderr.String(), "no comparable predecessor") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(site, "index.html")); err != nil {
		t.Fatalf("current-only site not rendered: %v", err)
	}
}

func TestRenderAutoPreviousFailsClosedOnCorruptHistory(t *testing.T) {
	dir := t.TempDir()
	artifactsDir := filepath.Join(dir, "artifacts")
	store, err := observatory.OpenHistoryStore(artifactsDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(cliEvidence("obs_prev", "2026-07-10T12:00:00Z"), 10); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "history", "index.json"), []byte("{ broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	current := cliEvidence("obs_cur", "2026-07-11T12:00:00Z")
	inputPath := filepath.Join(dir, "current.json")
	writeEvidenceFile(t, inputPath, current)
	configPath := writeHistoryConfig(t, dir, artifactsDir)

	var stdout, stderr bytes.Buffer
	err = run(context.Background(), []string{"render", "--input", inputPath, "--output", filepath.Join(dir, "site"), "--auto-previous", "--config", configPath}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "corrupt history") {
		t.Fatalf("expected corrupt-history failure, err = %v", err)
	}
}

func TestRenderRejectsPreviousWithAutoPrevious(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"render", "--input", "x.json", "--output", "site", "--previous", "y.json", "--auto-previous"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v", err)
	}
}

func TestScanRejectsMissingTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"scan"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "usage: observatory scan") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "--no-history") {
		t.Fatalf("scan usage does not document history flags: %v", err)
	}
}

func TestRenderRequiresInputAndOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"render", "--auto-previous"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "usage: observatory render") {
		t.Fatalf("err = %v", err)
	}
}
