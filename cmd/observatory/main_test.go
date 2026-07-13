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

// validEvidenceForTest builds a minimal, valid, complete piece of behavior
// evidence for exercising the CLI grade surface without provisioning a VM.
func validEvidenceForTest() observatory.Evidence {
	return cliEvidence("obs_cli", "2026-07-10T12:00:00Z")
}

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
		Canaries: []observatory.CanaryObservation{
			{ID: "cloud-credentials", Surface: "home file"},
			{ID: "openclaw-credentials", Surface: "state file"},
			{ID: "workspace-identity", Surface: "workspace file"},
			{ID: "workspace-memory", Surface: "workspace file"},
		},
		Coverage: observatory.CoverageEvidence{SyscallScope: "selected-mvp-syscalls", FileSyscalls: true, ProcessSyscalls: true, NetworkSyscalls: true, BaselinePaired: true, Limitations: []string{"Fixture limitation."}},
	}
}

func writeTempEvidenceFile(t *testing.T, evidence observatory.Evidence) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.json")
	writeEvidenceFile(t, path, evidence)
	return path
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

func TestGradeCommandEmitsDerivedGradeJSON(t *testing.T) {
	path := writeTempEvidenceFile(t, validEvidenceForTest())
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"grade", "--input", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var grade observatory.Grade
	if err := json.Unmarshal(stdout.Bytes(), &grade); err != nil {
		t.Fatalf("grade output is not JSON: %v\n%s", err, stdout.String())
	}
	if grade.SchemaVersion != observatory.GradeSchemaVersion || grade.PolicyVersion != observatory.GradePolicyVersion {
		t.Fatalf("grade versions = %#v", grade)
	}
	if !grade.Graded || grade.Letter != "A" {
		t.Fatalf("clean evidence graded=%v letter=%q", grade.Graded, grade.Letter)
	}
	if err := observatory.ValidateGrade(grade); err != nil {
		t.Fatalf("emitted grade invalid: %v", err)
	}
}

func TestGradeCommandGradesHardEscalatorF(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secure standalone grade artifacts require Linux")
	}
	evidence := validEvidenceForTest()
	// A planted canary value on an observed outbound trace is an authoritative
	// hard escalator available in base evidence.
	evidence.Observations = []observatory.Observation{{
		Kind: "network", Operation: "send", Subject: "[canary:cloud-credentials]->198.51.100.7:443", Outcome: "succeeded",
		Role: "external", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1,
	}}
	path := writeTempEvidenceFile(t, evidence)
	output := filepath.Join(t.TempDir(), "grade.json")
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"grade", "--input", path, "--output", output}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var grade observatory.Grade
	if err := json.Unmarshal(data, &grade); err != nil {
		t.Fatal(err)
	}
	if grade.Letter != "F" {
		t.Fatalf("persistence grade letter = %q", grade.Letter)
	}
}

func TestGradeCommandRequiresInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"grade"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("err = %v", err)
	}
}

func stubScan(evidence observatory.Evidence, runDir string) func() {
	previous := scanFn
	scanFn = func(_ context.Context, _ string, _ observatory.Config, _ observatory.CommandExecutor) (observatory.ScanResult, error) {
		return observatory.ScanResult{Evidence: evidence, RunDirectory: runDir}, nil
	}
	return func() { scanFn = previous }
}

func countSnapshotFiles(t *testing.T, artifactsDir string) int {
	t.Helper()
	root := filepath.Join(artifactsDir, "history", "snapshots")
	identities, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, identity := range identities {
		if !identity.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, identity.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
				total++
			}
		}
	}
	return total
}

func TestScanFailsClosedOnCorruptHistoryButKeepsEvidence(t *testing.T) {
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
	configPath := writeHistoryConfig(t, dir, artifactsDir)

	current := cliEvidence("obs_cur", "2026-07-11T12:00:00Z")
	defer stubScan(current, dir)()

	var stdout, stderr bytes.Buffer
	err = run(context.Background(), []string{"scan", "--config", configPath, "--json", "./target"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "corrupt history") {
		t.Fatalf("expected corrupt-history failure, err = %v", err)
	}
	// Valid current evidence must still have been emitted to stdout.
	if !strings.Contains(stdout.String(), observatory.EvidenceSchemaVersion) || !strings.Contains(stdout.String(), "obs_cur") {
		t.Fatalf("valid current evidence was suppressed: %s", stdout.String())
	}
	// The prior snapshot must be preserved, not cleaned up.
	if got := countSnapshotFiles(t, artifactsDir); got != 1 {
		t.Fatalf("prior snapshot not preserved: %d snapshot files", got)
	}
}

func TestScanRecordsHistoryAndEmitsVersionDelta(t *testing.T) {
	dir := t.TempDir()
	artifactsDir := filepath.Join(dir, "artifacts")
	store, err := observatory.OpenHistoryStore(artifactsDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(cliEvidence("obs_prev", "2026-07-10T12:00:00Z"), 10); err != nil {
		t.Fatal(err)
	}
	configPath := writeHistoryConfig(t, dir, artifactsDir)

	current := cliEvidence("obs_cur", "2026-07-11T12:00:00Z")
	current.Target.SHA256 = "sha256:" + strings.Repeat("f", 64)
	current.Observations = append(current.Observations, observatory.Observation{
		Kind: "network", Operation: "connect", Subject: "93.184.216.34:443", Outcome: "succeeded", Role: "external", ExerciseCount: 1, DeltaCount: 1,
	})
	defer stubScan(current, dir)()

	deltaPath := filepath.Join(dir, "delta.json")
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"scan", "--config", configPath, "--json", "--delta", deltaPath, "./target"}, &stdout, &stderr); err != nil {
		t.Fatalf("scan: %v (stderr=%s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "obs_cur") {
		t.Fatalf("evidence missing from stdout: %s", stdout.String())
	}
	data, err := os.ReadFile(deltaPath)
	if err != nil {
		t.Fatal(err)
	}
	var delta observatory.VersionDelta
	if err := json.Unmarshal(data, &delta); err != nil {
		t.Fatal(err)
	}
	if delta.SchemaVersion != observatory.VersionDeltaSchemaVersion || delta.Previous.RunID != "obs_prev" || len(delta.Changes) != 1 {
		t.Fatalf("delta = %#v", delta)
	}
	// The current run is now recorded and the prior snapshot is preserved.
	if got := countSnapshotFiles(t, artifactsDir); got != 2 {
		t.Fatalf("snapshots after scan = %d", got)
	}
}

func TestScanRejectsDeltaWithNoHistory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"scan", "--no-history", "--delta", "delta.json", "./target"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--delta cannot be combined with --no-history") {
		t.Fatalf("err = %v", err)
	}
}

func writeMatrixConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "observatory.yml")
	config := `version: 1
live: false
artifactsDir: ` + filepath.Join(dir, "runs") + `
executor:
  kind: crabbox
  command: crabbox
  crabboxConfig: ` + filepath.Join(dir, "crabbox.yml") + `
runtime:
  model:
    baseUrl: http://10.0.0.2:8000/v1
    id: base-model
  controlPlaneAddresses: [10.0.0.2:8000]
matrix:
  variants:
    - id: model-a
      model:
        id: model-a
    - id: model-b
      model:
        id: model-b
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func matrixCommandTarget() string {
	return filepath.Join("..", "..", "testdata", "fixtures", "probe-skill")
}

func TestMatrixCommandDryRunShowsMultiplier(t *testing.T) {
	configPath := writeMatrixConfig(t)
	output := filepath.Join(t.TempDir(), "must-not-exist")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	err := run(context.Background(), []string{"matrix", "--config", configPath, "--dry-run", "--output", output, matrixCommandTarget()}, stdout, stderr)
	if err != nil {
		t.Fatalf("dry run err = %v (stderr=%s)", err, stderr.String())
	}
	for _, expected := range []string{`"schema": "observatory.matrix-plan.v1"`, `"resourceMultiplier": 2`, `"execution": "sequential"`} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout missing %q:\n%s", expected, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "10.0.0.2") {
		t.Fatalf("dry run leaked a raw endpoint:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "matrix plan") || !strings.Contains(stderr.String(), "2x") {
		t.Fatalf("stderr missing plan summary:\n%s", stderr.String())
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("dry run touched output path: %v", err)
	}
}

func TestMatrixCommandRejectsUndocumentedTimeoutAxis(t *testing.T) {
	configPath := writeMatrixConfig(t)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	modified := strings.Replace(string(data), "    - id: model-a\n      model:", "    - id: model-a\n      timeoutSeconds: 30\n      model:", 1)
	if err := os.WriteFile(configPath, []byte(modified), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	err = run(context.Background(), []string{"matrix", "--config", configPath, "--dry-run", matrixCommandTarget()}, stdout, stderr)
	if err == nil || !strings.Contains(err.Error(), "timeoutSeconds") || !strings.Contains(err.Error(), "field") {
		t.Fatalf("err = %v", err)
	}
}

func TestHelpMentionsGrade(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "observatory grade") {
		t.Fatalf("help missing grade command:\n%s", stdout.String())
	}
}

func TestPairedArtifactCollisionPreservesExistingEvidence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secure standalone grade artifacts require Linux")
	}
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	gradePath := filepath.Join(dir, "grade.json")
	if err := os.WriteFile(evidencePath, []byte("old evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gradePath, []byte("old grade"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence := validEvidenceForTest()
	grade := observatory.GradeEvidence(evidence)
	if err := writeArtifactFiles(evidencePath, evidence, gradePath, grade); err == nil {
		t.Fatal("existing grade destination was accepted")
	}
	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old evidence" {
		t.Fatalf("evidence changed before grade collision: %q", data)
	}
}

func TestPairedArtifactPathsMustDiffer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secure standalone grade artifacts require Linux")
	}
	path := filepath.Join(t.TempDir(), "artifact.json")
	evidence := validEvidenceForTest()
	grade := observatory.GradeEvidence(evidence)
	if err := writeArtifactFiles(path, evidence, path, grade); err == nil {
		t.Fatal("identical evidence and grade paths were accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("identical artifact path was created: %v", err)
	}
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

func TestMatrixCommandRequiresVariants(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "observatory.yml")
	config := `version: 1
live: false
artifactsDir: ` + filepath.Join(dir, "runs") + `
executor:
  kind: crabbox
  command: crabbox
  crabboxConfig: ` + filepath.Join(dir, "crabbox.yml") + `
runtime:
  model:
    baseUrl: http://10.0.0.2:8000/v1
    id: base-model
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := run(context.Background(), []string{"matrix", "--config", configPath, "--dry-run", "./target"}, stdout, stderr); err == nil || !strings.Contains(err.Error(), "no matrix.variants") {
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

func TestMatrixCommandUsage(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := run(context.Background(), []string{"matrix"}, stdout, stderr); err == nil || !strings.Contains(err.Error(), "usage: observatory matrix") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunStageCreatesBoundedTargetAndMetadata(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("---\nname: staged-test\n---\n# Safe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(root, "staged")
	metadata := filepath.Join(root, "metadata.json")
	var stdout bytes.Buffer
	if err := runStage([]string{"--output", staged, "--metadata", metadata, target}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(staged, "SKILL.md")); err != nil {
		t.Fatalf("staged target missing: %v", err)
	}
	var evidence struct {
		Kind   string `json:"kind"`
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
	}
	data, err := os.ReadFile(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Kind != "skill" || evidence.ID != "staged-test" || evidence.SHA256 == "" {
		t.Fatalf("metadata = %#v", evidence)
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not JSON: %s", stdout.Bytes())
	}
}

func TestRunStageRequiresNewMetadataFile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("---\nname: staged-test\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(root, "metadata.json")
	if err := os.WriteFile(metadata, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runStage([]string{"--output", filepath.Join(root, "staged"), "--metadata", metadata, target}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected existing metadata to fail closed")
	}
	data, readErr := os.ReadFile(metadata)
	if readErr != nil || string(data) != "keep" {
		t.Fatalf("existing metadata changed: %q, %v", data, readErr)
	}
}
