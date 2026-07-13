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
	return observatory.Evidence{
		SchemaVersion:       observatory.EvidenceSchemaVersion,
		CaptureConfigSHA256: "sha256:" + strings.Repeat("d", 64),
		Target: observatory.TargetEvidence{
			Name: "cli-fixture", Kind: "skill", ID: "cli-fixture", SHA256: "sha256:" + strings.Repeat("a", 64),
			FileCount: 1, DirectoryCount: 1, TotalBytes: 10,
			Files:       []observatory.TargetFile{{Path: "SKILL.md", Bytes: 10, Mode: "0644"}},
			Directories: []observatory.TargetDirectory{{Path: ".", Mode: "0755"}},
		},
		Run: observatory.RunEvidence{
			ID: "obs_cli", Status: "completed", StartedAt: "2026-07-10T11:59:59Z", CompletedAt: "2026-07-10T12:00:00Z", Executor: "fixture",
			Isolation: observatory.IsolationEvidence{Substrate: "proxmox-vm", NetworkMode: "deny-except-model", ContainmentProfile: "fixture", GuestFirewallSHA256: "sha256:" + strings.Repeat("b", 64), GuestFirewallPolicySHA256: "sha256:" + strings.Repeat("e", 64), Verification: "fixture"},
			Runtime:   observatory.RuntimeEvidence{OpenClawVersion: "OpenClaw fixture", StraceVersion: "strace fixture", ModelProvider: "local", ModelID: "fixture", ModelEndpoint: "private"},
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

func writeEvidenceFile(t *testing.T, evidence observatory.Evidence) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.json")
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGradeCommandEmitsDerivedGradeJSON(t *testing.T) {
	path := writeEvidenceFile(t, validEvidenceForTest())
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
	path := writeEvidenceFile(t, evidence)
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
