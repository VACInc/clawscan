package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
