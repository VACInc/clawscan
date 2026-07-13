package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestMatrixCommandUsage(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := run(context.Background(), []string{"matrix"}, stdout, stderr); err == nil || !strings.Contains(err.Error(), "usage: observatory matrix") {
		t.Fatalf("err = %v", err)
	}
}
