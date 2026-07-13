//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openclaw/clawscan/internal/observatory"
)

func matrixOutputFixture() observatory.MatrixResult {
	evidence := observatory.Evidence{SchemaVersion: "fixture-evidence"}
	return observatory.MatrixResult{
		Comparison: observatory.MatrixComparison{Schema: observatory.MatrixComparisonSchema},
		Runs: []observatory.MatrixRun{
			{ID: "model-a", Evidence: &evidence},
			{ID: "model-b", Evidence: &evidence},
		},
	}
}

func TestWriteMatrixOutputPublishesOwnerOnlyCompleteDirectory(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "matrix")
	if err := writeMatrixOutput(output, matrixOutputFixture()); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Lstat(output)
	if err != nil {
		t.Fatal(err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm() != matrixOutputDirectoryMode {
		t.Fatalf("output directory mode = %s", dirInfo.Mode())
	}
	wantFiles := []string{"comparison.json", "variant-model-a.json", "variant-model-b.json"}
	for _, name := range wantFiles {
		path := filepath.Join(output, name)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != matrixOutputFileMode {
			t.Fatalf("%s mode = %s", name, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var decoded any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("%s is not JSON: %v", name, err)
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), matrixOutputTempPrefix) {
			t.Fatalf("successful publication left staging directory %q", entry.Name())
		}
	}
}

func TestWriteMatrixOutputRejectsSymlinkAncestor(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(base, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if err := writeMatrixOutput(filepath.Join(linkedParent, "matrix"), matrixOutputFixture()); err == nil || !strings.Contains(err.Error(), "unsafe ancestor") {
		t.Fatalf("err = %v", err)
	}
	entries, err := os.ReadDir(realParent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink target received output: %#v", entries)
	}
}

func TestWriteMatrixOutputRejectsExistingSymlinkAndHardlink(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		base := t.TempDir()
		outside := filepath.Join(base, "outside")
		want := []byte("outside must remain unchanged\n")
		if err := os.WriteFile(outside, want, 0o600); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(base, "matrix")
		if err := os.Symlink(outside, output); err != nil {
			t.Fatal(err)
		}
		if err := writeMatrixOutput(output, matrixOutputFixture()); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("err = %v", err)
		}
		got, err := os.ReadFile(outside)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("symlink target changed: %q", got)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		base := t.TempDir()
		outside := filepath.Join(base, "outside")
		want := []byte("hardlink target must remain unchanged\n")
		if err := os.WriteFile(outside, want, 0o600); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(base, "matrix")
		if err := os.Link(outside, output); err != nil {
			t.Fatal(err)
		}
		if err := writeMatrixOutput(output, matrixOutputFixture()); err == nil || !strings.Contains(err.Error(), "hard-linked") {
			t.Fatalf("err = %v", err)
		}
		got, err := os.ReadFile(outside)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("hardlink target changed: %q", got)
		}
	})
}

func TestWriteMatrixOutputNeverClobbersExistingDirectory(t *testing.T) {
	output := filepath.Join(t.TempDir(), "matrix")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "sentinel")
	want := []byte("preserve me\n")
	if err := os.WriteFile(sentinel, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeMatrixOutput(output, matrixOutputFixture()); err == nil || !strings.Contains(err.Error(), "refusing to clobber") {
		t.Fatalf("err = %v", err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("existing output changed: %q", got)
	}
}

func TestWriteMatrixOutputConcurrentPublishHasSingleWinner(t *testing.T) {
	output := filepath.Join(t.TempDir(), "matrix")
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- writeMatrixOutput(output, matrixOutputFixture())
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	successes := 0
	failures := 0
	for err := range errs {
		if err == nil {
			successes++
		} else if strings.Contains(err.Error(), "refusing to clobber") || strings.Contains(err.Error(), "already exists") {
			failures++
		} else {
			t.Fatalf("unexpected publish error: %v", err)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("successes=%d failures=%d", successes, failures)
	}
	for _, name := range []string{"comparison.json", "variant-model-a.json", "variant-model-b.json"} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Fatalf("winning output is incomplete: %s: %v", name, err)
		}
	}
}

func TestWriteMatrixOutputRejectsUnsafeVariantFilenameBeforeWriting(t *testing.T) {
	result := matrixOutputFixture()
	result.Runs[0].ID = "../escape"
	output := filepath.Join(t.TempDir(), "matrix")
	if err := writeMatrixOutput(output, result); err == nil || !strings.Contains(err.Error(), "variant id is unsafe") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("unsafe variant created output: %v", err)
	}
}
