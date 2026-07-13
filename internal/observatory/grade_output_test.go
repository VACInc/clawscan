//go:build linux

package observatory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteGradeFileSecureCreateOnly(t *testing.T) {
	grade := GradeEvidence(gradableEvidence())
	t.Run("success", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nested", "grade.json")
		if err := WriteGradeFile(path, grade); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
			t.Fatalf("grade output mode/type = %v", info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var persisted Grade
		if err := json.Unmarshal(data, &persisted); err != nil {
			t.Fatal(err)
		}
		if err := ValidateGrade(persisted); err != nil {
			t.Fatalf("persisted grade invalid: %v", err)
		}
	})

	t.Run("named fallback publishes atomically", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "owner-only")
		path := filepath.Join(dir, "grade.json")
		if err := writeGradeFile(path, grade, false); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != "grade.json" {
			t.Fatalf("named fallback left staging artifacts: %#v", entries)
		}
		info, err := entries[0].Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("fallback output mode = %v", info.Mode())
		}
	})

	t.Run("existing regular is unchanged", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "grade.json")
		if err := os.WriteFile(path, []byte("sentinel"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := WriteGradeFile(path, grade); err == nil {
			t.Fatal("existing output was clobbered")
		}
		data, _ := os.ReadFile(path)
		if string(data) != "sentinel" {
			t.Fatalf("existing output changed: %q", data)
		}
	})

	t.Run("final symlink is refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		path := filepath.Join(dir, "grade.json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := WriteGradeFile(path, grade); err == nil {
			t.Fatal("final symlink was followed")
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("symlink target was unexpectedly created: %v", err)
		}
	})

	t.Run("symlink ancestor is refused", func(t *testing.T) {
		dir := t.TempDir()
		realDir := filepath.Join(dir, "real")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(dir, "link")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}
		if err := WriteGradeFile(filepath.Join(linkDir, "grade.json"), grade); err == nil || !strings.Contains(err.Error(), "unsafe component") {
			t.Fatalf("symlink ancestor err = %v", err)
		}
		if _, err := os.Stat(filepath.Join(realDir, "grade.json")); !os.IsNotExist(err) {
			t.Fatalf("symlinked ancestor received output: %v", err)
		}
	})

	t.Run("hardlink path is refused", func(t *testing.T) {
		dir := t.TempDir()
		source := filepath.Join(dir, "source")
		path := filepath.Join(dir, "grade.json")
		if err := os.WriteFile(source, []byte("sentinel"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(source, path); err != nil {
			t.Fatal(err)
		}
		if err := WriteGradeFile(path, grade); err == nil {
			t.Fatal("hardlink output was accepted")
		}
		data, _ := os.ReadFile(source)
		if string(data) != "sentinel" {
			t.Fatalf("hardlink source changed: %q", data)
		}
	})
}

func TestCheckGradeOutputAvailableUsesSecureDestinationWalk(t *testing.T) {
	dir := t.TempDir()
	available := filepath.Join(dir, "nested", "grade.json")
	if err := CheckGradeOutputAvailable(available); err != nil {
		t.Fatalf("available destination rejected: %v", err)
	}
	if err := os.WriteFile(available, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckGradeOutputAvailable(available); err == nil {
		t.Fatal("existing destination passed preflight")
	}

	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := CheckGradeOutputAvailable(filepath.Join(linkDir, "grade.json")); err == nil {
		t.Fatal("symlinked ancestor passed preflight")
	}
}
