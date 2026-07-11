//go:build linux

package observatory

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInspectTargetRejectsSpecialEntryThroughPathDescriptor(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("---\nname: fifo-probe\n---\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "device-like-entry"), 0600); err != nil {
		t.Fatal(err)
	}
	limits := LimitsConfig{MaxFiles: 10, MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxBundleBytes: 1 << 20}
	if _, err := InspectTarget(root, limits); err == nil || !strings.Contains(err.Error(), "unsupported non-regular") {
		t.Fatalf("special target entry was accepted: %v", err)
	}
}

func TestWalkTargetTreeStopsAtEntryBudget(t *testing.T) {
	root := t.TempDir()
	for index := 0; index < 256; index++ {
		name := filepath.Join(root, fmt.Sprintf("entry-%03d", index))
		if err := os.WriteFile(name, []byte("probe"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	visited := 0
	err := walkTargetTree(root, 2, func(_ string, _ fs.FileInfo, _ *os.File) (bool, error) {
		visited++
		return true, nil
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds maxFiles entries (2)") {
		t.Fatalf("entry budget was not enforced: %v", err)
	}
	if visited != 2 {
		t.Fatalf("walker visited %d entries past a budget of 2", visited)
	}
}

func TestInspectTargetRejectsNonUTF8Path(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("---\nname: utf8-probe\n---\n"), 0600); err != nil {
		t.Fatal(err)
	}
	invalidName := string([]byte{'b', 'a', 'd', '-', 0xff})
	if err := os.Mkdir(filepath.Join(root, invalidName), 0700); err != nil {
		t.Fatal(err)
	}
	limits := LimitsConfig{MaxFiles: 10, MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxBundleBytes: 1 << 20}
	if _, err := InspectTarget(root, limits); err == nil || !strings.Contains(err.Error(), "non-UTF-8 path") {
		t.Fatalf("non-UTF-8 target path was accepted: %v", err)
	}
}
