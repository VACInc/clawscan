//go:build linux

package observatory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHistoryRejectsSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	artifacts := filepath.Join(base, "artifacts")
	if err := os.Mkdir(artifacts, historyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "redirected-history")
	if err := os.Mkdir(target, historyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(artifacts, "history")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHistoryStore(artifacts); err == nil || !strings.Contains(err.Error(), "unsafe history root") {
		t.Fatalf("err = %v", err)
	}
}

func TestHistoryRejectsSymlinkAncestor(t *testing.T) {
	base := t.TempDir()
	realArtifacts := filepath.Join(base, "real-artifacts")
	if err := os.Mkdir(realArtifacts, historyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	linkedArtifacts := filepath.Join(base, "linked-artifacts")
	if err := os.Symlink(realArtifacts, linkedArtifacts); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHistoryStore(linkedArtifacts); err == nil || !strings.Contains(err.Error(), "without following links") {
		t.Fatalf("err = %v", err)
	}
	entries, err := os.ReadDir(realArtifacts)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlinked artifact directory received history data: %#v", entries)
	}
}

func TestHistoryRejectsUnsafeRootModeAndOwnership(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.root, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecureHistoryRoot(store.root); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("unsafe mode err = %v", err)
	}

	if err := os.Chmod(store.root, historyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	root, err := openSecureHistoryRoot(store.root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	if err := validateHistoryDescriptor(int(root.dir.Fd()), root.uid+1, unix.S_IFDIR, historyDirectoryMode, "history root"); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("non-owner err = %v", err)
	}
}

func TestHistoryRejectsSymlinkIndexWithoutTouchingTarget(t *testing.T) {
	base := t.TempDir()
	store, err := OpenHistoryStore(filepath.Join(base, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.json")
	want := []byte("outside must remain unchanged\n")
	if err := os.WriteFile(outside, want, historyFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, store.indexPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.loadIndex(); err == nil || !strings.Contains(err.Error(), "without following links") {
		t.Fatalf("err = %v", err)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestHistoryRejectsSymlinkSnapshotAndDirectory(t *testing.T) {
	t.Run("snapshot file", func(t *testing.T) {
		store, err := OpenHistoryStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Record(historyFixture("obs_symlink", "2026-07-10T12:00:00Z"), 10); err != nil {
			t.Fatal(err)
		}
		index, err := store.loadIndex()
		if err != nil {
			t.Fatal(err)
		}
		snapshot := filepath.Join(store.root, index.Entries[0].SnapshotPath)
		preserved := snapshot + ".preserved"
		if err := os.Rename(snapshot, preserved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(preserved, snapshot); err != nil {
			t.Fatal(err)
		}
		if _, err := store.loadIndex(); err == nil || !strings.Contains(err.Error(), "without following links") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("snapshot directory", func(t *testing.T) {
		base := t.TempDir()
		store, err := OpenHistoryStore(filepath.Join(base, "artifacts"))
		if err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(base, "outside")
		if err := os.Mkdir(outside, historyDirectoryMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(store.root, "snapshots")); err != nil {
			t.Fatal(err)
		}
		if err := store.Record(historyFixture("obs_dir_symlink", "2026-07-10T12:00:00Z"), 10); err == nil || !strings.Contains(err.Error(), "without following links") {
			t.Fatalf("err = %v", err)
		}
		entries, err := os.ReadDir(outside)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("redirected directory received history data: %#v", entries)
		}
	})
}

func TestHistoryRejectsUnsafeIndexSnapshotAndDirectoryModes(t *testing.T) {
	tests := []struct {
		name string
		path func(*HistoryStore, historyIndex) string
		mode os.FileMode
	}{
		{name: "index", path: func(store *HistoryStore, _ historyIndex) string { return store.indexPath() }, mode: 0o640},
		{name: "snapshot", path: func(store *HistoryStore, index historyIndex) string {
			return filepath.Join(store.root, index.Entries[0].SnapshotPath)
		}, mode: 0o640},
		{name: "snapshot directory", path: func(store *HistoryStore, index historyIndex) string {
			return filepath.Dir(filepath.Join(store.root, index.Entries[0].SnapshotPath))
		}, mode: 0o750},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := OpenHistoryStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Record(historyFixture("obs_mode", "2026-07-10T12:00:00Z"), 10); err != nil {
				t.Fatal(err)
			}
			index, err := store.loadIndex()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(test.path(store, index), test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := store.loadIndex(); err == nil || !strings.Contains(err.Error(), "mode") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestHistoryRejectsUnsafeTemporaryIndexWithoutTouchingTarget(t *testing.T) {
	base := t.TempDir()
	store, err := OpenHistoryStore(filepath.Join(base, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(historyFixture("obs_a", "2026-07-10T12:00:00Z"), 10); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.tmp")
	want := []byte("do not truncate\n")
	if err := os.WriteFile(outside, want, historyFileMode); err != nil {
		t.Fatal(err)
	}
	tempName := historyIndexTemporaryPrefix + "adversarial"
	if err := os.Symlink(outside, filepath.Join(store.root, tempName)); err != nil {
		t.Fatal(err)
	}
	root, err := openSecureHistoryRoot(store.root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	payload, err := os.ReadFile(store.indexPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := root.writeIndexAtomicNamed(payload, tempName); err == nil || !strings.Contains(err.Error(), "temporary history index") {
		t.Fatalf("err = %v", err)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("temporary symlink target changed: %q", got)
	}
}

func TestHistoryStaleTemporaryIndexDoesNotBlockLaterWrite(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(historyFixture("obs_a", "2026-07-10T12:00:00Z"), 10); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(store.root, historyIndexTemporaryPrefix+"stale")
	if err := os.WriteFile(stale, []byte("incomplete stale index\n"), historyFileMode); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(historyFixture("obs_b", "2026-07-11T12:00:00Z"), 10); err != nil {
		t.Fatal(err)
	}
	index, err := store.loadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Entries) != 2 {
		t.Fatalf("entries = %d", len(index.Entries))
	}
	if info, err := os.Lstat(stale); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("stale temp was unexpectedly changed: info=%v err=%v", info, err)
	}
}

func TestHistoryAdoptsIdenticalOrphanSnapshotOnRetry(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	evidence := historyFixture("obs_orphan", "2026-07-10T12:00:00Z")
	identity, ok := stableIdentity(evidence)
	if !ok {
		t.Fatal("fixture has no stable identity")
	}
	rel := store.snapshotRelativePath(identity, evidence)
	if err := os.MkdirAll(filepath.Dir(filepath.Join(store.root, rel)), historyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	payload, err := marshalEvidenceSnapshot(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.root, rel), payload, historyFileMode); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(evidence, 10); err != nil {
		t.Fatal(err)
	}
	index, err := store.loadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Entries) != 1 || index.Entries[0].RunID != evidence.Run.ID {
		t.Fatalf("index = %#v", index)
	}
}

func TestHistoryValidatesAllIndexMetadataAgainstSnapshots(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(historyFixture("obs_metadata", "2026-07-10T12:00:00Z"), 10); err != nil {
		t.Fatal(err)
	}
	index, err := store.loadIndex()
	if err != nil {
		t.Fatal(err)
	}
	index.Entries[0].TargetSHA256 = "sha256:" + strings.Repeat("9", 64)
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.indexPath(), data, historyFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.loadIndex(); err == nil || !strings.Contains(err.Error(), "does not exactly match") {
		t.Fatalf("err = %v", err)
	}
}

func TestHistorySerializesConcurrentWriters(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const writers = 24
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wait sync.WaitGroup
	for i := 0; i < writers; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			<-start
			evidence := historyFixture(fmt.Sprintf("obs_concurrent_%02d", i), fmt.Sprintf("2026-07-10T12:00:%02dZ", i))
			errs <- store.Record(evidence, writers)
		}(i)
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	index, err := store.loadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Entries) != writers {
		t.Fatalf("entries = %d, want %d", len(index.Entries), writers)
	}
}

func TestHistoryWriterLockWaitIsBounded(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := openSecureHistoryRoot(store.root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	release, err := root.acquireWriterLock(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	store.lockTimeout = 50 * time.Millisecond
	started := time.Now()
	err = store.Record(historyFixture("obs_locked", "2026-07-10T12:00:00Z"), 10)
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("lock wait was not bounded: %s", elapsed)
	}
}

func TestHistoryCreatesOwnerOnlyDurableLayout(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(historyFixture("obs_layout", "2026-07-10T12:00:00Z"), 10); err != nil {
		t.Fatal(err)
	}
	index, err := store.loadIndex()
	if err != nil {
		t.Fatal(err)
	}
	directories := []string{
		store.root,
		filepath.Join(store.root, "snapshots"),
		filepath.Dir(filepath.Join(store.root, index.Entries[0].SnapshotPath)),
	}
	for _, path := range directories {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != historyDirectoryMode {
			t.Fatalf("directory %s mode = %s", filepath.Base(path), info.Mode())
		}
	}
	files := []string{
		store.indexPath(),
		filepath.Join(store.root, ".writer.lock"),
		filepath.Join(store.root, index.Entries[0].SnapshotPath),
	}
	for _, path := range files {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != historyFileMode {
			t.Fatalf("file %s mode = %s", filepath.Base(path), info.Mode())
		}
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), historyIndexTemporaryPrefix) {
			t.Fatalf("temporary index remains after successful commit: %s", entry.Name())
		}
	}
}
