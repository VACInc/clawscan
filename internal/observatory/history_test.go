package observatory

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func historyFixture(runID string, completedAt string) Evidence {
	evidence := fixtureEvidence()
	evidence.Run.ID = runID
	evidence.Run.CompletedAt = completedAt
	return evidence
}

func TestHistoryRecordsAndSelectsLatestComparable(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	previous := historyFixture("obs_prev", "2026-07-10T12:00:00Z")
	if err := store.Record(previous, 10); err != nil {
		t.Fatal(err)
	}
	current := historyFixture("obs_cur", "2026-07-11T12:00:00Z")
	current.Target.SHA256 = "sha256:" + strings.Repeat("f", 64)
	current.Observations = append(current.Observations, Observation{
		Kind: "network", Operation: "connect", Subject: "93.184.216.34:443", Outcome: "succeeded", Role: "external", ExerciseCount: 1, DeltaCount: 1,
	})
	selected, err := store.LatestComparable(current)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil || selected.Run.ID != "obs_prev" {
		t.Fatalf("selected = %#v", selected)
	}
	delta, err := ComputeVersionDelta(*selected, current)
	if err != nil {
		t.Fatal(err)
	}
	if delta.SchemaVersion != VersionDeltaSchemaVersion || delta.Identity != "skill:example/fixture-skill" || delta.TargetKind != "skill" {
		t.Fatalf("delta = %#v", delta)
	}
	if delta.Previous.RunID != "obs_prev" || delta.Current.RunID != "obs_cur" {
		t.Fatalf("delta endpoints = %#v / %#v", delta.Previous, delta.Current)
	}
	if len(delta.Changes) != 1 || delta.Changes[0].Change != "added" || delta.Changes[0].Subject != "93.184.216.34:443" {
		t.Fatalf("changes = %#v", delta.Changes)
	}
	// The v1 schema carries no grade, so the reserved grade seam stays nil while
	// the evidence-based changes remain the signal.
	if delta.Grade != nil {
		t.Fatalf("grade = %#v", delta.Grade)
	}
}

func TestHistoryExcludesCurrentRunAsPredecessor(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	current := historyFixture("obs_only", "2026-07-10T12:00:00Z")
	if err := store.Record(current, 10); err != nil {
		t.Fatal(err)
	}
	selected, err := store.LatestComparable(current)
	if err != nil {
		t.Fatal(err)
	}
	if selected != nil {
		t.Fatalf("current run was selected as its own predecessor: %#v", selected)
	}
}

func TestHistorySkipsIncomparablePredecessorAndKeepsSearching(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	comparable := historyFixture("obs_old", "2026-07-08T12:00:00Z")
	// A newer capture whose protocol/config differs must be skipped, not treated
	// as the delta baseline.
	incomparable := historyFixture("obs_mid", "2026-07-09T12:00:00Z")
	incomparable.CaptureConfigSHA256 = "sha256:" + strings.Repeat("9", 64)
	if err := store.Record(comparable, 10); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(incomparable, 10); err != nil {
		t.Fatal(err)
	}
	current := historyFixture("obs_cur", "2026-07-10T12:00:00Z")
	selected, err := store.LatestComparable(current)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil || selected.Run.ID != "obs_old" {
		t.Fatalf("selected = %#v", selected)
	}
}

func TestHistoryFailsClosedOnCorruptIndex(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenHistoryStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(historyFixture("obs_prev", "2026-07-10T12:00:00Z"), 10); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "history", "index.json"), []byte("{ not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	current := historyFixture("obs_cur", "2026-07-11T12:00:00Z")
	if _, err := store.LatestComparable(current); err == nil || !strings.Contains(err.Error(), "corrupt history") {
		t.Fatalf("err = %v", err)
	}
}

func TestHistoryFailsClosedOnCorruptSnapshot(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenHistoryStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(historyFixture("obs_prev", "2026-07-10T12:00:00Z"), 10); err != nil {
		t.Fatal(err)
	}
	index, err := store.loadIndex()
	if err != nil || len(index.Entries) != 1 {
		t.Fatalf("index = %#v err = %v", index, err)
	}
	snapshot := filepath.Join(dir, "history", index.Entries[0].SnapshotPath)
	if err := os.WriteFile(snapshot, []byte("{ truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	current := historyFixture("obs_cur", "2026-07-11T12:00:00Z")
	if _, err := store.LatestComparable(current); err == nil || !strings.Contains(err.Error(), "corrupt history") {
		t.Fatalf("err = %v", err)
	}
}

func TestHistoryFailsClosedAtBoundWithoutDeleting(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenHistoryStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := historyFixture("obs_a", "2026-07-10T12:00:00Z")
	second := historyFixture("obs_b", "2026-07-11T12:00:00Z")
	if err := store.Record(first, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(second, 2); err != nil {
		t.Fatal(err)
	}
	third := historyFixture("obs_c", "2026-07-12T12:00:00Z")
	if err := store.Record(third, 2); err == nil || !strings.Contains(err.Error(), "maxPerIdentity") {
		t.Fatalf("expected bound failure, err = %v", err)
	}
	// The bound must fail closed without dropping either prior entry or snapshot.
	index, err := store.loadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Entries) != 2 {
		t.Fatalf("entries = %d", len(index.Entries))
	}
	kept := map[string]bool{}
	for _, entry := range index.Entries {
		kept[entry.RunID] = true
	}
	if !kept["obs_a"] || !kept["obs_b"] {
		t.Fatalf("bound dropped an existing entry: %#v", index.Entries)
	}
	snapshotDir := store.snapshotDir("skill:example/fixture-skill")
	files, err := os.ReadDir(snapshotDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("snapshot files = %d", len(files))
	}
}

func TestHistoryRecordIsIdempotentAndRejectsConflict(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	original := historyFixture("obs_dup", "2026-07-10T12:00:00Z")
	if err := store.Record(original, 10); err != nil {
		t.Fatal(err)
	}
	// A byte-identical re-record of the same run is an idempotent no-op.
	if err := store.Record(original, 10); err != nil {
		t.Fatalf("identical re-record failed: %v", err)
	}
	index, err := store.loadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Entries) != 1 {
		t.Fatalf("entries = %d", len(index.Entries))
	}
	snapshot := filepath.Join(store.root, index.Entries[0].SnapshotPath)
	before, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// A conflicting payload for the same run id must error and preserve the
	// existing snapshot untouched.
	conflict := original
	conflict.Target.SHA256 = "sha256:" + strings.Repeat("9", 64)
	if err := store.Record(conflict, 10); err == nil || !strings.Contains(err.Error(), "conflicting record") {
		t.Fatalf("expected conflict rejection, err = %v", err)
	}
	after, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("preserved snapshot was modified")
	}
}

func TestHistoryDoesNotRecordIncompleteCapture(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	evidence := historyFixture("obs_incomplete", "2026-07-10T12:00:00Z")
	evidence.Run.Status = "incomplete"
	evidence.Run.LaneExitCode.Exercise = 124
	if err := store.Record(evidence, 10); !errors.Is(err, ErrHistoryIncompleteCapture) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "index.json")); !os.IsNotExist(err) {
		t.Fatalf("incomplete capture wrote an index: %v", err)
	}
}

func TestHistorySkipsSkillWithoutStableLineage(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	evidence := historyFixture("obs_nolineage", "2026-07-10T12:00:00Z")
	evidence.Target.Lineage = ""
	if err := store.Record(evidence, 10); !errors.Is(err, ErrHistoryNoStableIdentity) {
		t.Fatalf("record err = %v", err)
	}
	current := historyFixture("obs_cur", "2026-07-11T12:00:00Z")
	current.Target.Lineage = ""
	selected, err := store.LatestComparable(current)
	if err != nil || selected != nil {
		t.Fatalf("selected = %#v err = %v", selected, err)
	}
}

func TestComputeVersionDeltaFailsClosedOnRuntimeDrift(t *testing.T) {
	previous := historyFixture("obs_prev", "2026-07-10T12:00:00Z")
	current := historyFixture("obs_cur", "2026-07-11T12:00:00Z")
	current.Run.Runtime.OpenClawVersion = "OpenClaw other"
	if _, err := ComputeVersionDelta(previous, current); err == nil || !strings.Contains(err.Error(), "identical, recorded runtime") {
		t.Fatalf("err = %v", err)
	}
}

func TestHistorySelectsNewestBySubSecondPrecision(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	older := historyFixture("obs_a", "2026-07-10T12:00:00Z")
	newer := historyFixture("obs_b", "2026-07-10T12:00:00.5Z")
	if err := store.Record(older, 10); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(newer, 10); err != nil {
		t.Fatal(err)
	}
	current := historyFixture("obs_cur", "2026-07-10T12:00:01Z")
	selected, err := store.LatestComparable(current)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil || selected.Run.ID != "obs_b" {
		t.Fatalf("selected = %#v", selected)
	}
}

func TestHistoryIsolatesSkillAndPluginIdentities(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	skill := historyFixture("obs_skill", "2026-07-10T12:00:00Z")
	plugin := historyFixture("obs_plugin", "2026-07-10T12:00:00Z")
	plugin.Target.Kind = "plugin"
	plugin.Target.ID = "observatory-probe"
	plugin.Target.Lineage = ""
	if err := store.Record(skill, 10); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(plugin, 10); err != nil {
		t.Fatal(err)
	}
	currentSkill := historyFixture("obs_skill2", "2026-07-11T12:00:00Z")
	selected, err := store.LatestComparable(currentSkill)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil || selected.Run.ID != "obs_skill" {
		t.Fatalf("skill selected = %#v", selected)
	}
	currentPlugin := historyFixture("obs_plugin2", "2026-07-11T12:00:00Z")
	currentPlugin.Target.Kind = "plugin"
	currentPlugin.Target.ID = "observatory-probe"
	currentPlugin.Target.Lineage = ""
	selectedPlugin, err := store.LatestComparable(currentPlugin)
	if err != nil {
		t.Fatal(err)
	}
	if selectedPlugin == nil || selectedPlugin.Run.ID != "obs_plugin" {
		t.Fatalf("plugin selected = %#v", selectedPlugin)
	}
}

func TestHistoryRejectsSnapshotPathEscape(t *testing.T) {
	store, err := OpenHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.resolve("../escape.json"); err == nil || !strings.Contains(err.Error(), "escapes the store") {
		t.Fatalf("err = %v", err)
	}
}
