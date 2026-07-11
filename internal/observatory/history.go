package observatory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// HistorySchemaVersion identifies the on-disk index layout for the local
// version-diff history store.
const HistorySchemaVersion = "observatory.history.v1"

// VersionDeltaSchemaVersion identifies the structured behavior delta document.
const VersionDeltaSchemaVersion = "observatory.version-delta.v1"

// MaxHistoryIndexBytes bounds the trusted local history index. It is generous
// but finite so a damaged or oversized index fails closed instead of being
// parsed unbounded.
const MaxHistoryIndexBytes = 16 << 20

// defaultHistoryMaxPerIdentity is the built-in bounded cap on recorded
// snapshots per stable identity. History is append-only, so reaching the cap
// fails a new record closed rather than deleting prior snapshots.
const defaultHistoryMaxPerIdentity = 1000

// maxHistoryMaxPerIdentity bounds the configurable cap.
const maxHistoryMaxPerIdentity = 100000

// ErrHistoryNoStableIdentity is returned when evidence has no stable
// lineage/plugin identity to index by. Such captures cannot participate in
// version diffs and are simply not recorded.
var ErrHistoryNoStableIdentity = errors.New("history: target has no stable lineage or plugin identity")

// ErrHistoryIncompleteCapture is returned when an incomplete capture is offered
// for recording. Only completed captures can be a valid predecessor.
var ErrHistoryIncompleteCapture = errors.New("history: incomplete capture is not recorded")

// HistoryStore is a private, append-oriented store of prior public evidence
// snapshots keyed by stable target identity. It lives under the operator's
// artifacts directory and never contains raw traces or transcripts.
type HistoryStore struct {
	root string
}

// HistoryEntry is the indexed metadata retained for one recorded capture. It is
// intentionally small; comparability is always re-verified against the full
// snapshot before a delta is produced.
type HistoryEntry struct {
	Identity            string `json:"identity"`
	Kind                string `json:"kind"`
	Lineage             string `json:"lineage,omitempty"`
	PluginID            string `json:"pluginId,omitempty"`
	RunID               string `json:"runId"`
	TargetSHA256        string `json:"targetSha256"`
	CaptureConfigSHA256 string `json:"captureConfigSha256"`
	CompletedAt         string `json:"completedAt"`
	RecordedAt          string `json:"recordedAt"`
	Status              string `json:"status"`
	SnapshotPath        string `json:"snapshotPath"`
}

type historyIndex struct {
	SchemaVersion string         `json:"schemaVersion"`
	Entries       []HistoryEntry `json:"entries"`
}

// VersionEndpoint identifies one side of a version delta without republishing
// the full evidence.
type VersionEndpoint struct {
	RunID        string `json:"runId"`
	CompletedAt  string `json:"completedAt"`
	TargetSHA256 string `json:"targetSha256"`
}

// GradeDelta is a reserved seam for a future external grade signal. The v1
// evidence schema carries no grade, so it is nil today. When a grade source is
// added it populates this field ALONGSIDE the evidence-based Changes; a grade
// change never replaces or suppresses the behavioral delta.
type GradeDelta struct {
	Previous string `json:"previous,omitempty"`
	Current  string `json:"current,omitempty"`
	Changed  bool   `json:"changed"`
}

// VersionDelta is the structured, evidence-based behavior delta between a
// strictly comparable predecessor and the current capture.
type VersionDelta struct {
	SchemaVersion string          `json:"schemaVersion"`
	Identity      string          `json:"identity"`
	TargetKind    string          `json:"targetKind"`
	Lineage       string          `json:"lineage,omitempty"`
	PluginID      string          `json:"pluginId,omitempty"`
	Previous      VersionEndpoint `json:"previous"`
	Current       VersionEndpoint `json:"current"`
	Changes       []VersionChange `json:"changes"`
	Grade         *GradeDelta     `json:"grade,omitempty"`
}

// OpenHistoryStore prepares the private history store beneath artifactsDir.
func OpenHistoryStore(artifactsDir string) (*HistoryStore, error) {
	trimmed := strings.TrimSpace(artifactsDir)
	if trimmed == "" {
		return nil, errors.New("history store requires an artifacts directory")
	}
	root := filepath.Join(trimmed, "history")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create history store: %w", err)
	}
	return &HistoryStore{root: root}, nil
}

func (store *HistoryStore) indexPath() string {
	return filepath.Join(store.root, "index.json")
}

// resolve maps a stored relative snapshot path to an absolute path, rejecting
// any entry that escapes the store. A corrupt or hostile index therefore
// cannot redirect reads outside the history tree.
func (store *HistoryStore) resolve(rel string) (string, error) {
	clean := filepath.Clean(rel)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("corrupt history: snapshot path %q escapes the store", rel)
	}
	return filepath.Join(store.root, clean), nil
}

func (store *HistoryStore) loadIndex() (historyIndex, error) {
	data, err := os.ReadFile(store.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return historyIndex{SchemaVersion: HistorySchemaVersion}, nil
	}
	if err != nil {
		return historyIndex{}, fmt.Errorf("read history index: %w", err)
	}
	if len(data) > MaxHistoryIndexBytes {
		return historyIndex{}, errors.New("corrupt history: index exceeds size bound")
	}
	var index historyIndex
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return historyIndex{}, fmt.Errorf("corrupt history: parse index: %w", err)
	}
	if index.SchemaVersion != HistorySchemaVersion {
		return historyIndex{}, fmt.Errorf("corrupt history: unsupported index schema %q", index.SchemaVersion)
	}
	return index, nil
}

func (store *HistoryStore) writeIndex(index historyIndex) error {
	index.SchemaVersion = HistorySchemaVersion
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp := store.indexPath() + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, store.indexPath()); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}

// Record appends completed evidence to the append-only history under a bounded
// per-identity cap. It never deletes or overwrites a prior snapshot: recording
// the same run id succeeds only when the preserved snapshot is valid and
// byte-identical, a conflicting payload for the same run id is an error, and
// reaching maxPerIdentity fails closed instead of pruning older entries. Per-run
// artifact directories and raw bundles are never touched.
func (store *HistoryStore) Record(evidence Evidence, maxPerIdentity int) error {
	if err := ValidateEvidence(evidence); err != nil {
		return err
	}
	identity, ok := stableIdentity(evidence)
	if !ok {
		return ErrHistoryNoStableIdentity
	}
	if evidence.Run.Status != "completed" {
		return ErrHistoryIncompleteCapture
	}
	if maxPerIdentity < 1 {
		maxPerIdentity = defaultHistoryMaxPerIdentity
	}
	index, err := store.loadIndex()
	if err != nil {
		return err
	}
	payload, err := marshalEvidenceSnapshot(evidence)
	if err != nil {
		return err
	}
	dir := store.snapshotDir(identity)
	name := historySortKey(evidence) + "-" + shortToken(evidence.Run.ID) + ".json"
	rel := filepath.Join("snapshots", filepath.Base(dir), name)

	count := 0
	for i := range index.Entries {
		if index.Entries[i].Identity != identity {
			continue
		}
		count++
		if index.Entries[i].RunID == evidence.Run.ID {
			// Re-recording a run is idempotent only when the preserved snapshot
			// is valid and byte-identical; conflicting reuse is rejected and the
			// existing snapshot is left untouched.
			return store.verifyIdenticalRecord(index.Entries[i], payload)
		}
	}
	if count >= maxPerIdentity {
		return fmt.Errorf("history: %s already has %d recorded snapshots at the maxPerIdentity bound of %d; history is append-only, so prune it manually before adding more", identity, count, maxPerIdentity)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeSnapshotNoClobber(filepath.Join(store.root, rel), payload); err != nil {
		return err
	}
	index.Entries = append(index.Entries, HistoryEntry{
		Identity:            identity,
		Kind:                evidence.Target.Kind,
		Lineage:             evidence.Target.Lineage,
		PluginID:            pluginIdentityID(evidence),
		RunID:               evidence.Run.ID,
		TargetSHA256:        evidence.Target.SHA256,
		CaptureConfigSHA256: evidence.CaptureConfigSHA256,
		CompletedAt:         evidence.Run.CompletedAt,
		RecordedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		Status:              evidence.Run.Status,
		SnapshotPath:        rel,
	})
	return store.writeIndex(index)
}

// verifyIdenticalRecord accepts a re-record of an existing run only when its
// preserved snapshot is valid and byte-identical to the new payload. It never
// modifies the stored snapshot.
func (store *HistoryStore) verifyIdenticalRecord(entry HistoryEntry, payload []byte) error {
	path, err := store.resolve(entry.SnapshotPath)
	if err != nil {
		return err
	}
	if _, err := loadHistorySnapshot(path); err != nil {
		return err
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("corrupt history: read snapshot %s: %w", filepath.Base(entry.SnapshotPath), err)
	}
	if !bytes.Equal(stored, payload) {
		return fmt.Errorf("history: conflicting record for run %q; the preserved snapshot differs and is not overwritten", entry.RunID)
	}
	return nil
}

// writeSnapshotNoClobber writes a new snapshot without clobbering an existing
// one. If the target already exists it must be byte-identical; a different
// existing snapshot is preserved and reported as an error. Only a newly created
// file that fails mid-write is removed.
func writeSnapshotNoClobber(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("corrupt history: read snapshot %s: %w", filepath.Base(path), readErr)
		}
		if !bytes.Equal(existing, payload) {
			return fmt.Errorf("history: refusing to overwrite existing snapshot %s with different content", filepath.Base(path))
		}
		return nil
	}
	if err != nil {
		return err
	}
	_, writeErr := file.Write(payload)
	closeErr := file.Close()
	if writeErr != nil {
		os.Remove(path) // clean up only this newly created, failed snapshot
		return writeErr
	}
	if closeErr != nil {
		os.Remove(path) // clean up only this newly created, failed snapshot
		return closeErr
	}
	return nil
}

func marshalEvidenceSnapshot(evidence Evidence) ([]byte, error) {
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// LatestComparable returns the most recent strictly comparable predecessor for
// current, excluding current's own run. It returns (nil, nil) when no
// comparable predecessor exists, and an error only when the history itself is
// corrupt. Legitimately incomparable predecessors (different capture protocol,
// isolation receipt, prompt, model, resource limits, or target identity) are
// skipped rather than treated as a delta.
func (store *HistoryStore) LatestComparable(current Evidence) (*Evidence, error) {
	if err := ValidateEvidence(current); err != nil {
		return nil, err
	}
	identity, ok := stableIdentity(current)
	if !ok {
		return nil, nil
	}
	index, err := store.loadIndex()
	if err != nil {
		return nil, err
	}
	candidates := []HistoryEntry{}
	for _, entry := range index.Entries {
		if entry.Identity == identity && entry.RunID != current.Run.ID {
			candidates = append(candidates, entry)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return historyEntryBefore(candidates[j], candidates[i]) // newest first
	})
	for _, entry := range candidates {
		path, err := store.resolve(entry.SnapshotPath)
		if err != nil {
			return nil, err
		}
		evidence, err := loadHistorySnapshot(path)
		if err != nil {
			return nil, err
		}
		snapshotIdentity, ok := stableIdentity(evidence)
		if !ok || snapshotIdentity != identity {
			return nil, fmt.Errorf("corrupt history: snapshot %s identity does not match its index entry", filepath.Base(entry.SnapshotPath))
		}
		if evidence.Run.ID == current.Run.ID {
			continue
		}
		if err := validateEvidenceComparison(evidence, current); err != nil {
			continue
		}
		result := evidence
		return &result, nil
	}
	return nil, nil
}

func (store *HistoryStore) snapshotDir(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return filepath.Join(store.root, "snapshots", hex.EncodeToString(sum[:]))
}

func loadHistorySnapshot(path string) (Evidence, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Evidence{}, fmt.Errorf("corrupt history: read snapshot %s: %w", filepath.Base(path), err)
	}
	if !info.Mode().IsRegular() {
		return Evidence{}, fmt.Errorf("corrupt history: snapshot %s is not a regular file", filepath.Base(path))
	}
	if info.Size() > MaxEvidenceBytes {
		return Evidence{}, fmt.Errorf("corrupt history: snapshot %s exceeds the evidence size bound", filepath.Base(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Evidence{}, fmt.Errorf("corrupt history: read snapshot %s: %w", filepath.Base(path), err)
	}
	var evidence Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return Evidence{}, fmt.Errorf("corrupt history: parse snapshot %s: %w", filepath.Base(path), err)
	}
	if err := ValidateEvidence(evidence); err != nil {
		return Evidence{}, fmt.Errorf("corrupt history: invalid snapshot %s: %w", filepath.Base(path), err)
	}
	return evidence, nil
}

// ComputeVersionDelta builds a structured, evidence-based delta between a
// strictly comparable predecessor and the current capture. It fails closed when
// the two captures are not comparable.
func ComputeVersionDelta(previous Evidence, current Evidence) (VersionDelta, error) {
	if err := ValidateEvidence(previous); err != nil {
		return VersionDelta{}, fmt.Errorf("validate previous evidence: %w", err)
	}
	if err := ValidateEvidence(current); err != nil {
		return VersionDelta{}, err
	}
	if err := validateEvidenceComparison(previous, current); err != nil {
		return VersionDelta{}, err
	}
	identity, _ := stableIdentity(current)
	delta := VersionDelta{
		SchemaVersion: VersionDeltaSchemaVersion,
		Identity:      identity,
		TargetKind:    current.Target.Kind,
		Lineage:       current.Target.Lineage,
		PluginID:      pluginIdentityID(current),
		Previous: VersionEndpoint{
			RunID: previous.Run.ID, CompletedAt: previous.Run.CompletedAt, TargetSHA256: previous.Target.SHA256,
		},
		Current: VersionEndpoint{
			RunID: current.Run.ID, CompletedAt: current.Run.CompletedAt, TargetSHA256: current.Target.SHA256,
		},
		Changes: DiffEvidence(previous, current),
		Grade:   gradeDelta(previous, current),
	}
	return delta, nil
}

// gradeSignal extracts an optional external grade label bound to a capture. The
// v1 evidence schema intentionally carries no grade, so this returns "". This
// is the single seam a future grade source hooks into; behavioral Changes are
// always computed independently so a grade never becomes the only signal.
func gradeSignal(evidence Evidence) string { return "" }

func gradeDelta(previous Evidence, current Evidence) *GradeDelta {
	before := gradeSignal(previous)
	after := gradeSignal(current)
	if before == "" && after == "" {
		return nil
	}
	return &GradeDelta{Previous: before, Current: after, Changed: before != after}
}

func stableIdentity(evidence Evidence) (string, bool) {
	identity, err := comparisonIdentity(evidence)
	if err != nil {
		return "", false
	}
	return identity, true
}

func pluginIdentityID(evidence Evidence) string {
	if evidence.Target.Kind == "plugin" {
		return evidence.Target.ID
	}
	return ""
}

func historySortKey(evidence Evidence) string {
	parsed, err := time.Parse(time.RFC3339Nano, evidence.Run.CompletedAt)
	if err != nil {
		return "00000000T000000.000000000Z"
	}
	return parsed.UTC().Format("20060102T150405.000000000Z")
}

// historyEntryBefore orders entries oldest-first using parsed timestamps so
// sub-second precision differences order correctly rather than lexically.
func historyEntryBefore(a HistoryEntry, b HistoryEntry) bool {
	at, aerr := time.Parse(time.RFC3339Nano, a.CompletedAt)
	bt, berr := time.Parse(time.RFC3339Nano, b.CompletedAt)
	if aerr == nil && berr == nil && !at.Equal(bt) {
		return at.Before(bt)
	}
	ar, _ := time.Parse(time.RFC3339Nano, a.RecordedAt)
	br, _ := time.Parse(time.RFC3339Nano, b.RecordedAt)
	if !ar.Equal(br) {
		return ar.Before(br)
	}
	return a.RunID < b.RunID
}

func shortToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}
