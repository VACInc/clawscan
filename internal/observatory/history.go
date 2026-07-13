package observatory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// historyWriterLockTimeout bounds contention on the cross-process history
// writer lock. Readers do not take the lock because the index is replaced
// atomically only after its referenced snapshot is durable.
const historyWriterLockTimeout = 2 * time.Second

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
	root        string
	lockTimeout time.Duration
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
	if err := prepareSecureHistoryRoot(root); err != nil {
		return nil, fmt.Errorf("create history store: %w", err)
	}
	return &HistoryStore{root: root, lockTimeout: historyWriterLockTimeout}, nil
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
	root, err := openSecureHistoryRoot(store.root)
	if err != nil {
		return historyIndex{}, err
	}
	defer root.close()
	return store.loadIndexFrom(root)
}

func (store *HistoryStore) loadIndexFrom(root *secureHistoryRoot) (historyIndex, error) {
	data, err := root.readRegularFile("index.json", MaxHistoryIndexBytes, historyFileMode)
	if errors.Is(err, errHistoryPathNotExist) {
		return historyIndex{SchemaVersion: HistorySchemaVersion}, nil
	}
	if err != nil {
		return historyIndex{}, fmt.Errorf("read history index: %w", err)
	}
	if len(data) > MaxHistoryIndexBytes {
		return historyIndex{}, errors.New("corrupt history: index exceeds size bound")
	}
	var index historyIndex
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return historyIndex{}, fmt.Errorf("corrupt history: parse index: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return historyIndex{}, fmt.Errorf("corrupt history: parse index: %w", err)
	}
	if index.SchemaVersion != HistorySchemaVersion {
		return historyIndex{}, fmt.Errorf("corrupt history: unsupported index schema %q", index.SchemaVersion)
	}
	if err := store.validateIndex(root, index); err != nil {
		return historyIndex{}, err
	}
	return index, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

// validateIndex verifies every evidence-backed field before the index is used
// for selection, duplicate detection, or per-identity bounds. This prevents a
// modified index from hiding snapshots under a false identity or redirecting a
// record to unrelated evidence.
func (store *HistoryStore) validateIndex(root *secureHistoryRoot, index historyIndex) error {
	seenRuns := make(map[string]string, len(index.Entries))
	seenSnapshots := make(map[string]struct{}, len(index.Entries))
	for _, entry := range index.Entries {
		recordedAt, err := time.Parse(time.RFC3339Nano, entry.RecordedAt)
		if err != nil || recordedAt.UTC().Format(time.RFC3339Nano) != entry.RecordedAt {
			return fmt.Errorf("corrupt history: run %q has invalid recordedAt metadata", entry.RunID)
		}
		if prior, ok := seenRuns[entry.RunID]; ok {
			return fmt.Errorf("corrupt history: duplicate run %q in snapshots %q and %q", entry.RunID, prior, entry.SnapshotPath)
		}
		if _, ok := seenSnapshots[entry.SnapshotPath]; ok {
			return fmt.Errorf("corrupt history: duplicate snapshot path %q", entry.SnapshotPath)
		}

		evidence, err := store.loadHistorySnapshot(root, entry.SnapshotPath)
		if err != nil {
			return err
		}
		if evidence.Run.Status != "completed" {
			return fmt.Errorf("corrupt history: snapshot %s is not a completed capture", filepath.Base(entry.SnapshotPath))
		}
		identity, ok := stableIdentity(evidence)
		if !ok {
			return fmt.Errorf("corrupt history: snapshot %s has no stable identity", filepath.Base(entry.SnapshotPath))
		}
		expectedRel := store.snapshotRelativePath(identity, evidence)
		expected := historyEntryForEvidence(evidence, entry.RecordedAt, expectedRel)
		if entry != expected {
			return fmt.Errorf("corrupt history: index metadata for snapshot %s does not exactly match its evidence", filepath.Base(entry.SnapshotPath))
		}
		seenRuns[entry.RunID] = entry.SnapshotPath
		seenSnapshots[entry.SnapshotPath] = struct{}{}
	}
	return nil
}

func historyEntryForEvidence(evidence Evidence, recordedAt string, snapshotPath string) HistoryEntry {
	identity, _ := stableIdentity(evidence)
	return HistoryEntry{
		Identity:            identity,
		Kind:                evidence.Target.Kind,
		Lineage:             evidence.Target.Lineage,
		PluginID:            pluginIdentityID(evidence),
		RunID:               evidence.Run.ID,
		TargetSHA256:        evidence.Target.SHA256,
		CaptureConfigSHA256: evidence.CaptureConfigSHA256,
		CompletedAt:         evidence.Run.CompletedAt,
		RecordedAt:          recordedAt,
		Status:              evidence.Run.Status,
		SnapshotPath:        snapshotPath,
	}
}

func (store *HistoryStore) writeIndex(root *secureHistoryRoot, index historyIndex) error {
	index.SchemaVersion = HistorySchemaVersion
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > MaxHistoryIndexBytes {
		return errors.New("history: updated index exceeds size bound")
	}
	return root.writeIndexAtomic(data)
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
	root, err := openSecureHistoryRoot(store.root)
	if err != nil {
		return err
	}
	defer root.close()
	release, err := root.acquireWriterLock(store.lockTimeout)
	if err != nil {
		return err
	}
	defer release()

	index, err := store.loadIndexFrom(root)
	if err != nil {
		return err
	}
	payload, err := marshalEvidenceSnapshot(evidence)
	if err != nil {
		return err
	}
	rel := store.snapshotRelativePath(identity, evidence)

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
			return store.verifyIdenticalRecord(root, index.Entries[i], payload)
		}
	}
	if count >= maxPerIdentity {
		return fmt.Errorf("history: %s already has %d recorded snapshots at the maxPerIdentity bound of %d; history is append-only, so prune it manually before adding more", identity, count, maxPerIdentity)
	}
	if err := root.ensureDirectory(filepath.Dir(rel), historyDirectoryMode); err != nil {
		return err
	}
	if err := writeSnapshotNoClobber(root, rel, payload); err != nil {
		return err
	}
	index.Entries = append(index.Entries, historyEntryForEvidence(
		evidence,
		time.Now().UTC().Format(time.RFC3339Nano),
		rel,
	))
	return store.writeIndex(root, index)
}

// verifyIdenticalRecord accepts a re-record of an existing run only when its
// preserved snapshot is valid and byte-identical to the new payload. It never
// modifies the stored snapshot.
func (store *HistoryStore) verifyIdenticalRecord(root *secureHistoryRoot, entry HistoryEntry, payload []byte) error {
	if _, err := store.loadHistorySnapshot(root, entry.SnapshotPath); err != nil {
		return err
	}
	stored, err := root.readRegularFile(entry.SnapshotPath, MaxEvidenceBytes, historyFileMode)
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
// existing snapshot is preserved and reported as an error. A failed write is
// left unindexed so no cleanup path can race another writer; a retry fails
// closed unless the complete canonical payload is present.
func writeSnapshotNoClobber(root *secureHistoryRoot, rel string, payload []byte) error {
	created, err := root.writeRegularFileExclusive(rel, payload, historyFileMode)
	if errors.Is(err, errHistoryPathExist) {
		existing, readErr := root.readRegularFile(rel, MaxEvidenceBytes, historyFileMode)
		if readErr != nil {
			return fmt.Errorf("corrupt history: read snapshot %s: %w", filepath.Base(rel), readErr)
		}
		if !bytes.Equal(existing, payload) {
			return fmt.Errorf("history: refusing to overwrite existing snapshot %s with different content", filepath.Base(rel))
		}
		return root.syncRegularFile(rel, historyFileMode)
	}
	if err != nil {
		return err
	}
	if !created {
		return errors.New("history: snapshot writer returned no result")
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
	root, err := openSecureHistoryRoot(store.root)
	if err != nil {
		return nil, err
	}
	defer root.close()
	index, err := store.loadIndexFrom(root)
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
		evidence, err := store.loadHistorySnapshot(root, entry.SnapshotPath)
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

func (store *HistoryStore) snapshotRelativePath(identity string, evidence Evidence) string {
	dir := store.snapshotDir(identity)
	name := historySortKey(evidence) + "-" + shortToken(evidence.Run.ID) + ".json"
	return filepath.Join("snapshots", filepath.Base(dir), name)
}

func (store *HistoryStore) loadHistorySnapshot(root *secureHistoryRoot, rel string) (Evidence, error) {
	if _, err := store.resolve(rel); err != nil {
		return Evidence{}, err
	}
	data, err := root.readRegularFile(rel, MaxEvidenceBytes, historyFileMode)
	if err != nil {
		return Evidence{}, fmt.Errorf("corrupt history: read snapshot %s: %w", filepath.Base(rel), err)
	}
	var evidence Evidence
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return Evidence{}, fmt.Errorf("corrupt history: parse snapshot %s: %w", filepath.Base(rel), err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Evidence{}, fmt.Errorf("corrupt history: parse snapshot %s: %w", filepath.Base(rel), err)
	}
	if err := ValidateEvidence(evidence); err != nil {
		return Evidence{}, fmt.Errorf("corrupt history: invalid snapshot %s: %w", filepath.Base(rel), err)
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
