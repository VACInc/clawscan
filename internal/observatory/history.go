package observatory

import (
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

// Record appends completed evidence to history and prunes the identity's
// snapshots to retain. It never touches per-run artifact directories or raw
// bundles. Recording the same run twice replaces the prior snapshot rather than
// duplicating it.
func (store *HistoryStore) Record(evidence Evidence, retain int) error {
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
	if retain < 1 {
		retain = 1
	}
	index, err := store.loadIndex()
	if err != nil {
		return err
	}
	dir := store.snapshotDir(identity)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := historySortKey(evidence) + "-" + shortToken(evidence.Run.ID) + ".json"
	rel := filepath.Join("snapshots", filepath.Base(dir), name)
	if err := writeJSON(filepath.Join(store.root, rel), evidence, 0o600); err != nil {
		return err
	}
	entry := HistoryEntry{
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
	}
	replaced := false
	for i := range index.Entries {
		if index.Entries[i].Identity == identity && index.Entries[i].RunID == entry.RunID {
			if index.Entries[i].SnapshotPath != rel {
				if old, resolveErr := store.resolve(index.Entries[i].SnapshotPath); resolveErr == nil {
					os.Remove(old)
				}
			}
			index.Entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		index.Entries = append(index.Entries, entry)
	}
	store.prune(&index, identity, retain)
	return store.writeIndex(index)
}

// prune bounds the identity's snapshots to retain, deleting only the pruned
// history snapshots. Entries for other identities are preserved untouched.
func (store *HistoryStore) prune(index *historyIndex, identity string, retain int) {
	matching := []HistoryEntry{}
	others := []HistoryEntry{}
	for _, entry := range index.Entries {
		if entry.Identity == identity {
			matching = append(matching, entry)
		} else {
			others = append(others, entry)
		}
	}
	sort.SliceStable(matching, func(i, j int) bool {
		return historyEntryBefore(matching[j], matching[i]) // newest first
	})
	if len(matching) > retain {
		for _, entry := range matching[retain:] {
			if path, err := store.resolve(entry.SnapshotPath); err == nil {
				os.Remove(path)
			}
		}
		matching = matching[:retain]
	}
	index.Entries = append(others, matching...)
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
