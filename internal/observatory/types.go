package observatory

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const EvidenceSchemaVersion = "observatory.behavior.v1"
const MaxEvidenceBytes = 64 << 20

// MaxTimelineEventsPerLane bounds the ordered tool-event timeline that each lane
// publishes. The timeline is a normalized, secret-safe projection; the cap keeps
// the public evidence bounded even when an exercise emits many syscalls. Events
// beyond the cap are dropped from the earliest-preserving prefix and the lane is
// flagged truncated. The value is bound into the capture-config receipt through
// the capture protocol revision so it cannot silently drift across versions.
const MaxTimelineEventsPerLane = 4096

type Evidence struct {
	SchemaVersion       string              `json:"schemaVersion"`
	CaptureConfigSHA256 string              `json:"captureConfigSha256"`
	Target              TargetEvidence      `json:"target"`
	Run                 RunEvidence         `json:"run"`
	Exercise            ExerciseEvidence    `json:"exercise"`
	Observations        []Observation       `json:"observations"`
	Canaries            []CanaryObservation `json:"canaries"`
	Coverage            CoverageEvidence    `json:"coverage"`
	Timeline            Timeline            `json:"timeline"`
}

type TargetEvidence struct {
	Name           string            `json:"name"`
	Kind           string            `json:"kind"`
	Lineage        string            `json:"lineage,omitempty"`
	ID             string            `json:"id,omitempty"`
	DeclaredTools  []string          `json:"declaredTools,omitempty"`
	SHA256         string            `json:"sha256"`
	FileCount      int               `json:"fileCount"`
	DirectoryCount int               `json:"directoryCount"`
	TotalBytes     int64             `json:"totalBytes"`
	Files          []TargetFile      `json:"files"`
	Directories    []TargetDirectory `json:"directories"`
	Omitted        []TargetOmission  `json:"omitted,omitempty"`
}

type TargetFile struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
	Mode  string `json:"mode"`
}

type TargetDirectory struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type TargetOmission struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Bytes  int64  `json:"bytes,omitempty"`
}

type RunEvidence struct {
	ID           string            `json:"id"`
	Status       string            `json:"status"`
	StartedAt    string            `json:"startedAt"`
	CompletedAt  string            `json:"completedAt"`
	DurationMs   int64             `json:"durationMs"`
	Executor     string            `json:"executor"`
	Isolation    IsolationEvidence `json:"isolation"`
	Runtime      RuntimeEvidence   `json:"runtime"`
	LaneExitCode LaneExitCodes     `json:"laneExitCode"`
}

type IsolationEvidence struct {
	Substrate                 string `json:"substrate"`
	NetworkMode               string `json:"networkMode"`
	ContainmentProfile        string `json:"containmentProfile"`
	GuestFirewallSHA256       string `json:"guestFirewallSha256"`
	GuestFirewallPolicySHA256 string `json:"guestFirewallPolicySha256"`
	Verification              string `json:"verification"`
}

type RuntimeEvidence struct {
	OpenClawVersion string `json:"openclawVersion,omitempty"`
	StraceVersion   string `json:"straceVersion,omitempty"`
	ModelProvider   string `json:"modelProvider"`
	ModelID         string `json:"modelId"`
	ModelEndpoint   string `json:"modelEndpoint"`
}

type LaneExitCodes struct {
	Baseline int `json:"baseline"`
	Exercise int `json:"exercise"`
}

type ExerciseEvidence struct {
	PromptSHA256      string `json:"promptSha256"`
	TurnLimit         int    `json:"turnLimit"`
	BaselineOutputSHA string `json:"baselineOutputSha256,omitempty"`
	ExerciseOutputSHA string `json:"exerciseOutputSha256,omitempty"`
}

type Observation struct {
	Kind          string `json:"kind"`
	Operation     string `json:"operation"`
	Subject       string `json:"subject"`
	Outcome       string `json:"outcome"`
	Role          string `json:"role,omitempty"`
	BaselineCount int    `json:"baselineCount"`
	ExerciseCount int    `json:"exerciseCount"`
	DeltaCount    int    `json:"deltaCount"`
}

type CanaryObservation struct {
	ID                   string `json:"id"`
	Surface              string `json:"surface"`
	BaselineInteractions int    `json:"baselineInteractions"`
	ExerciseInteractions int    `json:"exerciseInteractions"`
	DeltaInteractions    int    `json:"deltaInteractions"`
}

type CoverageEvidence struct {
	SyscallScope    string   `json:"syscallScope"`
	FileSyscalls    bool     `json:"fileSyscalls"`
	ProcessSyscalls bool     `json:"processSyscalls"`
	NetworkSyscalls bool     `json:"networkSyscalls"`
	BaselinePaired  bool     `json:"baselinePaired"`
	Limitations     []string `json:"limitations"`
}

// Timeline is the ordered tool-event timeline for both lanes. Unlike
// Observations (a baseline-subtracted aggregate), the timeline preserves the
// per-lane sequence of activity so downstream grading and future
// declared-vs-observed comparison can reason about ordering and timing. Subjects
// reuse the same normalization and redaction as Observations, so no raw
// arguments, secrets, canary values, private addresses, or host paths appear.
type Timeline struct {
	MaxEventsPerLane int          `json:"maxEventsPerLane"`
	Baseline         TimelineLane `json:"baseline"`
	Exercise         TimelineLane `json:"exercise"`
}

type TimelineLane struct {
	EventCount  int             `json:"eventCount"`
	TotalEvents int             `json:"totalEvents"`
	Truncated   bool            `json:"truncated"`
	Timed       bool            `json:"timed"`
	DurationMs  *int64          `json:"durationMs,omitempty"`
	Events      []TimelineEvent `json:"events"`
}

type TimelineEvent struct {
	Sequence  int    `json:"sequence"`
	Kind      string `json:"kind"`
	Operation string `json:"operation"`
	Subject   string `json:"subject"`
	Outcome   string `json:"outcome"`
	Role      string `json:"role,omitempty"`
	Canary    string `json:"canary,omitempty"`
	// OffsetMs is the millisecond offset from the lane's first captured event.
	// It is present only when the lane carries trustworthy monotonic timing;
	// offsets are relative so no absolute wall-clock time is published.
	OffsetMs *int64 `json:"offsetMs,omitempty"`
}

type CaptureMetadata struct {
	RunID             string
	TargetSHA256      string
	CaptureConfigSHA  string
	StartedAt         time.Time
	CompletedAt       time.Time
	BaselineExitCode  int
	ExerciseExitCode  int
	BaselineWorkspace string
	ExerciseWorkspace string
	BaselineState     string
	ExerciseState     string
	BaselineHome      string
	ExerciseHome      string
	TargetKind        string
	TargetRoot        string
	OpenClawVersion   string
	StraceVersion     string
	FirewallSHA256    string
	Canaries          []CanaryDefinition
}

type CanaryDefinition struct {
	ID      string
	Surface string
	Path    string
	Marker  string
}

func ValidateEvidence(evidence Evidence) error {
	if evidence.SchemaVersion != EvidenceSchemaVersion {
		return fmt.Errorf("unsupported evidence schema: %s", evidence.SchemaVersion)
	}
	if !isSHA256Digest(evidence.CaptureConfigSHA256) {
		return errors.New("evidence capture configuration receipt is incomplete")
	}
	if strings.TrimSpace(evidence.Target.Name) == "" || len(evidence.Target.Name) > 120 || strings.ContainsAny(evidence.Target.Name, "\x00\r\n") || (evidence.Target.Kind != "skill" && evidence.Target.Kind != "plugin") || !isSHA256Digest(evidence.Target.SHA256) {
		return errors.New("evidence target identity is incomplete")
	}
	if evidence.Target.Lineage != "" && !targetLineagePattern.MatchString(evidence.Target.Lineage) {
		return errors.New("evidence target lineage is invalid")
	}
	if evidence.Target.Kind == "plugin" && !pluginIDPattern.MatchString(evidence.Target.ID) {
		return errors.New("evidence plugin target ID is invalid")
	}
	if evidence.Target.Kind == "skill" && !skillIDPattern.MatchString(evidence.Target.ID) {
		return errors.New("evidence skill target ID is invalid")
	}
	if evidence.Target.FileCount < 1 || evidence.Target.FileCount != len(evidence.Target.Files) || evidence.Target.DirectoryCount < 1 || evidence.Target.DirectoryCount != len(evidence.Target.Directories) || evidence.Target.TotalBytes < 0 {
		return errors.New("evidence target manifest is incomplete")
	}
	var totalBytes int64
	for _, file := range evidence.Target.Files {
		if file.Path == "" || file.Bytes < 0 || !isPermissionMode(file.Mode) {
			return errors.New("evidence target file manifest is invalid")
		}
		totalBytes += file.Bytes
	}
	if totalBytes != evidence.Target.TotalBytes {
		return errors.New("evidence target byte count does not match its manifest")
	}
	for _, directory := range evidence.Target.Directories {
		if directory.Path == "" || !isPermissionMode(directory.Mode) {
			return errors.New("evidence target directory manifest is invalid")
		}
	}
	for _, omission := range evidence.Target.Omitted {
		if omission.Path == "" || omission.Bytes < 0 || strings.TrimSpace(omission.Reason) == "" || len(omission.Reason) > 160 || strings.ContainsAny(omission.Path+omission.Reason, "\x00\r\n") {
			return errors.New("evidence target omission manifest is invalid")
		}
	}
	if strings.TrimSpace(evidence.Run.ID) == "" || (evidence.Run.Status != "completed" && evidence.Run.Status != "incomplete") || strings.TrimSpace(evidence.Run.Executor) == "" {
		return errors.New("evidence run identity is incomplete")
	}
	if evidence.Run.LaneExitCode.Baseline < 0 || evidence.Run.LaneExitCode.Baseline > 255 || evidence.Run.LaneExitCode.Exercise < 0 || evidence.Run.LaneExitCode.Exercise > 255 {
		return errors.New("evidence lane exit code is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, evidence.Run.StartedAt); err != nil {
		return errors.New("evidence run startedAt is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, evidence.Run.CompletedAt); err != nil {
		return errors.New("evidence run completedAt is invalid")
	}
	if strings.TrimSpace(evidence.Run.Isolation.Substrate) == "" || strings.TrimSpace(evidence.Run.Isolation.NetworkMode) == "" || strings.TrimSpace(evidence.Run.Isolation.ContainmentProfile) == "" || !isSHA256Digest(evidence.Run.Isolation.GuestFirewallSHA256) || !isSHA256Digest(evidence.Run.Isolation.GuestFirewallPolicySHA256) || strings.TrimSpace(evidence.Run.Isolation.Verification) == "" {
		return errors.New("evidence isolation receipt is incomplete")
	}
	if strings.TrimSpace(evidence.Run.Runtime.OpenClawVersion) == "" || strings.TrimSpace(evidence.Run.Runtime.StraceVersion) == "" || strings.TrimSpace(evidence.Run.Runtime.ModelProvider) == "" || strings.TrimSpace(evidence.Run.Runtime.ModelID) == "" || strings.TrimSpace(evidence.Run.Runtime.ModelEndpoint) == "" {
		return errors.New("evidence runtime receipt is incomplete")
	}
	if !isSHA256Digest(evidence.Exercise.PromptSHA256) || evidence.Exercise.TurnLimit != 1 {
		return errors.New("evidence exercise receipt is incomplete")
	}
	if evidence.Observations == nil || evidence.Canaries == nil || evidence.Coverage.Limitations == nil {
		return errors.New("evidence observations, canaries, and coverage are required")
	}
	if evidence.Coverage.SyscallScope != "selected-mvp-syscalls" {
		return errors.New("evidence syscall coverage scope is missing or unsupported")
	}
	completeCapture := evidence.Run.LaneExitCode == (LaneExitCodes{}) && evidence.Coverage.BaselinePaired &&
		evidence.Coverage.FileSyscalls && evidence.Coverage.ProcessSyscalls && evidence.Coverage.NetworkSyscalls
	if (evidence.Run.Status == "completed") != completeCapture {
		return errors.New("evidence run status is inconsistent with lane exits or capture coverage")
	}
	for _, observation := range evidence.Observations {
		expectedDelta := observation.ExerciseCount - observation.BaselineCount
		if observation.Kind == "" || observation.Operation == "" || observation.Subject == "" || observation.Outcome == "" || observation.BaselineCount < 0 || observation.ExerciseCount < 0 || expectedDelta < 1 || observation.DeltaCount != expectedDelta {
			return errors.New("evidence contains an invalid observation")
		}
	}
	for _, canary := range evidence.Canaries {
		expectedDelta := canary.ExerciseInteractions - canary.BaselineInteractions
		if expectedDelta < 0 {
			expectedDelta = 0
		}
		if canary.ID == "" || canary.Surface == "" || canary.BaselineInteractions < 0 || canary.ExerciseInteractions < 0 || canary.DeltaInteractions != expectedDelta {
			return errors.New("evidence contains an invalid canary observation")
		}
	}
	if err := validateTimeline(evidence.Timeline); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || len(encoded) > MaxEvidenceBytes {
		return fmt.Errorf("evidence exceeds maximum encoded size (%d bytes)", MaxEvidenceBytes)
	}
	return nil
}

// validateTimeline fails closed on any malformed timeline so incomplete or
// tampered captures cannot be published. It enforces the per-lane bound,
// contiguous sequence numbering, a closed outcome vocabulary, secret-safe
// subjects, and the invariant that timing offsets appear only for timed lanes
// and remain non-decreasing within the reported duration.
func validateTimeline(timeline Timeline) error {
	if timeline.MaxEventsPerLane != MaxTimelineEventsPerLane {
		return errors.New("evidence timeline per-lane event bound is missing or unsupported")
	}
	if err := validateTimelineLane(timeline.Baseline); err != nil {
		return fmt.Errorf("evidence baseline timeline is invalid: %w", err)
	}
	if err := validateTimelineLane(timeline.Exercise); err != nil {
		return fmt.Errorf("evidence exercise timeline is invalid: %w", err)
	}
	return nil
}

func validateTimelineLane(lane TimelineLane) error {
	if lane.Events == nil {
		return errors.New("events are required")
	}
	if lane.EventCount != len(lane.Events) {
		return errors.New("event count does not match its events")
	}
	if lane.EventCount > MaxTimelineEventsPerLane {
		return errors.New("event count exceeds the per-lane bound")
	}
	if lane.TotalEvents < lane.EventCount {
		return errors.New("total events cannot be fewer than published events")
	}
	if lane.Truncated != (lane.TotalEvents > lane.EventCount) {
		return errors.New("truncation flag is inconsistent with the event counts")
	}
	if !lane.Timed && lane.DurationMs != nil {
		return errors.New("untimed lane must not report a duration")
	}
	if lane.Timed && (lane.DurationMs == nil || *lane.DurationMs < 0) {
		return errors.New("timed lane must report a non-negative duration")
	}
	var lastOffset int64 = -1
	for index, event := range lane.Events {
		if event.Sequence != index+1 {
			return errors.New("event sequence is not contiguous")
		}
		if event.Kind != "file" && event.Kind != "process" && event.Kind != "network" {
			return errors.New("event kind is unsupported")
		}
		if strings.TrimSpace(event.Operation) == "" || strings.TrimSpace(event.Subject) == "" {
			return errors.New("event operation and subject are required")
		}
		if len(event.Subject) > 4096 || strings.ContainsAny(event.Subject, "\x00\r\n") ||
			strings.ContainsAny(event.Operation+event.Role+event.Canary, "\x00\r\n") {
			return errors.New("event fields contain unsafe characters")
		}
		if event.Outcome != "completed" && event.Outcome != "denied" && event.Outcome != "error" {
			return errors.New("event outcome is unsupported")
		}
		if lane.Timed {
			if event.OffsetMs == nil || *event.OffsetMs < 0 {
				return errors.New("timed event must report a non-negative offset")
			}
			if *event.OffsetMs < lastOffset {
				return errors.New("timed event offsets must be non-decreasing")
			}
			if *event.OffsetMs > *lane.DurationMs {
				return errors.New("timed event offset exceeds the lane duration")
			}
			lastOffset = *event.OffsetMs
		} else if event.OffsetMs != nil {
			return errors.New("untimed event must not report an offset")
		}
	}
	return nil
}

func isSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func isPermissionMode(value string) bool {
	if len(value) != 4 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '7' {
			return false
		}
	}
	return true
}
