package observatory

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const EvidenceSchemaVersion = "observatory.behavior.v1"
const MaxEvidenceBytes = 64 << 20

// MaxRuntimeTimelineEventsPerLane bounds the ordered runtime syscall timeline that
// each lane publishes. The timeline is a normalized, secret-safe projection of
// file/process/network syscalls (not OpenClaw tool calls); the cap keeps the
// public evidence bounded even when an exercise emits many syscalls. Events
// beyond the cap are dropped from the earliest-preserving prefix and the lane is
// flagged truncated. The value is bound into the capture-config receipt through
// the capture protocol revision so it cannot silently drift across versions.
const MaxRuntimeTimelineEventsPerLane = 4096

// MaxToolCallsPerLane bounds the published OpenClaw tool-call ledger per lane.
const MaxToolCallsPerLane = 4096

type Evidence struct {
	SchemaVersion       string              `json:"schemaVersion"`
	CaptureConfigSHA256 string              `json:"captureConfigSha256"`
	Target              TargetEvidence      `json:"target"`
	Run                 RunEvidence         `json:"run"`
	Exercise            ExerciseEvidence    `json:"exercise"`
	Observations        []Observation       `json:"observations"`
	Canaries            []CanaryObservation `json:"canaries"`
	Coverage            CoverageEvidence    `json:"coverage"`
	ToolCallLedger      ToolCallLedger      `json:"toolCallLedger"`
	RuntimeTimeline     RuntimeTimeline     `json:"runtimeTimeline"`
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

// RuntimeTimeline is the ordered runtime syscall timeline for both lanes. It
// records file/process/network syscalls captured by strace, not OpenClaw tool
// calls, tool arguments, or tool results; the OpenClaw tool-call ledger is a
// separate section. Unlike Observations (a baseline-subtracted aggregate), the
// timeline preserves the per-lane sequence of activity so downstream grading and
// future declared-vs-observed comparison can reason about ordering and timing.
// Subjects reuse the same normalization and redaction as Observations, so no raw
// arguments, secrets, canary values, private addresses, or host paths appear.
type RuntimeTimeline struct {
	MaxEventsPerLane int                 `json:"maxEventsPerLane"`
	Baseline         RuntimeTimelineLane `json:"baseline"`
	Exercise         RuntimeTimelineLane `json:"exercise"`
}

type RuntimeTimelineLane struct {
	EventCount  int                    `json:"eventCount"`
	TotalEvents int                    `json:"totalEvents"`
	Truncated   bool                   `json:"truncated"`
	Timed       bool                   `json:"timed"`
	DurationMs  *int64                 `json:"durationMs,omitempty"`
	Events      []RuntimeTimelineEvent `json:"events"`
}

type RuntimeTimelineEvent struct {
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

// ToolCallLedger is the paired OpenClaw tool-call ledger for both lanes. It is
// projected from OpenClaw's metadata-only audit ledger (tool.action started and
// finished records), which by contract records identity, ordering, terminal
// state, error code, and timing but never prompts, tool arguments, tool results,
// command output, or raw error text. It is a genuine record of OpenClaw tool
// activity, distinct from the RuntimeTimeline of underlying syscalls.
type ToolCallLedger struct {
	Source            string               `json:"source"`
	MaxCallsPerLane   int                  `json:"maxCallsPerLane"`
	ArgumentSummaries ToolArgumentCoverage `json:"argumentSummaries"`
	Baseline          ToolCallLane         `json:"baseline"`
	Exercise          ToolCallLane         `json:"exercise"`
}

// ToolArgumentCoverage records whether bounded, secret-safe argument/result
// summaries are published. In the MVP they are explicitly unavailable: the
// metadata-only audit ledger never carries arguments or results, and the
// redacted trajectory's best-effort redaction cannot guarantee synthetic-canary
// safety. The observatory publishes this explicit coverage rather than
// pretending syscall subjects are tool arguments.
type ToolArgumentCoverage struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

// ToolCallLane carries the coverage verdict and ordered tool calls for one lane.
// Coverage is "complete" (a claimed-complete ledger with every call terminal),
// "incomplete" (a claimed-complete ledger missing a terminal record or truncated),
// or "unavailable" (no audit ledger was recorded for the lane).
type ToolCallLane struct {
	Coverage   string     `json:"coverage"`
	Reason     string     `json:"reason,omitempty"`
	CallCount  int        `json:"callCount"`
	TotalCalls int        `json:"totalCalls"`
	Truncated  bool       `json:"truncated"`
	Timed      bool       `json:"timed"`
	DurationMs *int64     `json:"durationMs,omitempty"`
	Calls      []ToolCall `json:"calls"`
}

// ToolCall is one correlated tool invocation. Sequence is a safe per-lane ordinal
// used for correlation; the raw OpenClaw tool call id and its one-way fingerprint
// are never published. State is the terminal audit status, or "started" when the
// ledger recorded no terminal record for the call.
type ToolCall struct {
	Sequence   int    `json:"sequence"`
	Tool       string `json:"tool"`
	State      string `json:"state"`
	ErrorCode  string `json:"errorCode,omitempty"`
	DurationMs *int64 `json:"durationMs,omitempty"`
	OffsetMs   *int64 `json:"offsetMs,omitempty"`
}

type CaptureMetadata struct {
	RunID               string
	TargetSHA256        string
	CaptureConfigSHA    string
	StartedAt           time.Time
	CompletedAt         time.Time
	BaselineExitCode    int
	ExerciseExitCode    int
	BaselineWorkspace   string
	ExerciseWorkspace   string
	BaselineState       string
	ExerciseState       string
	BaselineHome        string
	ExerciseHome        string
	TargetKind          string
	TargetRoot          string
	OpenClawVersion     string
	StraceVersion       string
	FirewallSHA256      string
	BaselineAuditStatus string
	ExerciseAuditStatus string
	Canaries            []CanaryDefinition
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
	if err := validateRuntimeTimeline(evidence.RuntimeTimeline); err != nil {
		return err
	}
	if err := validateToolCallLedger(evidence.ToolCallLedger); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || len(encoded) > MaxEvidenceBytes {
		return fmt.Errorf("evidence exceeds maximum encoded size (%d bytes)", MaxEvidenceBytes)
	}
	return nil
}

const ToolCallLedgerSource = "openclaw-audit-ledger"

var (
	toolCallStates = map[string]bool{
		"started": true, "succeeded": true, "failed": true, "cancelled": true,
		"timed_out": true, "blocked": true, "unknown": true,
	}
	toolCallErrorCodes = map[string]bool{
		"run_failed": true, "run_cancelled": true, "run_timed_out": true, "run_blocked": true,
		"tool_failed": true, "tool_cancelled": true, "tool_timed_out": true, "tool_blocked": true,
		"tool_outcome_unknown": true,
	}
	// toolNamePattern accepts only the compact model-facing tool-name contract
	// (or the audit ledger's "unknown" sentinel). Any other value fails closed.
	toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
)

// validateToolCallLedger fails closed on a malformed published ledger so a
// claimed-complete tool audit cannot be misrepresented. Lane coverage is a closed
// vocabulary; unavailable lanes carry no calls or timing; complete lanes must be
// fully terminal and untruncated; and only safe ordinals, names, states, error
// codes, and relative timing are permitted (never raw tool call ids or arguments).
func validateToolCallLedger(ledger ToolCallLedger) error {
	if ledger.Source != ToolCallLedgerSource {
		return errors.New("evidence tool-call ledger source is missing or unsupported")
	}
	if ledger.MaxCallsPerLane != MaxToolCallsPerLane {
		return errors.New("evidence tool-call ledger per-lane bound is missing or unsupported")
	}
	if strings.TrimSpace(ledger.ArgumentSummaries.Reason) == "" || len(ledger.ArgumentSummaries.Reason) > 400 ||
		strings.ContainsAny(ledger.ArgumentSummaries.Reason, "\x00\r\n") {
		return errors.New("evidence tool-call ledger argument-summary coverage is incomplete")
	}
	if err := validateToolCallLane(ledger.Baseline); err != nil {
		return fmt.Errorf("evidence baseline tool-call ledger is invalid: %w", err)
	}
	if err := validateToolCallLane(ledger.Exercise); err != nil {
		return fmt.Errorf("evidence exercise tool-call ledger is invalid: %w", err)
	}
	return nil
}

func validateToolCallLane(lane ToolCallLane) error {
	if lane.Coverage != "complete" && lane.Coverage != "incomplete" && lane.Coverage != "unavailable" {
		return errors.New("coverage is unsupported")
	}
	if lane.Calls == nil {
		return errors.New("calls are required")
	}
	if lane.CallCount != len(lane.Calls) {
		return errors.New("call count does not match its calls")
	}
	if lane.CallCount > MaxToolCallsPerLane {
		return errors.New("call count exceeds the per-lane bound")
	}
	if lane.TotalCalls < lane.CallCount {
		return errors.New("total calls cannot be fewer than published calls")
	}
	if lane.Truncated != (lane.TotalCalls > lane.CallCount) {
		return errors.New("truncation flag is inconsistent with the call counts")
	}
	if len(lane.Reason) > 200 || strings.ContainsAny(lane.Reason, "\x00\r\n") {
		return errors.New("reason contains unsafe characters")
	}
	if lane.Coverage == "unavailable" && (lane.CallCount != 0 || lane.Truncated || lane.Timed) {
		return errors.New("unavailable lane must carry no calls or timing")
	}
	if !lane.Timed && lane.DurationMs != nil {
		return errors.New("untimed lane must not report a duration")
	}
	if lane.Timed && (lane.DurationMs == nil || *lane.DurationMs < 0) {
		return errors.New("timed lane must report a non-negative duration")
	}
	var lastOffset int64 = -1
	for index, call := range lane.Calls {
		if call.Sequence != index+1 {
			return errors.New("call sequence is not contiguous")
		}
		if !toolNamePattern.MatchString(call.Tool) {
			return errors.New("call tool name is missing or unsafe")
		}
		if !toolCallStates[call.State] {
			return errors.New("call state is unsupported")
		}
		if lane.Coverage == "complete" && call.State == "started" {
			return errors.New("complete lane cannot contain a call without a terminal record")
		}
		if call.ErrorCode != "" && !toolCallErrorCodes[call.ErrorCode] {
			return errors.New("call error code is unsupported")
		}
		if call.DurationMs != nil && *call.DurationMs < 0 {
			return errors.New("call duration must be non-negative")
		}
		if lane.Timed {
			if call.OffsetMs == nil || *call.OffsetMs < 0 {
				return errors.New("timed call must report a non-negative offset")
			}
			if *call.OffsetMs < lastOffset {
				return errors.New("timed call offsets must be non-decreasing")
			}
			if *call.OffsetMs > *lane.DurationMs {
				return errors.New("timed call offset exceeds the lane duration")
			}
			lastOffset = *call.OffsetMs
		} else if call.OffsetMs != nil {
			return errors.New("untimed call must not report an offset")
		}
	}
	if lane.Coverage == "complete" && lane.Truncated {
		return errors.New("complete lane cannot be truncated")
	}
	return nil
}

// validateRuntimeTimeline fails closed on any malformed runtimeTimeline so incomplete or
// tampered captures cannot be published. It enforces the per-lane bound,
// contiguous sequence numbering, a closed outcome vocabulary, secret-safe
// subjects, and the invariant that timing offsets appear only for timed lanes
// and remain non-decreasing within the reported duration.
func validateRuntimeTimeline(runtimeTimeline RuntimeTimeline) error {
	if runtimeTimeline.MaxEventsPerLane != MaxRuntimeTimelineEventsPerLane {
		return errors.New("evidence runtimeTimeline per-lane event bound is missing or unsupported")
	}
	if err := validateRuntimeTimelineLane(runtimeTimeline.Baseline); err != nil {
		return fmt.Errorf("evidence baseline runtimeTimeline is invalid: %w", err)
	}
	if err := validateRuntimeTimelineLane(runtimeTimeline.Exercise); err != nil {
		return fmt.Errorf("evidence exercise runtimeTimeline is invalid: %w", err)
	}
	return nil
}

func validateRuntimeTimelineLane(lane RuntimeTimelineLane) error {
	if lane.Events == nil {
		return errors.New("events are required")
	}
	if lane.EventCount != len(lane.Events) {
		return errors.New("event count does not match its events")
	}
	if lane.EventCount > MaxRuntimeTimelineEventsPerLane {
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
