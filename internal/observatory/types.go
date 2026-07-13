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

// Canary interaction stages are stable, publicly safe labels for how a canary
// was touched.
//
//   - read/write/execute/outbound are derived from the paired syscall trace.
//     The capture retains send-payload bytes (privately), so outbound
//     correlation is available whenever paired traces exist.
//   - agent-output records the canary value surfacing in the OpenClaw agent
//     command stdout / final JSON. It is honestly its own signal, not a
//     tool-call ledger.
//   - tool is reserved for a future authoritative control-plane ledger. Local
//     OpenClaw audit metadata lacks bounded arguments/results and is lane-owned,
//     so this protocol always reports tool coverage as limited. Tool use is
//     never inferred from agent stdout.
//
// Absence of a value on a stage whose channel is present is limited coverage,
// not proof the token went unused.
const (
	CanaryStageRead        = "read"
	CanaryStageWrite       = "write"
	CanaryStageExecute     = "execute"
	CanaryStageOutbound    = "outbound"
	CanaryStageAgentOutput = "agent-output"
	CanaryStageTool        = "tool"
)

// canaryStageSequence fixes the canonical order used for deterministic
// serialization, coverage reporting, and version comparison.
var canaryStageSequence = []string{CanaryStageRead, CanaryStageWrite, CanaryStageExecute, CanaryStageOutbound, CanaryStageAgentOutput, CanaryStageTool}

// maxCanaryInteractionCount bounds published interaction counters so an
// adversarially large capture cannot inflate evidence or its encoded size.
const maxCanaryInteractionCount = 1 << 20

type Evidence struct {
	SchemaVersion       string              `json:"schemaVersion"`
	CaptureConfigSHA256 string              `json:"captureConfigSha256"`
	Target              TargetEvidence      `json:"target"`
	Run                 RunEvidence         `json:"run"`
	Exercise            ExerciseEvidence    `json:"exercise"`
	Observations        []Observation       `json:"observations"`
	Canaries            []CanaryObservation `json:"canaries"`
	Coverage            CoverageEvidence    `json:"coverage"`
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
	ID                   string                   `json:"id"`
	Surface              string                   `json:"surface"`
	Class                string                   `json:"class"`
	BaselineInteractions int                      `json:"baselineInteractions"`
	ExerciseInteractions int                      `json:"exerciseInteractions"`
	DeltaInteractions    int                      `json:"deltaInteractions"`
	Stages               []CanaryStageInteraction `json:"stages"`
}

// CanaryStageInteraction records how many times a single canary was touched in
// a specific interaction stage. Baseline/exercise totals count distinct trace
// lines (the tool stage counts appearances in the captured agent output), and a
// line may map to more than one stage, so per-stage counts need not sum to the
// canary total.
type CanaryStageInteraction struct {
	Stage                string `json:"stage"`
	BaselineInteractions int    `json:"baselineInteractions"`
	ExerciseInteractions int    `json:"exerciseInteractions"`
	DeltaInteractions    int    `json:"deltaInteractions"`
}

// CanaryStageCoverage documents whether the capture protocol can positively
// detect a given interaction stage. "limited" means a zero interaction count is
// inconclusive (limited coverage, not proof of non-use); any nonzero stage
// interaction is still a real observation regardless of coverage.
type CanaryStageCoverage struct {
	Stage    string `json:"stage"`
	Coverage string `json:"coverage"`
	Source   string `json:"source"`
}

type CoverageEvidence struct {
	SyscallScope    string                `json:"syscallScope"`
	FileSyscalls    bool                  `json:"fileSyscalls"`
	ProcessSyscalls bool                  `json:"processSyscalls"`
	NetworkSyscalls bool                  `json:"networkSyscalls"`
	BaselinePaired  bool                  `json:"baselinePaired"`
	CanaryStages    []CanaryStageCoverage `json:"canaryStages"`
	Limitations     []string              `json:"limitations"`
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
	Class   string
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
	if err := validateCanaryStageCoverage(evidence.Coverage.CanaryStages); err != nil {
		return err
	}
	pairedTraceCoverage := evidence.Coverage.BaselinePaired && evidence.Coverage.FileSyscalls && evidence.Coverage.ProcessSyscalls && evidence.Coverage.NetworkSyscalls
	if evidence.Coverage.BaselinePaired != evidence.Coverage.FileSyscalls || evidence.Coverage.BaselinePaired != evidence.Coverage.ProcessSyscalls || evidence.Coverage.BaselinePaired != evidence.Coverage.NetworkSyscalls {
		return errors.New("evidence syscall and paired-trace coverage is inconsistent")
	}
	for _, index := range []int{0, 1, 2} {
		if (evidence.Coverage.CanaryStages[index].Coverage == "observed") != pairedTraceCoverage {
			return errors.New("evidence canary trace-stage coverage is inconsistent")
		}
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
		if strings.TrimSpace(canary.Class) == "" || len(canary.Class) > 40 || strings.ContainsAny(canary.Class, "\x00\r\n") {
			return errors.New("evidence contains an invalid canary class")
		}
		if err := validateCanaryStages(canary.Stages); err != nil {
			return err
		}
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || len(encoded) > MaxEvidenceBytes {
		return fmt.Errorf("evidence exceeds maximum encoded size (%d bytes)", MaxEvidenceBytes)
	}
	return nil
}

// validateCanaryStages enforces canonical stage ordering, non-empty stages, and
// per-stage delta consistency so stage-level correlation stays deterministic and
// safe to grade and diff across versions.
func validateCanaryStages(stages []CanaryStageInteraction) error {
	lastRank := -1
	for _, stage := range stages {
		rank, ok := canaryStageRank(stage.Stage)
		if !ok || rank <= lastRank {
			return errors.New("evidence canary stages are unknown, duplicated, or out of order")
		}
		lastRank = rank
		expected := stage.ExerciseInteractions - stage.BaselineInteractions
		if expected < 0 {
			expected = 0
		}
		if stage.BaselineInteractions < 0 || stage.ExerciseInteractions < 0 || stage.DeltaInteractions != expected {
			return errors.New("evidence contains an invalid canary stage interaction")
		}
		if stage.BaselineInteractions == 0 && stage.ExerciseInteractions == 0 {
			return errors.New("evidence canary stage has no interactions")
		}
	}
	return nil
}

// validateCanaryStageCoverage requires every interaction stage to declare its
// coverage exactly once and in canonical order, so absence of a stage hit can
// never be silently misread as proof of non-use.
func validateCanaryStageCoverage(coverage []CanaryStageCoverage) error {
	if len(coverage) != len(canaryStageSequence) {
		return errors.New("evidence canary stage coverage is incomplete")
	}
	expectedSources := map[string]map[string]bool{
		CanaryStageRead:    {"file-open-and-descriptor-syscall-trace": true},
		CanaryStageWrite:   {"file-mutation-syscall-trace": true},
		CanaryStageExecute: {"exec-syscall-trace": true},
		CanaryStageOutbound: {
			"socket-send-syscall-payload":                    true,
			"typed-sink-receipt":                             true,
			"socket-send-syscall-payload+typed-sink-receipt": true,
			"unavailable-or-unpaired":                        true,
		},
		CanaryStageAgentOutput: {
			"agent-command-stdout":                       true,
			"agent-command-stdout-unpaired-or-truncated": true,
		},
		CanaryStageTool: {"openclaw-audit-metadata-no-bounded-args-results": true},
	}
	for i, entry := range coverage {
		if entry.Stage != canaryStageSequence[i] {
			return errors.New("evidence canary stage coverage is missing or out of order")
		}
		if entry.Coverage != "observed" && entry.Coverage != "limited" {
			return errors.New("evidence canary stage coverage state is invalid")
		}
		if !expectedSources[entry.Stage][entry.Source] {
			return errors.New("evidence canary stage coverage source is invalid")
		}
		if entry.Stage == CanaryStageTool && entry.Coverage != "limited" {
			return errors.New("evidence tool-stage coverage cannot be authoritative for this capture protocol")
		}
		if entry.Stage == CanaryStageOutbound && entry.Source == "unavailable-or-unpaired" && entry.Coverage != "limited" {
			return errors.New("evidence outbound coverage is inconsistent with its source")
		}
		if entry.Stage == CanaryStageOutbound && entry.Source != "unavailable-or-unpaired" && entry.Coverage != "observed" {
			return errors.New("evidence outbound coverage is inconsistent with its source")
		}
		if entry.Stage == CanaryStageAgentOutput && (entry.Source == "agent-command-stdout") != (entry.Coverage == "observed") {
			return errors.New("evidence agent-output coverage is inconsistent with its source")
		}
	}
	return nil
}

func canaryStageRank(stage string) (int, bool) {
	for rank, name := range canaryStageSequence {
		if name == stage {
			return rank, true
		}
	}
	return 0, false
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
