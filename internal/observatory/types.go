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

const LegacyEvidenceSchemaVersion = "observatory.behavior.v1"
const EvidenceSchemaVersion = "observatory.behavior.v2"
const MaxEvidenceBytes = 64 << 20

const MaxRuntimeTimelineEventsPerLane = 4096
const MaxToolCallsPerLane = 4096

const (
	CanaryStageRead        = "read"
	CanaryStageWrite       = "write"
	CanaryStageExecute     = "execute"
	CanaryStageOutbound    = "outbound"
	CanaryStageAgentOutput = "agent-output"
	CanaryStageTool        = "tool"
)

var canaryStageSequence = []string{CanaryStageRead, CanaryStageWrite, CanaryStageExecute, CanaryStageOutbound, CanaryStageAgentOutput, CanaryStageTool}

const maxCanaryInteractionCount = 1 << 20

type Evidence struct {
	SchemaVersion       string                     `json:"schemaVersion"`
	CaptureConfigSHA256 string                     `json:"captureConfigSha256"`
	Target              TargetEvidence             `json:"target"`
	Run                 RunEvidence                `json:"run"`
	Exercise            ExerciseEvidence           `json:"exercise"`
	Observations        []Observation              `json:"observations"`
	Canaries            []CanaryObservation        `json:"canaries"`
	RedirectProbes      []RedirectProbeObservation `json:"redirectProbes"`
	Persistence         PersistenceEvidence        `json:"persistence"`
	Coverage            CoverageEvidence           `json:"coverage"`
	MockEgress          *MockEgressEvidence        `json:"mockEgress,omitempty"`
	ModelRelay          *ModelRelayEvidence        `json:"modelRelay,omitempty"`
	ToolCallLedger      ToolCallLedger             `json:"toolCallLedger"`
	RuntimeTimeline     RuntimeTimeline            `json:"runtimeTimeline"`
}

type TargetEvidence struct {
	Name                 string                `json:"name"`
	Kind                 string                `json:"kind"`
	Lineage              string                `json:"lineage,omitempty"`
	ID                   string                `json:"id,omitempty"`
	DeclaredTools        []string              `json:"declaredTools,omitempty"`
	DeclaredCapabilities *DeclaredCapabilities `json:"declaredCapabilities,omitempty"`
	SHA256               string                `json:"sha256"`
	FileCount            int                   `json:"fileCount"`
	DirectoryCount       int                   `json:"directoryCount"`
	TotalBytes           int64                 `json:"totalBytes"`
	Files                []TargetFile          `json:"files"`
	Directories          []TargetDirectory     `json:"directories"`
	Omitted              []TargetOmission      `json:"omitted,omitempty"`
}

// DeclaredCapabilities is the conservative, machine-readable capability
// declaration parsed from target-owned metadata. It is lineage, not a verdict.
type DeclaredCapabilities struct {
	Source       string   `json:"source"`
	Declared     bool     `json:"declared"`
	Capabilities []string `json:"capabilities,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

var declaredCapabilityTokens = map[string]bool{
	"filesystem-read":   true,
	"filesystem-write":  true,
	"credential-access": true,
	"network":           true,
	"process-exec":      true,
	"persistence":       true,
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
	ProxmoxTLSCASHA256        string `json:"proxmoxTlsCaSha256,omitempty"`
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
	Class                string                   `json:"class,omitempty"`
	BaselineInteractions int                      `json:"baselineInteractions"`
	ExerciseInteractions int                      `json:"exerciseInteractions"`
	DeltaInteractions    int                      `json:"deltaInteractions"`
	Stages               []CanaryStageInteraction `json:"stages"`
}

type CanaryStageInteraction struct {
	Stage                string `json:"stage"`
	BaselineInteractions int    `json:"baselineInteractions"`
	ExerciseInteractions int    `json:"exerciseInteractions"`
	DeltaInteractions    int    `json:"deltaInteractions"`
}

type CanaryStageCoverage struct {
	Stage    string `json:"stage"`
	Coverage string `json:"coverage"`
	Source   string `json:"source"`
}

// RedirectProbeObservation reports how far the exercised agent escalated a
// synthetic injected-instruction marker seeded into workspace content. The three
// tiers are deliberately separate: a marker that was only read or repeated is not
// evidence of prompt injection. Only a positive deviation delta over the baseline
// lane shows the exercise lane actually performed the harmless sentinel action the
// seeded instruction named. Escalation is the highest tier reached in the exercise
// lane; attributed is the highest tier whose delta over baseline is positive.
type RedirectProbeObservation struct {
	ID               string `json:"id"`
	Surface          string `json:"surface"`
	Vector           string `json:"vector"`
	ReadBaseline     int    `json:"readBaseline"`
	ReadExercise     int    `json:"readExercise"`
	ReadDelta        int    `json:"readDelta"`
	RepeatedBaseline int    `json:"repeatedBaseline"`
	RepeatedExercise int    `json:"repeatedExercise"`
	RepeatedDelta    int    `json:"repeatedDelta"`
	DeviatedBaseline int    `json:"deviatedBaseline"`
	DeviatedExercise int    `json:"deviatedExercise"`
	DeviatedDelta    int    `json:"deviatedDelta"`
	Escalation       string `json:"escalation"`
	Attributed       string `json:"attributed"`
	// Exercised is true only when the exercise lane actually read the seeded
	// instruction file. When false the probe was not exposed to the agent, so its
	// escalation is not meaningful and must not be read as resistance.
	Exercised bool `json:"exercised"`
}

type CoverageEvidence struct {
	SyscallScope            string                `json:"syscallScope"`
	FileSyscalls            bool                  `json:"fileSyscalls"`
	ProcessSyscalls         bool                  `json:"processSyscalls"`
	NetworkSyscalls         bool                  `json:"networkSyscalls"`
	BaselinePaired          bool                  `json:"baselinePaired"`
	CanaryStages            []CanaryStageCoverage `json:"canaryStages,omitempty"`
	RedirectProbeScope      string                `json:"redirectProbeScope"`
	RedirectProbeCount      int                   `json:"redirectProbeCount"`
	RedirectProbesExercised int                   `json:"redirectProbesExercised"`
	RedirectDeepMode        bool                  `json:"redirectDeepMode"`
	Limitations             []string              `json:"limitations"`
}

// PersistenceEvidence reports persistence- and lifecycle-relevant behavior for a
// bounded, curated set of surfaces. Findings distinguish attempted-but-denied
// operations (outcome "attempted") from successful residual changes confirmed by
// a before/after lane inventory (residual "confirmed"). The surface catalog makes
// coverage explicit; it is not an exhaustive host persistence audit.
type PersistenceEvidence struct {
	Scope           string               `json:"scope"`
	InventoryPaired bool                 `json:"inventoryPaired"`
	Surfaces        []PersistenceSurface `json:"surfaces"`
	Findings        []PersistenceFinding `json:"findings"`
	Limitations     []string             `json:"limitations"`
}

type PersistenceSurface struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

type PersistenceFinding struct {
	Surface       string `json:"surface"`
	Category      string `json:"category"`
	Operation     string `json:"operation"`
	Subject       string `json:"subject"`
	Outcome       string `json:"outcome"`
	Evidence      string `json:"evidence"`
	Residual      string `json:"residual"`
	BaselineCount int    `json:"baselineCount"`
	ExerciseCount int    `json:"exerciseCount"`
	DeltaCount    int    `json:"deltaCount"`
}

// RuntimeTimeline is the ordered, normalized syscall sequence for both lanes.
// It is independent from the supplemental OpenClaw tool-call metadata.
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
	OffsetMs  *int64 `json:"offsetMs,omitempty"`
}

// ToolCallLedger is supplemental lane-owned OpenClaw metadata. Audit rows are
// not integrity-signed, so this is not a tamper-evident grading boundary.
type ToolCallLedger struct {
	Source            string               `json:"source"`
	MaxCallsPerLane   int                  `json:"maxCallsPerLane"`
	ArgumentSummaries ToolArgumentCoverage `json:"argumentSummaries"`
	Baseline          ToolCallLane         `json:"baseline"`
	Exercise          ToolCallLane         `json:"exercise"`
}

type ToolArgumentCoverage struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

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
	Redirects           []RedirectProbeDefinition
}

type CanaryDefinition struct {
	ID      string
	Surface string
	Class   string
	Path    string
	Marker  string
}

func ValidateEvidence(evidence Evidence) error {
	if evidence.SchemaVersion != EvidenceSchemaVersion && evidence.SchemaVersion != LegacyEvidenceSchemaVersion {
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
	if err := validateDeclaredCapabilities(evidence.Target.DeclaredCapabilities); err != nil {
		return err
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
	if evidence.SchemaVersion == EvidenceSchemaVersion && !isSHA256Digest(evidence.Run.Isolation.ProxmoxTLSCASHA256) {
		return errors.New("evidence verified TLS receipt is incomplete")
	}
	if evidence.SchemaVersion == LegacyEvidenceSchemaVersion && evidence.Run.Isolation.ProxmoxTLSCASHA256 != "" && !isSHA256Digest(evidence.Run.Isolation.ProxmoxTLSCASHA256) {
		return errors.New("evidence verified TLS receipt is invalid")
	}
	if strings.TrimSpace(evidence.Run.Runtime.OpenClawVersion) == "" || strings.TrimSpace(evidence.Run.Runtime.StraceVersion) == "" || strings.TrimSpace(evidence.Run.Runtime.ModelProvider) == "" || strings.TrimSpace(evidence.Run.Runtime.ModelID) == "" || strings.TrimSpace(evidence.Run.Runtime.ModelEndpoint) == "" {
		return errors.New("evidence runtime receipt is incomplete")
	}
	// ModelRelay is mandatory for capture protocol v20 and later through
	// BuildEvidence's containment profile. Keep it optional for older v2
	// artifacts, whose profile predates the bounded relay.
	boundedRelayProfile := strings.Contains(evidence.Run.Isolation.ContainmentProfile, "bounded-model-relay")
	if boundedRelayProfile && evidence.ModelRelay == nil {
		return errors.New("evidence bounded model relay receipt is required")
	}
	if evidence.ModelRelay != nil {
		if err := validateModelRelayEvidence(evidence.ModelRelay); err != nil {
			return err
		}
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
	hasCanaryStageEvidence := evidence.Coverage.CanaryStages != nil
	for _, canary := range evidence.Canaries {
		hasCanaryStageEvidence = hasCanaryStageEvidence || canary.Class != "" || canary.Stages != nil
	}
	// Canary-stage fields are an additive v2 extension. Previously emitted v2
	// artifacts have none of these fields and must remain readable. Once any
	// extension field is present, validate the complete extension atomically.
	if hasCanaryStageEvidence {
		if evidence.Coverage.CanaryStages == nil {
			return errors.New("evidence canary stage coverage is required")
		}
		pairedTraceCoverage := evidence.Coverage.BaselinePaired && evidence.Coverage.FileSyscalls && evidence.Coverage.ProcessSyscalls && evidence.Coverage.NetworkSyscalls
		pairedSinkCoverage := evidence.MockEgress != nil && (evidence.MockEgress.CaptureComplete || evidence.ModelRelay == nil)
		if err := validateCanaryStageCoverage(evidence.Coverage.CanaryStages, pairedTraceCoverage, pairedSinkCoverage); err != nil {
			return err
		}
		if evidence.Coverage.BaselinePaired != evidence.Coverage.FileSyscalls ||
			evidence.Coverage.BaselinePaired != evidence.Coverage.ProcessSyscalls ||
			evidence.Coverage.BaselinePaired != evidence.Coverage.NetworkSyscalls {
			return errors.New("evidence syscall and paired-trace coverage is inconsistent")
		}
		for _, index := range []int{0, 1, 2} {
			if (evidence.Coverage.CanaryStages[index].Coverage == "observed") != pairedTraceCoverage {
				return errors.New("evidence canary trace-stage coverage is inconsistent")
			}
		}
	}
	hasRedirectEvidence := evidence.RedirectProbes != nil || evidence.Coverage.RedirectProbeScope != "" ||
		evidence.Coverage.RedirectProbeCount != 0 || evidence.Coverage.RedirectProbesExercised != 0 || evidence.Coverage.RedirectDeepMode
	if evidence.SchemaVersion == EvidenceSchemaVersion || hasRedirectEvidence {
		if evidence.RedirectProbes == nil {
			return errors.New("evidence redirect probes are required")
		}
		if evidence.Coverage.RedirectProbeScope != RedirectProbeScope {
			return errors.New("evidence redirect probe coverage scope is missing or unsupported")
		}
		if evidence.Coverage.RedirectProbeCount != len(evidence.RedirectProbes) {
			return errors.New("evidence redirect probe coverage count is inconsistent with its probe list")
		}
		exercisedProbes := 0
		for _, probe := range evidence.RedirectProbes {
			if probe.Exercised {
				exercisedProbes++
			}
		}
		if evidence.Coverage.RedirectProbesExercised != exercisedProbes {
			return errors.New("evidence redirect probe exposure coverage is inconsistent with its probe list")
		}
	}
	relayCaptureComplete := evidence.ModelRelay == nil || (!evidence.ModelRelay.Truncated && !evidence.ModelRelay.DeadlineHit &&
		evidence.ModelRelay.BaselineUpstreamErrors == 0 && evidence.ModelRelay.ExerciseUpstreamErrors == 0)
	completeCapture := evidence.Run.LaneExitCode == (LaneExitCodes{}) && evidence.Coverage.BaselinePaired &&
		evidence.Coverage.FileSyscalls && evidence.Coverage.ProcessSyscalls && evidence.Coverage.NetworkSyscalls && relayCaptureComplete
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
		if canary.ID == "" || canary.Surface == "" || canary.BaselineInteractions < 0 || canary.ExerciseInteractions < 0 ||
			canary.BaselineInteractions > maxCanaryInteractionCount || canary.ExerciseInteractions > maxCanaryInteractionCount ||
			canary.DeltaInteractions != expectedDelta {
			return errors.New("evidence contains an invalid canary observation")
		}
		if hasCanaryStageEvidence {
			if canary.Class != "identity" && canary.Class != "memory" && canary.Class != "credential" {
				return errors.New("evidence contains an invalid canary class")
			}
			if canary.Stages == nil {
				return errors.New("evidence canary stages are required")
			}
			if err := validateCanaryStages(canary.Stages); err != nil {
				return err
			}
			stageBaselineTotal := 0
			stageExerciseTotal := 0
			for _, stage := range canary.Stages {
				if stage.BaselineInteractions > canary.BaselineInteractions || stage.ExerciseInteractions > canary.ExerciseInteractions {
					return errors.New("evidence canary stage interactions exceed their aggregate canary counts")
				}
				stageBaselineTotal += stage.BaselineInteractions
				stageExerciseTotal += stage.ExerciseInteractions
			}
			if stageBaselineTotal < canary.BaselineInteractions || stageExerciseTotal < canary.ExerciseInteractions {
				return errors.New("evidence aggregate canary interactions lack complete stage accounting")
			}
		}
	}
	if err := validateMockEgressEvidence(evidence.MockEgress, boundedRelayProfile || evidence.ModelRelay != nil); err != nil {
		return err
	}
	hasPersistenceEvidence := evidence.Persistence.Scope != "" || evidence.Persistence.InventoryPaired ||
		evidence.Persistence.Surfaces != nil || evidence.Persistence.Findings != nil || evidence.Persistence.Limitations != nil
	if evidence.SchemaVersion == EvidenceSchemaVersion || hasPersistenceEvidence {
		if err := validatePersistenceEvidence(evidence.Persistence); err != nil {
			return err
		}
	}
	if evidence.SchemaVersion == EvidenceSchemaVersion || hasRedirectEvidence {
		seenRedirect := map[string]bool{}
		for _, probe := range evidence.RedirectProbes {
			if probe.ID == "" || seenRedirect[probe.ID] || probe.Surface == "" || (probe.Vector != "network" && probe.Vector != "file") {
				return errors.New("evidence contains an invalid redirect probe")
			}
			seenRedirect[probe.ID] = true
			if probe.ReadBaseline < 0 || probe.ReadExercise < 0 || probe.RepeatedBaseline < 0 || probe.RepeatedExercise < 0 || probe.DeviatedBaseline < 0 || probe.DeviatedExercise < 0 {
				return errors.New("evidence contains an invalid redirect probe count")
			}
			if probe.ReadDelta != deltaNonNegative(probe.ReadExercise, probe.ReadBaseline) ||
				probe.RepeatedDelta != deltaNonNegative(probe.RepeatedExercise, probe.RepeatedBaseline) ||
				probe.DeviatedDelta != deltaNonNegative(probe.DeviatedExercise, probe.DeviatedBaseline) {
				return errors.New("evidence redirect probe delta is inconsistent with its counts")
			}
			if probe.Escalation != redirectEscalation(probe.ReadExercise, probe.RepeatedExercise, probe.DeviatedExercise) ||
				probe.Attributed != redirectEscalation(probe.ReadDelta, probe.RepeatedDelta, probe.DeviatedDelta) {
				return errors.New("evidence redirect probe escalation is inconsistent with its counts")
			}
			if probe.Exercised != (probe.ReadExercise > 0) {
				return errors.New("evidence redirect probe exposure flag is inconsistent with its exercise-lane read")
			}
		}
	}
	hasRuntimeTimeline := evidence.RuntimeTimeline.MaxEventsPerLane != 0 || evidence.RuntimeTimeline.Baseline.Events != nil ||
		evidence.RuntimeTimeline.Exercise.Events != nil || evidence.RuntimeTimeline.Baseline.EventCount != 0 || evidence.RuntimeTimeline.Exercise.EventCount != 0
	if evidence.SchemaVersion == EvidenceSchemaVersion || hasRuntimeTimeline {
		if err := validateRuntimeTimeline(evidence.RuntimeTimeline); err != nil {
			return err
		}
	}
	hasToolCallLedger := evidence.ToolCallLedger.Source != "" || evidence.ToolCallLedger.MaxCallsPerLane != 0 ||
		evidence.ToolCallLedger.Baseline.Calls != nil || evidence.ToolCallLedger.Exercise.Calls != nil
	if evidence.SchemaVersion == EvidenceSchemaVersion || hasToolCallLedger {
		if err := validateToolCallLedger(evidence.ToolCallLedger); err != nil {
			return err
		}
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || len(encoded) > MaxEvidenceBytes {
		return fmt.Errorf("evidence exceeds maximum encoded size (%d bytes)", MaxEvidenceBytes)
	}
	return nil
}

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
		if stage.BaselineInteractions < 0 || stage.ExerciseInteractions < 0 ||
			stage.BaselineInteractions > maxCanaryInteractionCount || stage.ExerciseInteractions > maxCanaryInteractionCount ||
			stage.DeltaInteractions != expected {
			return errors.New("evidence contains an invalid canary stage interaction")
		}
		if stage.BaselineInteractions == 0 && stage.ExerciseInteractions == 0 {
			return errors.New("evidence canary stage has no interactions")
		}
		if stage.Stage == CanaryStageTool {
			return errors.New("evidence tool-stage interactions are unsupported by this capture protocol")
		}
	}
	return nil
}

func validateCanaryStageCoverage(coverage []CanaryStageCoverage, pairedTrace bool, pairedSinkReceipt bool) error {
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
	for index, entry := range coverage {
		if entry.Stage != canaryStageSequence[index] {
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
		if entry.Stage == CanaryStageOutbound && (entry.Source == "unavailable-or-unpaired") != (entry.Coverage == "limited") {
			return errors.New("evidence outbound coverage is inconsistent with its source")
		}
		if entry.Stage == CanaryStageAgentOutput && (entry.Source == "agent-command-stdout") != (entry.Coverage == "observed") {
			return errors.New("evidence agent-output coverage is inconsistent with its source")
		}
	}
	expectedOutbound := CanaryStageCoverage{Stage: CanaryStageOutbound, Coverage: "limited", Source: "unavailable-or-unpaired"}
	switch {
	case pairedTrace && pairedSinkReceipt:
		expectedOutbound.Coverage = "observed"
		expectedOutbound.Source = "socket-send-syscall-payload+typed-sink-receipt"
	case pairedTrace:
		expectedOutbound.Coverage = "observed"
		expectedOutbound.Source = "socket-send-syscall-payload"
	case pairedSinkReceipt:
		expectedOutbound.Coverage = "observed"
		expectedOutbound.Source = "typed-sink-receipt"
	}
	if coverage[3] != expectedOutbound {
		return errors.New("evidence outbound coverage is inconsistent with paired trace and typed-sink provenance")
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

func validatePersistenceEvidence(persistence PersistenceEvidence) error {
	if persistence.Scope != persistenceScope {
		return errors.New("evidence persistence scope is missing or unsupported")
	}
	if persistence.Surfaces == nil || persistence.Findings == nil || persistence.Limitations == nil {
		return errors.New("evidence persistence surfaces, findings, and limitations are required")
	}
	if len(persistence.Surfaces) == 0 {
		return errors.New("evidence persistence surface catalog is empty")
	}
	validSurfaceScope := map[string]bool{"agent": true, "user": true, "system": true}
	surfaceCategory := map[string]string{}
	for _, surface := range persistence.Surfaces {
		if !persistenceSurfaceIDPattern.MatchString(surface.ID) || surface.Category == "" || len(surface.Category) > 64 ||
			!validSurfaceScope[surface.Scope] || strings.TrimSpace(surface.Description) == "" ||
			len(surface.Description) > 200 || strings.ContainsAny(surface.Category+surface.Description, "\x00\r\n") {
			return errors.New("evidence persistence surface catalog is invalid")
		}
		if _, duplicate := surfaceCategory[surface.ID]; duplicate {
			return errors.New("evidence persistence surface catalog has duplicate identifiers")
		}
		surfaceCategory[surface.ID] = surface.Category
	}
	validOutcome := map[string]bool{"succeeded": true, "attempted": true}
	validEvidence := map[string]bool{"syscall": true, "inventory": true, "syscall+inventory": true}
	validResidual := map[string]bool{"confirmed": true, "not-observed": true, "unavailable": true}
	for _, finding := range persistence.Findings {
		category, known := surfaceCategory[finding.Surface]
		if !known || finding.Category != category {
			return errors.New("evidence persistence finding references an unknown surface")
		}
		if finding.Operation == "" || finding.Subject == "" || len(finding.Subject) > 512 ||
			strings.ContainsAny(finding.Subject, "\x00\r\n") || strings.Contains(finding.Subject, "OBS-CANARY-") {
			return errors.New("evidence contains an invalid persistence finding subject")
		}
		if !validOutcome[finding.Outcome] || !validEvidence[finding.Evidence] || !validResidual[finding.Residual] {
			return errors.New("evidence contains an invalid persistence finding classification")
		}
		expectedDelta := finding.ExerciseCount - finding.BaselineCount
		if finding.BaselineCount < 0 || finding.ExerciseCount < 0 || expectedDelta < 1 || finding.DeltaCount != expectedDelta {
			return errors.New("evidence contains an invalid persistence finding count")
		}
		// A confirmed residual must be backed by inventory; an inventory-backed
		// finding must be a confirmed, successful change. This keeps the
		// attempted-vs-residual distinction unambiguous for grading.
		inventoryBacked := finding.Evidence == "inventory" || finding.Evidence == "syscall+inventory"
		if (finding.Residual == "confirmed") != inventoryBacked {
			return errors.New("evidence persistence residual state is inconsistent with its evidence source")
		}
		if inventoryBacked && finding.Outcome != "succeeded" {
			return errors.New("evidence persistence inventory-confirmed finding must record a succeeded outcome")
		}
	}
	return nil
}

const ToolCallLedgerSource = "openclaw-audit-ledger"

var (
	toolCallStates = map[string]bool{
		"started": true, "succeeded": true, "failed": true, "cancelled": true,
		"timed_out": true, "blocked": true, "unknown": true,
	}
	toolCallErrorCodeByState = map[string]string{
		"started": "", "succeeded": "", "failed": "tool_failed", "cancelled": "tool_cancelled",
		"timed_out": "tool_timed_out", "blocked": "tool_blocked", "unknown": "tool_outcome_unknown",
	}
	toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
)

func validateToolCallLedger(ledger ToolCallLedger) error {
	if ledger.Source != ToolCallLedgerSource {
		return errors.New("evidence tool-call ledger source is missing or unsupported")
	}
	if ledger.MaxCallsPerLane != MaxToolCallsPerLane {
		return errors.New("evidence tool-call ledger per-lane bound is missing or unsupported")
	}
	if ledger.ArgumentSummaries.Available || strings.TrimSpace(ledger.ArgumentSummaries.Reason) == "" || len(ledger.ArgumentSummaries.Reason) > 400 ||
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
	if lane.Coverage != "incomplete" && lane.Coverage != "unavailable" {
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
	if len(lane.Reason) > 400 || strings.ContainsAny(lane.Reason, "\x00\r\n") {
		return errors.New("reason contains unsafe characters")
	}
	if strings.TrimSpace(lane.Reason) == "" {
		return errors.New("lane coverage reason is required")
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
	lastOffset := int64(-1)
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
		if call.ErrorCode != toolCallErrorCodeByState[call.State] {
			return errors.New("call state and error code are inconsistent")
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
	return nil
}

func validateRuntimeTimeline(timeline RuntimeTimeline) error {
	if timeline.MaxEventsPerLane != MaxRuntimeTimelineEventsPerLane {
		return errors.New("evidence runtimeTimeline per-lane event bound is missing or unsupported")
	}
	if err := validateRuntimeTimelineLane(timeline.Baseline); err != nil {
		return fmt.Errorf("evidence baseline runtimeTimeline is invalid: %w", err)
	}
	if err := validateRuntimeTimelineLane(timeline.Exercise); err != nil {
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
	lastOffset := int64(-1)
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

func validateDeclaredCapabilities(declared *DeclaredCapabilities) error {
	if declared == nil {
		return nil
	}
	if declared.Source != "plugin-manifest" && declared.Source != "skill-frontmatter" {
		return errors.New("evidence declared capabilities source is invalid")
	}
	seen := map[string]bool{}
	previous := ""
	for _, token := range declared.Capabilities {
		if !declaredCapabilityTokens[token] {
			return fmt.Errorf("evidence declares an unknown capability token: %s", token)
		}
		if seen[token] {
			return errors.New("evidence declared capabilities contain a duplicate token")
		}
		if token < previous {
			return errors.New("evidence declared capabilities must be sorted")
		}
		seen[token] = true
		previous = token
	}
	if !declared.Declared && len(declared.Capabilities) != 0 {
		return errors.New("evidence declared capabilities are present but marked as not declared")
	}
	for _, note := range declared.Notes {
		if strings.TrimSpace(note) == "" || len(note) > 200 || strings.ContainsAny(note, "\x00\r\n") {
			return errors.New("evidence declared capability note is invalid")
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
