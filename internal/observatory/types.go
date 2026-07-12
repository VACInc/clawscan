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

type Evidence struct {
	SchemaVersion       string                     `json:"schemaVersion"`
	CaptureConfigSHA256 string                     `json:"captureConfigSha256"`
	Target              TargetEvidence             `json:"target"`
	Run                 RunEvidence                `json:"run"`
	Exercise            ExerciseEvidence           `json:"exercise"`
	Observations        []Observation              `json:"observations"`
	Canaries            []CanaryObservation        `json:"canaries"`
	RedirectProbes      []RedirectProbeObservation `json:"redirectProbes"`
	Coverage            CoverageEvidence           `json:"coverage"`
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
	SyscallScope            string   `json:"syscallScope"`
	FileSyscalls            bool     `json:"fileSyscalls"`
	ProcessSyscalls         bool     `json:"processSyscalls"`
	NetworkSyscalls         bool     `json:"networkSyscalls"`
	BaselinePaired          bool     `json:"baselinePaired"`
	RedirectProbeScope      string   `json:"redirectProbeScope"`
	RedirectProbeCount      int      `json:"redirectProbeCount"`
	RedirectProbesExercised int      `json:"redirectProbesExercised"`
	RedirectDeepMode        bool     `json:"redirectDeepMode"`
	Limitations             []string `json:"limitations"`
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
	Redirects         []RedirectProbeDefinition
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
	if evidence.Observations == nil || evidence.Canaries == nil || evidence.RedirectProbes == nil || evidence.Coverage.Limitations == nil {
		return errors.New("evidence observations, canaries, redirect probes, and coverage are required")
	}
	if evidence.Coverage.SyscallScope != "selected-mvp-syscalls" {
		return errors.New("evidence syscall coverage scope is missing or unsupported")
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
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || len(encoded) > MaxEvidenceBytes {
		return fmt.Errorf("evidence exceeds maximum encoded size (%d bytes)", MaxEvidenceBytes)
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
