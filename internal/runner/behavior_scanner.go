package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/openclaw/clawscan/internal/observatory"
)

var errInvalidBehaviorJSON = errors.New("Observatory behavior scanner returned invalid JSON")

const behaviorFailureMessage = "Observatory process exited nonzero; inspect its private run artifacts for details."

const defaultBehaviorScannerTimeout = 150 * time.Minute

func behaviorRequirements(env map[string]string) []EnvRequirement {
	return []EnvRequirement{{EnvVar: "CLAWSCAN_BEHAVIOR_CONFIG", Reason: "scanner behavior"}}
}

func (runner ExternalScannerRunner) runBehavior(target string, startedAt string) (ScannerResult, error) {
	completedAt := func() string { return time.Now().UTC().Format(time.RFC3339Nano) }
	if runner.SandboxMode == SandboxModeDocker {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Error:       "The behavior scanner provisions its own remote isolation boundary; rerun Clawscan with --sandbox off.",
		}, nil
	}
	command := strings.TrimSpace(runner.Env["CLAWSCAN_BEHAVIOR_BIN"])
	if command == "" {
		command = "observatory"
	}
	configPath := runner.Env["CLAWSCAN_BEHAVIOR_CONFIG"]
	args := []string{"scan", "--config", configPath, "--json", target}
	fullCommand := []string{filepath.Base(command), "scan", "--config", "[config]", "--json", "[target]"}
	timeout := runner.BehaviorTimeout
	if timeout == 0 {
		timeout = runner.Timeout
	}
	if timeout == 0 {
		timeout = defaultBehaviorScannerTimeout
	}
	output, runErr := runner.CommandRunner.Run(command, args, "", timeout)
	raw := strings.TrimSpace(output.Stdout)
	if runErr != nil {
		message := behaviorFailureMessage
		if _, canonical, valid := decodeBehaviorEvidence(raw); valid {
			return ScannerResult{
				Status:      "failed",
				StartedAt:   startedAt,
				CompletedAt: completedAt(),
				Command:     fullCommand,
				Error:       message,
				Raw:         canonical,
			}, nil
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     fullCommand,
			Error:       message,
		}, nil
	}
	if raw == "" {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     fullCommand,
			Error:       "Observatory behavior scanner did not return JSON on stdout.",
		}, nil
	}
	evidence, canonical, valid := decodeBehaviorEvidence(raw)
	if !valid {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     fullCommand,
			Error:       errInvalidBehaviorJSON.Error(),
		}, nil
	}
	if !behaviorEvidenceCompleted(evidence) {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     fullCommand,
			Error:       "Observatory returned incomplete behavior evidence.",
			Raw:         canonical,
		}, nil
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: completedAt(),
		Command:     fullCommand,
		Raw:         canonical,
	}, nil
}

func decodeBehaviorEvidence(raw string) (observatory.Evidence, json.RawMessage, bool) {
	if len(raw) == 0 || len(raw) > observatory.MaxEvidenceBytes {
		return observatory.Evidence{}, nil, false
	}
	var evidence observatory.Evidence
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return observatory.Evidence{}, nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return observatory.Evidence{}, nil, false
	}
	if observatory.ValidateEvidence(evidence) != nil {
		return observatory.Evidence{}, nil, false
	}
	canonical, err := json.Marshal(evidence)
	if err != nil || len(canonical) > observatory.MaxEvidenceBytes {
		return observatory.Evidence{}, nil, false
	}
	return evidence, json.RawMessage(canonical), true
}

func behaviorEvidenceCompleted(evidence observatory.Evidence) bool {
	return evidence.Run.Status == "completed" && evidence.Run.LaneExitCode.Baseline == 0 &&
		evidence.Run.LaneExitCode.Exercise == 0 && evidence.Coverage.BaselinePaired &&
		evidence.Coverage.FileSyscalls && evidence.Coverage.ProcessSyscalls && evidence.Coverage.NetworkSyscalls
}
