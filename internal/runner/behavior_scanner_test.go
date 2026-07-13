package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const behaviorFixture = `{
  "schemaVersion":"observatory.behavior.v1",
  "captureConfigSha256":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "target":{"name":"demo","kind":"skill","id":"demo","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","fileCount":1,"directoryCount":1,"totalBytes":7,"files":[{"path":"SKILL.md","bytes":7,"mode":"0644"}],"directories":[{"path":".","mode":"0755"}]},
  "run":{"id":"obs_test","status":"completed","startedAt":"2026-07-10T12:00:00Z","completedAt":"2026-07-10T12:00:01Z","durationMs":1000,"executor":"fixture","isolation":{"substrate":"fixture","networkMode":"none","containmentProfile":"fixture","guestFirewallSha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","guestFirewallPolicySha256":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","verification":"fixture"},"runtime":{"openclawVersion":"OpenClaw fixture","straceVersion":"strace fixture","modelProvider":"fixture","modelId":"fixture","modelEndpoint":"private"},"laneExitCode":{"baseline":0,"exercise":0}},
  "exercise":{"promptSha256":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","turnLimit":1},
  "observations":[],"canaries":[],
  "coverage":{"syscallScope":"selected-mvp-syscalls","fileSyscalls":true,"processSyscalls":true,"networkSyscalls":true,"baselinePaired":true,"canaryStages":[{"stage":"read","coverage":"observed","source":"file-open-and-descriptor-syscall-trace"},{"stage":"write","coverage":"observed","source":"file-mutation-syscall-trace"},{"stage":"execute","coverage":"observed","source":"exec-syscall-trace"},{"stage":"outbound","coverage":"observed","source":"socket-send-syscall-payload"},{"stage":"agent-output","coverage":"observed","source":"agent-command-stdout"},{"stage":"tool","coverage":"limited","source":"openclaw-audit-metadata-no-bounded-args-results"}],"limitations":[]}
}`

func TestParseArgsAcceptsBehaviorScanner(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "behavior", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(opts.Scanners, ","); got != "behavior" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestValidateRequirementsRequiresBehaviorConfig(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "behavior", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequirements(opts, map[string]string{}); err == nil || !strings.Contains(err.Error(), "CLAWSCAN_BEHAVIOR_CONFIG required by scanner behavior") {
		t.Fatalf("err = %v", err)
	}
}

func TestBehaviorScannerRequiresHostSideClawscanMode(t *testing.T) {
	runner := &behaviorRecordingRunner{stdout: behaviorFixture}
	result, err := (ExternalScannerRunner{
		CommandRunner: runner,
		Env:           map[string]string{"CLAWSCAN_BEHAVIOR_CONFIG": "/private/config.yml"},
		SandboxMode:   SandboxModeDocker,
	}).runBehavior("/tmp/skill", "2026-07-10T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "--sandbox off") {
		t.Fatalf("result = %#v", result)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unexpected command calls: %#v", runner.calls)
	}
}

func TestRunExecutesBehaviorScannerAndPreservesEvidence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	recorder := &behaviorRecordingRunner{stdout: behaviorFixture}
	opts, err := ParseArgs([]string{dir, "--scanner", "behavior", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{
			"CLAWSCAN_BEHAVIOR_CONFIG": "/private/config.yml",
			"CLAWSCAN_BEHAVIOR_BIN":    "/opt/observatory",
		},
		CommandRunner: recorder,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["behavior"]
	_, canonicalFixture, validFixture := decodeBehaviorEvidence(behaviorFixture)
	if !validFixture {
		t.Fatal("behavior fixture is invalid")
	}
	if result.Status != "completed" || !bytes.Equal(result.Raw, canonicalFixture) {
		t.Fatalf("result = %#v", result)
	}
	if len(recorder.calls) != 1 {
		t.Fatalf("calls = %#v", recorder.calls)
	}
	call := recorder.calls[0]
	if call.command != "/opt/observatory" || strings.Join(call.args, " ") != "scan --config /private/config.yml --json "+dir {
		t.Fatalf("call = %#v", call)
	}
	if call.timeout != defaultBehaviorScannerTimeout {
		t.Fatalf("timeout = %s", call.timeout)
	}
	if strings.Join(result.Command, " ") != "observatory scan --config [config] --json [target]" {
		t.Fatalf("recorded command = %#v", result.Command)
	}
	rawArtifact, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawArtifact, []byte("/private/config.yml")) {
		t.Fatalf("artifact leaked config path: %s", rawArtifact)
	}
	if bytes.Contains(rawArtifact, []byte("/opt/observatory")) {
		t.Fatalf("artifact leaked scanner binary path: %s", rawArtifact)
	}
}

func TestBehaviorScannerRejectsUnknownPrivateFields(t *testing.T) {
	withTranscript := strings.TrimSuffix(behaviorFixture, "}") + `,"transcript":"private"}`
	result, err := (ExternalScannerRunner{
		CommandRunner: &behaviorRecordingRunner{stdout: withTranscript},
		Env:           map[string]string{"CLAWSCAN_BEHAVIOR_CONFIG": "/private/config.yml"},
		SandboxMode:   SandboxModeOff,
	}).runBehavior("/tmp/skill", "2026-07-10T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || len(result.Raw) != 0 || result.Error != errInvalidBehaviorJSON.Error() {
		t.Fatalf("result = %#v", result)
	}
}

func TestBehaviorScannerHonorsExplicitTimeout(t *testing.T) {
	recorder := &behaviorRecordingRunner{stdout: behaviorFixture}
	_, err := (ExternalScannerRunner{
		CommandRunner: recorder,
		Env:           map[string]string{"CLAWSCAN_BEHAVIOR_CONFIG": "/private/config.yml"},
		SandboxMode:   SandboxModeOff,
		Timeout:       7 * time.Minute,
	}).runBehavior("/tmp/skill", "2026-07-10T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.calls) != 1 || recorder.calls[0].timeout != 7*time.Minute {
		t.Fatalf("calls = %#v", recorder.calls)
	}
}

func TestBehaviorScannerPreservesValidEvidenceOnNonzeroExit(t *testing.T) {
	result, err := (ExternalScannerRunner{
		CommandRunner: &behaviorRecordingRunner{stdout: behaviorFixture, stderr: "lane incomplete", err: errors.New("exit status 1")},
		Env:           map[string]string{"CLAWSCAN_BEHAVIOR_CONFIG": "/private/config.yml"},
		SandboxMode:   SandboxModeOff,
	}).runBehavior("/tmp/skill", "2026-07-10T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || len(result.Raw) == 0 || result.Error != behaviorFailureMessage {
		t.Fatalf("result = %#v", result)
	}
}

func TestBehaviorScannerPreservesButFailsIncompleteEvidence(t *testing.T) {
	incomplete := strings.Replace(behaviorFixture, `"status":"completed"`, `"status":"incomplete"`, 1)
	incomplete = strings.Replace(incomplete, `"baselinePaired":true`, `"baselinePaired":false`, 1)
	for _, field := range []string{"fileSyscalls", "processSyscalls", "networkSyscalls"} {
		incomplete = strings.Replace(incomplete, `"`+field+`":true`, `"`+field+`":false`, 1)
	}
	for _, stage := range []string{"read", "write", "execute"} {
		incomplete = strings.Replace(incomplete, `"stage":"`+stage+`","coverage":"observed"`, `"stage":"`+stage+`","coverage":"limited"`, 1)
	}
	incomplete = strings.Replace(incomplete, `"stage":"outbound","coverage":"observed","source":"socket-send-syscall-payload"`, `"stage":"outbound","coverage":"limited","source":"unavailable-or-unpaired"`, 1)
	result, err := (ExternalScannerRunner{
		CommandRunner: &behaviorRecordingRunner{stdout: incomplete, err: errors.New("exit status 1")},
		Env:           map[string]string{"CLAWSCAN_BEHAVIOR_CONFIG": "/private/config.yml"},
		SandboxMode:   SandboxModeOff,
	}).runBehavior("/tmp/skill", "2026-07-10T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || len(result.Raw) == 0 || result.Error != behaviorFailureMessage {
		t.Fatalf("result = %#v", result)
	}
}

func TestBehaviorScannerRejectsWrongSchema(t *testing.T) {
	result, err := (ExternalScannerRunner{
		CommandRunner: &behaviorRecordingRunner{stdout: `{"schemaVersion":"other"}`},
		Env:           map[string]string{"CLAWSCAN_BEHAVIOR_CONFIG": "/private/config.yml"},
		SandboxMode:   SandboxModeOff,
	}).runBehavior("/tmp/skill", "2026-07-10T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || result.Error != errInvalidBehaviorJSON.Error() {
		t.Fatalf("result = %#v", result)
	}
}

func TestBehaviorScannerRejectsIncompleteMatchingSchema(t *testing.T) {
	result, err := (ExternalScannerRunner{
		CommandRunner: &behaviorRecordingRunner{stdout: `{"schemaVersion":"observatory.behavior.v1"}`},
		Env:           map[string]string{"CLAWSCAN_BEHAVIOR_CONFIG": "/private/config.yml"},
		SandboxMode:   SandboxModeOff,
	}).runBehavior("/tmp/skill", "2026-07-10T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || result.Error != errInvalidBehaviorJSON.Error() {
		t.Fatalf("result = %#v", result)
	}
}

func TestBehaviorScannerRedactsPathsFromCommandErrors(t *testing.T) {
	target := "/home/example/private/skill"
	config := "/home/example/private/config.yml"
	artifacts := "/srv/private-customer/observatory/obs_123"
	binary := "/opt/private-tools/observatory"
	result, err := (ExternalScannerRunner{
		CommandRunner: &behaviorRecordingRunner{stderr: "run_directory: " + artifacts + "\ninspect capture bundle: stat " + artifacts + "/capture.tar.gz\nfailed at " + target + " using " + config, err: errors.New("fork/exec " + binary + ": exit status 1")},
		Env:           map[string]string{"CLAWSCAN_BEHAVIOR_CONFIG": config, "CLAWSCAN_BEHAVIOR_BIN": binary},
		SandboxMode:   SandboxModeOff,
	}).runBehavior(target, "2026-07-10T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Error != behaviorFailureMessage || strings.Contains(result.Error, "/home/example") || strings.Contains(result.Error, artifacts) || strings.Contains(result.Error, binary) {
		t.Fatalf("error = %q", result.Error)
	}
}

type behaviorCommandCall struct {
	command string
	args    []string
	cwd     string
	timeout time.Duration
}

type behaviorRecordingRunner struct {
	calls  []behaviorCommandCall
	stdout string
	stderr string
	err    error
}

func (runner *behaviorRecordingRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	runner.calls = append(runner.calls, behaviorCommandCall{command: command, args: append([]string(nil), args...), cwd: cwd, timeout: timeout})
	return CommandOutput{Stdout: runner.stdout, Stderr: runner.stderr}, runner.err
}
