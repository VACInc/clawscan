package observatory

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanaryStageCorrelationClassifiesTraceStages(t *testing.T) {
	metadata := CaptureMetadata{
		BaselineWorkspace: "/run/baseline/workspace", ExerciseWorkspace: "/run/exercise/workspace",
		BaselineState: "/run/baseline/state", ExerciseState: "/run/exercise/state",
		BaselineHome: "/run/baseline/home", ExerciseHome: "/run/exercise/home",
		TargetKind: "skill", TargetRoot: "/run/exercise/workspace/skills/observed",
	}
	marker := testCanaryMarkers()["cloud-credentials"]
	baseline := `openat(AT_FDCWD, "/run/baseline/home/.aws/credentials", O_RDONLY) = 3` + "\n"
	exercise := `openat(AT_FDCWD, "/run/exercise/home/.aws/credentials", O_RDONLY) = 3
openat(AT_FDCWD, "/run/exercise/home/.aws/credentials", O_WRONLY|O_CREAT, 0600) = 4
truncate("/run/exercise/home/.aws/credentials", 0) = 0
execve("/run/exercise/home/.aws/credentials", ["x"], 0x0) = 0
sendto(5<TCP:[10.0.0.3:5000->93.184.216.34:443]>, "` + marker + `", 61, 0, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 61
`
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{baseline}, ExerciseTraces: []string{exercise},
		Metadata: metadata, Canaries: testCanaries(), ControlPlaneAddresses: []string{"10.0.0.2:8000"},
	})
	cloud := findCanary(result.Canaries, "cloud-credentials")
	if cloud.Class != "credential" || cloud.BaselineInteractions != 1 || cloud.ExerciseInteractions != 5 || cloud.DeltaInteractions != 4 {
		t.Fatalf("cloud canary = %#v", cloud)
	}
	want := map[string][3]int{
		CanaryStageRead: {1, 1, 0}, CanaryStageWrite: {0, 2, 2},
		CanaryStageExecute: {0, 1, 1}, CanaryStageOutbound: {0, 1, 1},
	}
	for stage, counts := range want {
		got := findCanaryStageForTest(cloud.Stages, stage)
		if [3]int{got.BaselineInteractions, got.ExerciseInteractions, got.DeltaInteractions} != counts {
			t.Fatalf("stage %q = %#v, want %v", stage, got, counts)
		}
		if coverage := canaryCoverageForTest(result.Coverage.CanaryStages, stage); coverage.Coverage != "observed" {
			t.Fatalf("stage %q coverage = %#v", stage, coverage)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("OBS-CANARY")) {
		t.Fatalf("canary marker leaked: %s", encoded)
	}
}

func TestCanaryAgentOutputNeverBecomesToolEvidence(t *testing.T) {
	marker := testCanaryMarkers()["workspace-memory"]
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{`execve("/usr/bin/node", ["node"], 0x0) = 0`},
		ExerciseTraces: []string{`execve("/usr/bin/node", ["node"], 0x0) = 0`},
		Metadata:       CaptureMetadata{TargetKind: "skill"}, Canaries: testCanaries(),
		BaselineAgentOutputs: clonePrivatePayloads(nil),
		ExerciseAgentOutputs: clonePrivatePayloads([]byte("answer " + marker + " " + marker)),
	})
	memory := findCanary(result.Canaries, "workspace-memory")
	if memory.BaselineInteractions != 0 || memory.ExerciseInteractions != 2 || memory.DeltaInteractions != 2 {
		t.Fatalf("agent-output aggregate = %#v", memory)
	}
	output := findCanaryStageForTest(memory.Stages, CanaryStageAgentOutput)
	if output.ExerciseInteractions != 2 || output.DeltaInteractions != 2 {
		t.Fatalf("agent-output stage = %#v", output)
	}
	if tool := findCanaryStageForTest(memory.Stages, CanaryStageTool); tool.Stage != "" {
		t.Fatalf("stdout became tool evidence: %#v", tool)
	}
	if coverage := canaryCoverageForTest(result.Coverage.CanaryStages, CanaryStageTool); coverage.Coverage != "limited" {
		t.Fatalf("tool coverage = %#v", coverage)
	}
}

func TestIncompleteSinkReceiptCannotProvideCanaryCoverage(t *testing.T) {
	marker := testCanaryMarkers()["cloud-credentials"]
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces:               []string{`getpid() = 100`},
		ExerciseTraces:               []string{`getpid() = 101`},
		Metadata:                     CaptureMetadata{TargetKind: "skill"},
		Canaries:                     testCanaries(),
		BaselineSinkPayloads:         clonePrivatePayloads(nil),
		ExerciseSinkPayloads:         clonePrivatePayloads([]byte(marker)),
		BaselineSinkPayloadsPresent:  true,
		ExerciseSinkPayloadsPresent:  true,
		BaselineSinkPayloadsComplete: true,
		ExerciseSinkPayloadsComplete: false,
	})
	if outbound := findCanaryStageForTest(findCanary(result.Canaries, "cloud-credentials").Stages, CanaryStageOutbound); outbound.Stage != "" {
		t.Fatalf("incomplete sink payload became canary evidence: %#v", outbound)
	}
	coverage := canaryCoverageForTest(result.Coverage.CanaryStages, CanaryStageOutbound)
	if coverage.Coverage != "observed" || coverage.Source != "socket-send-syscall-payload" {
		t.Fatalf("incomplete sink did not downgrade to syscall-only coverage: %#v", coverage)
	}
}

func TestCanaryMarkerOperandsDoNotOverstateExecuteOrStdoutWrite(t *testing.T) {
	marker := testCanaryMarkers()["workspace-memory"]
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{`execve("/bin/echo", ["echo"], 0x0) = 0`},
		ExerciseTraces: []string{
			`execve("/bin/echo", ["echo", "` + marker + `"], 0x0) = 0` + "\n" +
				`execve(NULL, ["` + marker + `"], 0x0) = -1 EFAULT (Bad address)` + "\n" +
				`write(1</dev/null>, "` + marker + `", 61) = 61` + "\n" +
				`sendto(5<UNIX:[1]>, NULL, 0, 0, {sa_family=AF_UNIX, sun_path="@` + marker + `"}, 64) = 0`,
		},
		Metadata: CaptureMetadata{TargetKind: "skill"}, Canaries: testCanaries(),
		BaselineAgentOutputs: clonePrivatePayloads(nil),
		ExerciseAgentOutputs: clonePrivatePayloads([]byte(marker)),
	})
	memory := findCanary(result.Canaries, "workspace-memory")
	if execute := findCanaryStageForTest(memory.Stages, CanaryStageExecute); execute.Stage != "" {
		t.Fatalf("argv marker became execute evidence: %#v", execute)
	}
	if write := findCanaryStageForTest(memory.Stages, CanaryStageWrite); write.Stage != "" {
		t.Fatalf("stdout marker became write evidence: %#v", write)
	}
	if outbound := findCanaryStageForTest(memory.Stages, CanaryStageOutbound); outbound.Stage != "" {
		t.Fatalf("sockaddr marker became outbound payload evidence: %#v", outbound)
	}
	if output := findCanaryStageForTest(memory.Stages, CanaryStageAgentOutput); output.ExerciseInteractions != 1 {
		t.Fatalf("agent-output evidence = %#v", output)
	}
	if memory.ExerciseInteractions != 1 || memory.DeltaInteractions != 1 {
		t.Fatalf("aggregate = %#v", memory)
	}
}

func TestFailedCanaryPropagationSyscallsAreNotConfirmed(t *testing.T) {
	marker := testCanaryMarkers()["cloud-credentials"]
	metadata := CaptureMetadata{
		BaselineHome: "/run/baseline/home", ExerciseHome: "/run/exercise/home",
		TargetKind: "skill",
	}
	exercise := strings.Join([]string{
		`execve("/run/exercise/home/.aws/credentials", ["x"], 0x0) = -1 EACCES (Permission denied)`,
		`execve("` + marker + `", ["x"], 0x0) = -1 EPERM (Operation not permitted)`,
		`sendto(5<TCP:[10.0.0.3:5000->93.184.216.34:443]>, "` + marker + `", 61, 0, NULL, 0) = -1 EPERM (Operation not permitted)`,
		`sendmsg(5<TCP:[10.0.0.3:5000->93.184.216.34:443]>, {msg_iov=[{iov_base="` + marker + `", iov_len=61}], msg_iovlen=1}, 0) = -1 EPIPE (Broken pipe)`,
		`write(5<TCP:[10.0.0.3:5000->93.184.216.34:443]>, "` + marker + `", 61) = -1 EPIPE (Broken pipe)`,
	}, "\n")
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{`getpid() = 100`}, ExerciseTraces: []string{exercise},
		Metadata: metadata, Canaries: testCanaries(),
	})
	cloud := findCanary(result.Canaries, "cloud-credentials")
	if cloud.ExerciseInteractions != 0 || cloud.DeltaInteractions != 0 {
		t.Fatalf("failed propagation became confirmed canary evidence: %#v", cloud)
	}
	for _, stage := range []string{CanaryStageExecute, CanaryStageOutbound} {
		if got := findCanaryStageForTest(cloud.Stages, stage); got.Stage != "" {
			t.Fatalf("failed syscall became %s evidence: %#v", stage, got)
		}
	}
}

func TestBuildEvidenceUsesOnlyVerifiedCanonicalSinkPayloads(t *testing.T) {
	config := validTestConfig(t, t.TempDir())
	config.Runtime.MockEgress = MockEgressConfig{
		Enabled: true, Address: "127.0.0.9:9009", MaxRequests: 8,
		MaxBytesPerRequest: 4096, MaxTotalBytes: 8192, DeadlineSeconds: 5,
	}
	configSHA, err := captureConfigSHA256(config)
	if err != nil {
		t.Fatal(err)
	}
	marker := testCanaryMarkers()["cloud-credentials"]
	payload := []byte("owned-fixture-private-payload:" + marker)
	entries := fixtureBundleEntries("obs_verified_sink", "sha256:"+strings.Repeat("a", 64), configSHA, "skill", "")
	entries["exercise/trace"] += `sendto(5<TCP:[127.0.0.1:5000->127.0.0.9:9009]>, "` + marker + `", 61, 0, {sa_family=AF_INET, sin_port=htons(9009), sin_addr=inet_addr("127.0.0.9")}, 16) = 61` + "\n"
	entries["baseline/mock-egress.json"] = mockEgressReceiptJSON("127.0.0.9", 9009, "baseline", 0, nil)
	entries["exercise/mock-egress.json"] = mockEgressReceiptJSON("127.0.0.9", 9009, "exercise", 1, payload)
	bundlePath := filepath.Join(t.TempDir(), "capture.tar.gz")
	if err := writeTestBundle(bundlePath, entries); err != nil {
		t.Fatal(err)
	}
	bundle, err := ReadCaptureBundle(bundlePath, config.Limits.MaxBundleBytes)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := BuildEvidence(fixtureEvidence().Target, config, bundle)
	if err != nil {
		t.Fatal(err)
	}
	cloud := findCanary(evidence.Canaries, "cloud-credentials")
	outbound := findCanaryStageForTest(cloud.Stages, CanaryStageOutbound)
	if outbound.ExerciseInteractions != 1 || outbound.DeltaInteractions != 1 {
		t.Fatalf("trace and canonical receipt were not deduplicated: %#v", outbound)
	}
	// The owned fixture also reads the canary once. Aggregate counts therefore
	// contain one read plus one deduplicated controlled-sink transmission.
	if cloud.ExerciseInteractions != 2 || cloud.DeltaInteractions != 2 {
		t.Fatalf("canonical sink aggregate = %#v", cloud)
	}
	coverage := canaryCoverageForTest(evidence.Coverage.CanaryStages, CanaryStageOutbound)
	if coverage.Coverage != "observed" || coverage.Source != "socket-send-syscall-payload+typed-sink-receipt" {
		t.Fatalf("outbound coverage = %#v", coverage)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range [][]byte{payload, []byte(marker), []byte("127.0.0.9")} {
		if bytes.Contains(encoded, private) {
			t.Fatalf("public evidence leaked private sink material %q: %s", private, encoded)
		}
	}
	// Exported BuildEvidence also supports programmatic bundles. Nonempty output
	// predating the explicit presence flag must still feed agent-output.
	bundle.ExerciseOutput = []byte(marker)
	bundle.ExerciseOutputPresent = false
	programmatic, err := BuildEvidence(fixtureEvidence().Target, config, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if output := findCanaryStageForTest(findCanary(programmatic.Canaries, "cloud-credentials").Stages, CanaryStageAgentOutput); output.ExerciseInteractions != 1 {
		t.Fatalf("programmatic output stage = %#v", output)
	}
	for _, test := range []struct {
		name   string
		mutate func(*MockEgressReceipt)
	}{
		{"truncated", func(receipt *MockEgressReceipt) { receipt.Truncated = true }},
		{"deadline", func(receipt *MockEgressReceipt) { receipt.DeadlineHit = true }},
		{"rejected", func(receipt *MockEgressReceipt) { receipt.RejectedRequests = 1 }},
	} {
		t.Run("incomplete receipt/"+test.name, func(t *testing.T) {
			partial := bundle
			receipt := *bundle.MockEgressExercise
			test.mutate(&receipt)
			partial.MockEgressExercise = &receipt
			partialEvidence, err := BuildEvidence(fixtureEvidence().Target, config, partial)
			if err != nil {
				t.Fatal(err)
			}
			coverage := canaryCoverageForTest(partialEvidence.Coverage.CanaryStages, CanaryStageOutbound)
			if coverage.Source != "socket-send-syscall-payload" || partialEvidence.MockEgress.CaptureComplete || len(partialEvidence.MockEgress.CanariesObserved) != 0 {
				t.Fatalf("incomplete receipt retained typed-sink coverage: coverage=%#v sink=%#v", coverage, partialEvidence.MockEgress)
			}
			if err := ValidateEvidence(partialEvidence); err != nil {
				t.Fatalf("incomplete receipt evidence failed validation: %v", err)
			}
		})
	}
	bundle.MockEgressExercise.Lane = "baseline"
	if _, err := BuildEvidence(fixtureEvidence().Target, config, bundle); err == nil || !strings.Contains(err.Error(), "lane mismatch") {
		t.Fatalf("unverified typed receipt err = %v", err)
	}
}

func TestCanaryCorrelationBoundsPrivateStreams(t *testing.T) {
	marker := testCanaryMarkers()["cloud-credentials"]
	flood := strings.Repeat(marker+" ", maxCanaryInteractionCount+16)
	result := AnalyzeTraces(AnalysisInput{
		Metadata: CaptureMetadata{TargetKind: "skill"}, Canaries: testCanaries(),
		ExerciseAgentOutputs: clonePrivatePayloads([]byte(flood)),
	})
	stage := findCanaryStageForTest(findCanary(result.Canaries, "cloud-credentials").Stages, CanaryStageAgentOutput)
	want := bytes.Count([]byte(flood[:maxCanaryScanBytes]), []byte(marker))
	if stage.ExerciseInteractions != want || stage.DeltaInteractions != want {
		t.Fatalf("bounded stage = %#v, want %d", stage, want)
	}
	cloud := findCanary(result.Canaries, "cloud-credentials")
	if cloud.ExerciseInteractions != want || cloud.DeltaInteractions != want {
		t.Fatalf("bounded aggregate = %#v, want %d", cloud, want)
	}
	if coverage := canaryCoverageForTest(result.Coverage.CanaryStages, CanaryStageAgentOutput); coverage.Coverage != "limited" {
		t.Fatalf("bounded coverage = %#v", coverage)
	}
}

func TestPreviouslyEmittedV2EvidenceWithoutCanaryStagesRemainsReadable(t *testing.T) {
	evidence := fixtureEvidence()
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	delete(document["coverage"].(map[string]any), "canaryStages")
	for _, rawCanary := range document["canaries"].([]any) {
		canary := rawCanary.(map[string]any)
		delete(canary, "class")
		delete(canary, "stages")
	}
	encoded, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEvidence(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode prior v2 evidence: %v", err)
	}
	output := t.TempDir()
	if err := RenderSite(output, decoded, nil); err != nil {
		t.Fatalf("render prior v2 evidence: %v", err)
	}
	if _, err := LoadEvidence(filepath.Join(output, "evidence.json")); err != nil {
		t.Fatalf("reload rendered prior v2 evidence: %v", err)
	}
}

func TestValidateEvidenceRejectsForgedCanaryCoverage(t *testing.T) {
	evidence := fixtureEvidence()
	evidence.Canaries[0].BaselineInteractions = 0
	evidence.Canaries[0].ExerciseInteractions = 1
	evidence.Canaries[0].DeltaInteractions = 1
	evidence.Canaries[0].Stages = []CanaryStageInteraction{{Stage: CanaryStageTool, ExerciseInteractions: 1, DeltaInteractions: 1}}
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "tool-stage interactions are unsupported") {
		t.Fatalf("tool interaction err = %v", err)
	}
	evidence = fixtureEvidence()
	evidence.Canaries[0].Stages = []CanaryStageInteraction{{Stage: CanaryStageRead, ExerciseInteractions: 1, DeltaInteractions: 1}}
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "exceed their aggregate") {
		t.Fatalf("aggregate mismatch err = %v", err)
	}
	evidence = fixtureEvidence()
	evidence.Canaries[0].ExerciseInteractions = 1
	evidence.Canaries[0].DeltaInteractions = 1
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "lack complete stage accounting") {
		t.Fatalf("missing stage accounting err = %v", err)
	}
	evidence = fixtureEvidence()
	evidence.Coverage.CanaryStages[5].Coverage = "observed"
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "cannot be authoritative") {
		t.Fatalf("tool coverage err = %v", err)
	}
	evidence = fixtureEvidence()
	evidence.Coverage.CanaryStages[3].Source = "unavailable-or-unpaired"
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "outbound coverage is inconsistent") {
		t.Fatalf("outbound coverage err = %v", err)
	}
	evidence = fixtureEvidence()
	evidence.Coverage.CanaryStages[3].Source = "socket-send-syscall-payload+typed-sink-receipt"
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "typed-sink provenance") {
		t.Fatalf("forged sink provenance err = %v", err)
	}
}

func findCanaryStageForTest(stages []CanaryStageInteraction, name string) CanaryStageInteraction {
	for _, stage := range stages {
		if stage.Stage == name {
			return stage
		}
	}
	return CanaryStageInteraction{}
}

func canaryCoverageForTest(coverage []CanaryStageCoverage, stage string) CanaryStageCoverage {
	for _, entry := range coverage {
		if entry.Stage == stage {
			return entry
		}
	}
	return CanaryStageCoverage{}
}
