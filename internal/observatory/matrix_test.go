package observatory

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var (
	matrixCAOnce sync.Once
	matrixCAPEM  []byte
)

func sharedMatrixCAPEM(t *testing.T) []byte {
	t.Helper()
	matrixCAOnce.Do(func() {
		matrixCAPEM = append([]byte(nil), testCAPEM(t, "matrix-shared-ca")...)
	})
	return append([]byte(nil), matrixCAPEM...)
}

func matrixTestConfig(t *testing.T, variants ...MatrixVariant) Config {
	t.Helper()
	config := validTestConfig(t, t.TempDir())
	config.Matrix = MatrixConfig{Variants: variants}
	return config
}

func matrixFixtureTarget() string {
	return filepath.Join("..", "..", "testdata", "fixtures", "probe-skill")
}

func TestMatrixConfigRejectsInvalidVariants(t *testing.T) {
	tests := []struct {
		name     string
		variants []MatrixVariant
		want     string
	}{
		{
			name:     "too few",
			variants: []MatrixVariant{{ID: "only", Model: ModelConfig{ID: "solo"}}},
			want:     "at least 2 variants",
		},
		{
			name: "too many",
			variants: func() []MatrixVariant {
				many := make([]MatrixVariant, MaxMatrixVariants+1)
				for i := range many {
					many[i] = MatrixVariant{ID: string(rune('a'+i)) + "-variant", Model: ModelConfig{ID: string(rune('a'+i)) + "-model"}}
				}
				return many
			}(),
			want: "at most 8 variants",
		},
		{
			name:     "duplicate id",
			variants: []MatrixVariant{{ID: "dup", Model: ModelConfig{ID: "a"}}, {ID: "Dup", Model: ModelConfig{ID: "b"}}},
			want:     "unique and unambiguous",
		},
		{
			name:     "bad id",
			variants: []MatrixVariant{{ID: "has space", Model: ModelConfig{ID: "a"}}, {ID: "ok", Model: ModelConfig{ID: "b"}}},
			want:     "stable label",
		},
		{
			name:     "ambiguous effective config",
			variants: []MatrixVariant{{ID: "one", Model: ModelConfig{ID: "same"}}, {ID: "two", Model: ModelConfig{ID: "same"}}},
			want:     "same effective configuration",
		},
		{
			name:     "invalid variant model",
			variants: []MatrixVariant{{ID: "small", Model: ModelConfig{ID: "a", ContextWindow: 100}}, {ID: "ok", Model: ModelConfig{ID: "b"}}},
			want:     `matrix variant "small"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := matrixTestConfig(t, test.variants...)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMatrixConfigAcceptsDistinctVariantsAndKeepsDefaultSingleModel(t *testing.T) {
	config := matrixTestConfig(t,
		MatrixVariant{ID: "baseline", Model: ModelConfig{ID: "model-a"}},
		MatrixVariant{ID: "wider-context", Model: ModelConfig{ID: "model-b", ContextWindow: 32768}},
		MatrixVariant{ID: "alternate-api", Model: ModelConfig{ID: "model-c", API: "openai-responses"}},
	)
	if err := config.Validate(); err != nil {
		t.Fatalf("valid matrix rejected: %v", err)
	}
	// The base runtime model is untouched: the default single scan still uses it.
	if config.Runtime.Model.ID != "fixture-model" {
		t.Fatalf("matrix mutated the default model: %q", config.Runtime.Model.ID)
	}
}

func TestVariantConfigMergesOverridesWithoutMutatingBase(t *testing.T) {
	base := validTestConfig(t, t.TempDir())
	variant := MatrixVariant{
		ID:                    "override",
		Model:                 ModelConfig{ID: "variant-model", ContextWindow: 16384},
		ControlPlaneAddresses: []string{"10.0.0.9:9000"},
	}
	effective := base.VariantConfig(variant)
	if effective.Runtime.Model.ID != "variant-model" || effective.Runtime.Model.ContextWindow != 16384 {
		t.Fatalf("model override not applied: %#v", effective.Runtime.Model)
	}
	if effective.Runtime.Model.Provider != base.Runtime.Model.Provider || effective.Runtime.Model.BaseURL != base.Runtime.Model.BaseURL {
		t.Fatalf("unspecified model fields were not inherited: %#v", effective.Runtime.Model)
	}
	if len(effective.Runtime.ControlPlaneAddresses) != 1 || effective.Runtime.ControlPlaneAddresses[0] != "10.0.0.9:9000" {
		t.Fatalf("control plane override not applied: %#v", effective.Runtime.ControlPlaneAddresses)
	}
	if effective.Runtime.TimeoutSeconds != base.Runtime.TimeoutSeconds {
		t.Fatalf("matrix changed fixed timeout: %d", effective.Runtime.TimeoutSeconds)
	}
	if len(effective.Matrix.Variants) != 0 {
		t.Fatal("effective variant config still carries a matrix block")
	}
	if base.Runtime.Model.ID != "fixture-model" || base.Runtime.TimeoutSeconds != 10 || len(base.Runtime.ControlPlaneAddresses) != 1 || base.Runtime.ControlPlaneAddresses[0] != "10.0.0.2:8000" {
		t.Fatalf("base config was mutated: %#v", base.Runtime)
	}
}

func TestVariantConfigChangesOnlyDocumentedAxes(t *testing.T) {
	base := validTestConfig(t, t.TempDir())
	variant := MatrixVariant{
		ID: "alternate-endpoint",
		Model: ModelConfig{
			Provider: "alternate", BaseURL: "http://10.0.0.9:9000/v1", ID: "model-b",
			API: "openai-responses", ContextWindow: 16384, MaxTokens: 2048,
		},
		ControlPlaneAddresses: []string{"10.0.0.9:9000"},
	}
	effective := base.VariantConfig(variant)
	if got, want := matrixInvariantReceipts(effective, ""), matrixInvariantReceipts(base, ""); got != want {
		t.Fatalf("fixed receipts changed: got=%#v want=%#v", got, want)
	}
	if !reflect.DeepEqual(effective.Executor, base.Executor) || !reflect.DeepEqual(effective.Isolation, base.Isolation) ||
		!reflect.DeepEqual(effective.Exercise, base.Exercise) || !reflect.DeepEqual(effective.Limits, base.Limits) ||
		effective.TargetLineage != base.TargetLineage || effective.Runtime.TimeoutSeconds != base.Runtime.TimeoutSeconds ||
		effective.Runtime.AgentUser != base.Runtime.AgentUser || effective.Runtime.OpenClawCommand != base.Runtime.OpenClawCommand {
		t.Fatalf("variant changed a fixed axis: base=%#v effective=%#v", base, effective)
	}
}

func TestBuildMatrixPlanShowsResourceMultiplierAndHidesRawEndpoints(t *testing.T) {
	config := matrixTestConfig(t,
		MatrixVariant{ID: "model-a", Model: ModelConfig{ID: "model-a"}},
		MatrixVariant{ID: "model-b", Model: ModelConfig{ID: "model-b"}},
		MatrixVariant{ID: "model-c", Model: ModelConfig{ID: "model-c"}},
	)
	plan, err := BuildMatrixPlan(matrixFixtureTarget(), config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ResourceMultiplier != 3 || plan.FreshVMsProvisioned != 3 || plan.VariantCount != 3 || plan.Execution != "sequential" {
		t.Fatalf("plan = %#v", plan)
	}
	if plan.FixedConfigSHA256 == "" || plan.TargetSHA256 == "" {
		t.Fatalf("fixed config receipt = %q", plan.FixedConfigSHA256)
	}
	if plan.WorstCaseWallClockSeconds != 3*(10*2+300) {
		t.Fatalf("worst case = %d", plan.WorstCaseWallClockSeconds)
	}
	digests := map[string]bool{}
	for _, variant := range plan.Variants {
		if strings.Contains(variant.ModelEndpointClass, "10.0.0.2") || strings.Contains(variant.ModelEndpointClass, ":") {
			t.Fatalf("plan leaked a raw endpoint: %q", variant.ModelEndpointClass)
		}
		if digests[variant.CaptureConfigSHA256] {
			t.Fatalf("plan has a duplicate variant capture digest: %q", variant.CaptureConfigSHA256)
		}
		digests[variant.CaptureConfigSHA256] = true
	}
	summary := plan.Summary()
	for _, expected := range []string{"3 variants", "sequential", "3x", "worst-case wall clock"} {
		if !strings.Contains(summary, expected) {
			t.Fatalf("summary missing %q:\n%s", expected, summary)
		}
	}
	if _, err := BuildMatrixPlan("/does/not/matter", validTestConfig(t, t.TempDir())); err == nil || !strings.Contains(err.Error(), "no matrix.variants") {
		t.Fatalf("plan without variants err = %v", err)
	}
	second, err := BuildMatrixPlan(matrixFixtureTarget(), config)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(plan)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("matrix dry-run plan is nondeterministic:\n%s\n%s", firstJSON, secondJSON)
	}
}

func completeVariantInput(t *testing.T, id string, modelID string) MatrixComparisonInput {
	t.Helper()
	config := validTestConfig(t, t.TempDir())
	if err := os.WriteFile(config.Executor.TLSCAFile, sharedMatrixCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	config.TargetLineage = "example/fixture-skill"
	config.Runtime.Model.ID = modelID
	evidence := fixtureEvidence()
	evidence.Run.ID = "obs_" + id
	bindMatrixEvidence(t, &evidence, config)
	return MatrixComparisonInput{VariantID: modelID, Evidence: evidence, EffectiveConfig: &config}
}

func bindMatrixEvidence(t *testing.T, evidence *Evidence, config Config) {
	t.Helper()
	captureConfigSHA, err := captureConfigSHA256(config)
	if err != nil {
		t.Fatal(err)
	}
	evidence.CaptureConfigSHA256 = captureConfigSHA
	evidence.Target.Lineage = config.TargetLineage
	evidence.Run.Runtime.ModelID = config.Runtime.Model.ID
	evidence.Run.Runtime.ModelProvider = config.Runtime.Model.Provider
	evidence.Run.Runtime.ModelEndpoint = modelEndpointClass(config.Runtime.Model.BaseURL)
	evidence.Run.Executor = config.Executor.Kind
	evidence.Run.Isolation.Substrate = config.Isolation.Substrate
	evidence.Run.Isolation.NetworkMode = config.Isolation.NetworkMode
	evidence.Run.Isolation.Verification = config.Isolation.Verification
	_, tlsCASHA256, err := readAndValidateTLSCAFile(config.Executor.TLSCAFile, proxmoxAPIHostname(config.Executor.CrabboxConfig))
	if err != nil {
		t.Fatal(err)
	}
	evidence.Run.Isolation.ProxmoxTLSCASHA256 = tlsCASHA256
	evidence.Run.Isolation.GuestFirewallPolicySHA256 = digestBytes([]byte(guestFirewallRules("policy", config.Runtime.ControlPlaneAddresses, config.Runtime.ModelRelay, config.Runtime.MockEgress)))
	evidence.Exercise.PromptSHA256 = digestBytes([]byte(config.Exercise.Prompt))
	evidence.Exercise.TurnLimit = config.Exercise.TurnLimit
}

func TestCompareMatrixProducesPerVariantSignalsAndTotals(t *testing.T) {
	shared := Observation{Kind: "file", Operation: "open-for-read", Subject: "$HOME/.aws/credentials", Outcome: "succeeded", Role: "external", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1}
	onlyB := Observation{Kind: "network", Operation: "connect", Subject: "93.184.216.34:443", Outcome: "succeeded", Role: "external", BaselineCount: 0, ExerciseCount: 2, DeltaCount: 2}

	variantA := completeVariantInput(t, "a", "model-a")
	variantA.Evidence.Observations = []Observation{shared}
	variantB := completeVariantInput(t, "b", "model-b")
	variantB.Evidence.Observations = []Observation{shared, onlyB}

	comparison, err := CompareMatrix([]MatrixComparisonInput{
		variantA,
		variantB,
	})
	if err != nil {
		t.Fatal(err)
	}
	if comparison.Schema != MatrixComparisonSchema || len(comparison.Variants) != 2 || len(comparison.Excluded) != 0 {
		t.Fatalf("comparison = %#v", comparison)
	}
	var sharedRow, divergentRow *MatrixSignalRow
	for i := range comparison.Signals {
		switch comparison.Signals[i].Subject {
		case "$HOME/.aws/credentials":
			sharedRow = &comparison.Signals[i]
		case "93.184.216.34:443":
			divergentRow = &comparison.Signals[i]
		}
	}
	if sharedRow == nil || !sharedRow.Uniform || sharedRow.Deltas["model-a"] != 1 || sharedRow.Deltas["model-b"] != 1 {
		t.Fatalf("shared row = %#v", sharedRow)
	}
	if divergentRow == nil || divergentRow.Uniform || divergentRow.Deltas["model-a"] != 0 || divergentRow.Deltas["model-b"] != 2 {
		t.Fatalf("divergent row = %#v", divergentRow)
	}
	totals := map[string]MatrixSignalTotals{}
	for _, variant := range comparison.Variants {
		totals[variant.ID] = variant.SignalTotals
	}
	if totals["model-a"].File != 1 || totals["model-a"].Network != 0 || totals["model-b"].Network != 2 {
		t.Fatalf("totals = %#v", totals)
	}
	if comparison.HeldConstant.OpenClawVersion != "OpenClaw fixture" || comparison.Target.SHA256 == "" {
		t.Fatalf("held constant / target = %#v %#v", comparison.HeldConstant, comparison.Target)
	}
	if comparison.HeldConstant.CaptureProtocolRevision != CaptureProtocolRevision ||
		comparison.HeldConstant.FixedConfigSHA256 == "" || comparison.HeldConstant.IsolationConfigSHA256 == "" ||
		comparison.HeldConstant.ResourceLimitsSHA256 == "" || comparison.HeldConstant.ExerciseConfigSHA256 == "" ||
		comparison.HeldConstant.TargetConfigSHA256 == "" || comparison.HeldConstant.RuntimeConstantsSHA256 == "" ||
		comparison.HeldConstant.ModelRelayConfigSHA256 == "" || comparison.HeldConstant.MockEgressConfigSHA256 == "" ||
		comparison.HeldConstant.RedirectConfigSHA256 == "" || comparison.HeldConstant.ProxmoxTLSCASHA256 == "" {
		t.Fatalf("fixed receipts are incomplete: %#v", comparison.HeldConstant)
	}
}

func TestCompareMatrixRequiresEffectiveConfigAndExactCaptureBinding(t *testing.T) {
	left := completeVariantInput(t, "a", "model-a")
	right := completeVariantInput(t, "b", "model-b")

	missing := right
	missing.EffectiveConfig = nil
	if _, err := CompareMatrix([]MatrixComparisonInput{left, missing}); err == nil || !strings.Contains(err.Error(), "effective configuration is required") {
		t.Fatalf("missing config err = %v", err)
	}

	tampered := right
	tampered.Evidence.CaptureConfigSHA256 = "sha256:" + strings.Repeat("9", 64)
	if _, err := CompareMatrix([]MatrixComparisonInput{left, tampered}); err == nil || !strings.Contains(err.Error(), "capture configuration digest") {
		t.Fatalf("digest binding err = %v", err)
	}

	modelTampered := right
	modelTampered.Evidence.Run.Runtime.ModelID = "unbound-model"
	if _, err := CompareMatrix([]MatrixComparisonInput{left, modelTampered}); err == nil || !strings.Contains(err.Error(), "model receipt") {
		t.Fatalf("model binding err = %v", err)
	}

	firewallTampered := right
	firewallTampered.Evidence.Run.Isolation.GuestFirewallPolicySHA256 = "sha256:" + strings.Repeat("8", 64)
	if _, err := CompareMatrix([]MatrixComparisonInput{left, firewallTampered}); err == nil || !strings.Contains(err.Error(), "firewall policy receipt") {
		t.Fatalf("firewall binding err = %v", err)
	}

	caTampered := right
	caTampered.Evidence.Run.Isolation.ProxmoxTLSCASHA256 = "sha256:" + strings.Repeat("7", 64)
	if _, err := CompareMatrix([]MatrixComparisonInput{left, caTampered}); err == nil || !strings.Contains(err.Error(), "Proxmox TLS CA receipt") {
		t.Fatalf("TLS CA binding err = %v", err)
	}
}

func TestCompareMatrixAllowsBoundPerVariantFirewallReceipts(t *testing.T) {
	left := completeVariantInput(t, "a", "model-a")
	right := completeVariantInput(t, "b", "model-b")

	left.Evidence.Run.Isolation.GuestFirewallSHA256 = "sha256:" + strings.Repeat("1", 64)
	changed := *right.EffectiveConfig
	changed.Runtime.Model.BaseURL = "http://10.0.0.9:9000/v1"
	changed.Runtime.ControlPlaneAddresses = []string{"10.0.0.9:9000"}
	right.EffectiveConfig = &changed
	bindMatrixEvidence(t, &right.Evidence, changed)
	right.Evidence.Run.Isolation.GuestFirewallSHA256 = "sha256:" + strings.Repeat("2", 64)

	comparison, err := CompareMatrix([]MatrixComparisonInput{left, right})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Variants) != 2 ||
		comparison.Variants[0].GuestFirewallPolicySHA256 == comparison.Variants[1].GuestFirewallPolicySHA256 {
		t.Fatalf("per-variant firewall receipts were not retained: %#v", comparison.Variants)
	}
}

func TestCompareMatrixRejectsReceiptBoundFixedAxisDrift(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "resource limits", change: func(config *Config) { config.Limits.MaxTasks++ }},
		{name: "timeout", change: func(config *Config) { config.Runtime.TimeoutSeconds++ }},
		{name: "model relay limit", change: func(config *Config) { config.Runtime.ModelRelay.MaxRequests++ }},
		{name: "mock egress limit", change: func(config *Config) { config.Runtime.MockEgress.MaxRequests++ }},
		{name: "prompt", change: func(config *Config) { config.Exercise.Prompt += " Fixed-axis drift." }},
		{name: "isolation", change: func(config *Config) { config.Isolation.Verification = "other-network-proof" }},
		{name: "target lineage", change: func(config *Config) { config.TargetLineage = "example/other-skill" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left := completeVariantInput(t, "a", "model-a")
			right := completeVariantInput(t, "b", "model-b")
			changed := *right.EffectiveConfig
			test.change(&changed)
			right.EffectiveConfig = &changed
			bindMatrixEvidence(t, &right.Evidence, changed)
			if _, err := CompareMatrix([]MatrixComparisonInput{left, right}); err == nil || !strings.Contains(err.Error(), "fixed configuration receipts differ") {
				t.Fatalf("err = %v", err)
			}
		})
	}

	t.Run("Proxmox TLS CA bytes", func(t *testing.T) {
		left := completeVariantInput(t, "a", "model-a")
		right := completeVariantInput(t, "b", "model-b")
		changed := *right.EffectiveConfig
		changed.Executor.TLSCAFile = writeTestCA(t, t.TempDir(), "alternate-matrix-ca.pem")
		right.EffectiveConfig = &changed
		bindMatrixEvidence(t, &right.Evidence, changed)
		if _, err := CompareMatrix([]MatrixComparisonInput{left, right}); err == nil || !strings.Contains(err.Error(), "fixed configuration receipts differ") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCompareMatrixRejectsDuplicateAndAmbiguousIdentities(t *testing.T) {
	variantA := completeVariantInput(t, "a", "model-a")
	variantB := completeVariantInput(t, "b", "model-b")
	variantA.VariantID = "same"
	variantB.VariantID = "Same"

	if _, err := CompareMatrix([]MatrixComparisonInput{
		variantA,
		variantB,
	}); err == nil || !strings.Contains(err.Error(), "duplicate or ambiguous variant identity") {
		t.Fatalf("duplicate id err = %v", err)
	}

	shared := completeVariantInput(t, "shared", "model-x")
	left := shared
	right := shared
	left.VariantID = "left"
	right.VariantID = "right"
	if _, err := CompareMatrix([]MatrixComparisonInput{
		left,
		right,
	}); err == nil || !strings.Contains(err.Error(), "share the same capture configuration") {
		t.Fatalf("ambiguous config err = %v", err)
	}
}

func TestCompareMatrixRefusesIncomparableCaptures(t *testing.T) {
	tests := []struct {
		name            string
		change          func(*Evidence)
		want            string
		bindingRejected bool
	}{
		{name: "target digest", change: func(e *Evidence) { e.Target.SHA256 = "sha256:" + strings.Repeat("9", 64) }, want: "target digest"},
		{name: "prompt", change: func(e *Evidence) { e.Exercise.PromptSHA256 = "sha256:" + strings.Repeat("9", 64) }, want: "exercise receipt", bindingRejected: true},
		{name: "coverage", change: func(e *Evidence) { e.Coverage.Limitations = append(e.Coverage.Limitations, "extra") }, want: "capture coverage"},
		{name: "isolation", change: func(e *Evidence) { e.Run.Isolation.NetworkMode = "sinkhole" }, want: "isolation receipt", bindingRejected: true},
		{name: "runtime version", change: func(e *Evidence) { e.Run.Runtime.OpenClawVersion = "OpenClaw other" }, want: "OpenClaw runtime version"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			variantA := completeVariantInput(t, "a", "model-a")
			variantB := completeVariantInput(t, "b", "model-b")
			test.change(&variantB.Evidence)
			_, err := CompareMatrix([]MatrixComparisonInput{
				variantA,
				variantB,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) || (!test.bindingRejected && !strings.Contains(err.Error(), "differ only in model/runtime")) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCompareMatrixExcludesIncompleteWithoutMislabeling(t *testing.T) {
	variantA := completeVariantInput(t, "a", "model-a")
	variantB := completeVariantInput(t, "b", "model-b")
	incomplete := completeVariantInput(t, "c", "model-c")
	incomplete.Evidence.Run.Status = "incomplete"
	incomplete.Evidence.Run.LaneExitCode.Exercise = 124

	comparison, err := CompareMatrix([]MatrixComparisonInput{
		variantA,
		variantB,
		incomplete,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Variants) != 2 {
		t.Fatalf("comparable variants = %#v", comparison.Variants)
	}
	foundExclusion := false
	for _, excluded := range comparison.Excluded {
		if excluded.ID == "model-c" && excluded.Reason == "incomplete-capture" {
			foundExclusion = true
		}
	}
	if !foundExclusion {
		t.Fatalf("excluded = %#v", comparison.Excluded)
	}
	for _, signal := range comparison.Signals {
		if _, present := signal.Deltas["model-c"]; present {
			t.Fatalf("incomparable variant leaked into a behavioral signal: %#v", signal)
		}
	}

	// Only one comparable capture is not a comparison.
	if _, err := CompareMatrix([]MatrixComparisonInput{
		variantA,
		incomplete,
	}); err == nil || !strings.Contains(err.Error(), "at least 2 comparable complete captures") {
		t.Fatalf("single comparable err = %v", err)
	}
}

func TestCompareMatrixDerivesIdentityFromCaptureDigestWhenUnlabeled(t *testing.T) {
	variantA := completeVariantInput(t, "a", "model-a")
	variantB := completeVariantInput(t, "b", "model-b")
	variantA.VariantID = ""
	variantB.VariantID = ""
	comparison, err := CompareMatrix([]MatrixComparisonInput{
		variantA,
		variantB,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range comparison.Variants {
		if !strings.HasPrefix(variant.ID, "config-") {
			t.Fatalf("derived identity = %q", variant.ID)
		}
	}
}

func TestRunMatrixRunsVariantsSequentiallyWithFreshVMsAndComparison(t *testing.T) {
	requireLinuxControlHost(t)
	config := matrixTestConfig(t,
		MatrixVariant{ID: "model-a", Model: ModelConfig{ID: "model-a"}},
		MatrixVariant{ID: "model-b", Model: ModelConfig{ID: "model-b"}},
	)
	skill := matrixFixtureTarget()
	progress := &bytes.Buffer{}
	result, err := RunMatrix(context.Background(), skill, config, &fixtureExecutor{t: t}, MatrixOptions{Progress: progress})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Runs) != 2 {
		t.Fatalf("runs = %#v", result.Runs)
	}
	runDirs := map[string]bool{}
	digests := map[string]bool{}
	plannedDigests := map[string]string{}
	for _, planned := range result.Plan.Variants {
		plannedDigests[planned.ID] = planned.CaptureConfigSHA256
	}
	for _, run := range result.Runs {
		if run.Status != "completed" || run.Evidence == nil {
			t.Fatalf("run = %#v", run)
		}
		if runDirs[run.RunDirectory] {
			t.Fatalf("variants shared a run directory (not a fresh VM): %s", run.RunDirectory)
		}
		runDirs[run.RunDirectory] = true
		digests[run.CaptureConfigSHA256] = true
		if plannedDigests[run.ID] != run.CaptureConfigSHA256 {
			t.Fatalf("variant %q plan digest %q != capture receipt %q", run.ID, plannedDigests[run.ID], run.CaptureConfigSHA256)
		}
	}
	if len(digests) != 2 {
		t.Fatalf("variants did not bind distinct configs: %#v", digests)
	}
	if result.Comparison.Schema != MatrixComparisonSchema || len(result.Comparison.Variants) != 2 || len(result.Comparison.Excluded) != 0 {
		t.Fatalf("comparison = %#v", result.Comparison)
	}
	if result.Comparison.HeldConstant.FixedConfigSHA256 != result.Plan.FixedConfigSHA256 || result.Plan.TargetSHA256 != result.Comparison.Target.SHA256 {
		t.Fatalf("plan receipts do not bind comparison: plan=%#v held=%#v target=%#v", result.Plan, result.Comparison.HeldConstant, result.Comparison.Target)
	}
	if len(result.Comparison.Signals) == 0 {
		t.Fatal("comparison produced no signals")
	}
	models := map[string]bool{}
	for _, variant := range result.Comparison.Variants {
		models[variant.ModelID] = true
		if variant.ModelEndpoint == "" || variant.CaptureConfigSHA256 == "" {
			t.Fatalf("variant summary incomplete: %#v", variant)
		}
	}
	if !models["model-a"] || !models["model-b"] {
		t.Fatalf("variant model receipts = %#v", models)
	}
	if !strings.Contains(progress.String(), "matrix plan") {
		t.Fatalf("progress did not show the plan: %s", progress.String())
	}
}

func TestRunMatrixDryRunDoesNotProvision(t *testing.T) {
	config := matrixTestConfig(t,
		MatrixVariant{ID: "model-a", Model: ModelConfig{ID: "model-a"}},
		MatrixVariant{ID: "model-b", Model: ModelConfig{ID: "model-b"}},
	)
	executor := &fixtureExecutor{t: t}
	progress := &bytes.Buffer{}
	result, err := RunMatrix(context.Background(), matrixFixtureTarget(), config, executor, MatrixOptions{DryRun: true, Progress: progress})
	if err != nil {
		t.Fatal(err)
	}
	if executor.command != "" {
		t.Fatalf("dry run provisioned an executor: %#v", executor)
	}
	if len(result.Runs) != 0 || result.Comparison.Schema != "" {
		t.Fatalf("dry run produced runs or a comparison: %#v", result)
	}
	if result.Plan.ResourceMultiplier != 2 || !strings.Contains(progress.String(), "2x") {
		t.Fatalf("dry run plan = %#v progress=%s", result.Plan, progress.String())
	}
}

func TestRunMatrixDefaultScanUsesBaseModelOnly(t *testing.T) {
	requireLinuxControlHost(t)
	// A configuration that also defines a matrix must not change the default
	// single scan: Scan ignores the matrix and uses the base model.
	config := matrixTestConfig(t,
		MatrixVariant{ID: "model-a", Model: ModelConfig{ID: "model-a"}},
		MatrixVariant{ID: "model-b", Model: ModelConfig{ID: "model-b"}},
	)
	result, err := Scan(context.Background(), matrixFixtureTarget(), config, &fixtureExecutor{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if result.Evidence.Run.Runtime.ModelID != "fixture-model" {
		t.Fatalf("default scan used a matrix variant model: %q", result.Evidence.Run.Runtime.ModelID)
	}
}
