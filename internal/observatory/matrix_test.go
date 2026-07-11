package observatory

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func matrixTestConfig(t *testing.T, variants ...MatrixVariant) Config {
	t.Helper()
	config := validTestConfig(t, t.TempDir())
	config.Matrix = MatrixConfig{Variants: variants}
	return config
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
		MatrixVariant{ID: "long-timeout", Model: ModelConfig{ID: "model-c"}, TimeoutSeconds: 30},
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
		TimeoutSeconds:        42,
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
	if effective.Runtime.TimeoutSeconds != 42 {
		t.Fatalf("timeout override not applied: %d", effective.Runtime.TimeoutSeconds)
	}
	if len(effective.Matrix.Variants) != 0 {
		t.Fatal("effective variant config still carries a matrix block")
	}
	if base.Runtime.Model.ID != "fixture-model" || base.Runtime.TimeoutSeconds != 10 || len(base.Runtime.ControlPlaneAddresses) != 1 || base.Runtime.ControlPlaneAddresses[0] != "10.0.0.2:8000" {
		t.Fatalf("base config was mutated: %#v", base.Runtime)
	}
}

func TestBuildMatrixPlanShowsResourceMultiplierAndHidesRawEndpoints(t *testing.T) {
	config := matrixTestConfig(t,
		MatrixVariant{ID: "model-a", Model: ModelConfig{ID: "model-a"}},
		MatrixVariant{ID: "model-b", Model: ModelConfig{ID: "model-b"}},
		MatrixVariant{ID: "model-c", Model: ModelConfig{ID: "model-c"}},
	)
	plan, err := BuildMatrixPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ResourceMultiplier != 3 || plan.FreshVMsProvisioned != 3 || plan.VariantCount != 3 || plan.Execution != "sequential" {
		t.Fatalf("plan = %#v", plan)
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
	if _, err := BuildMatrixPlan(validTestConfig(t, t.TempDir())); err == nil || !strings.Contains(err.Error(), "no matrix.variants") {
		t.Fatalf("plan without variants err = %v", err)
	}
}

func completeVariantEvidence(id string, modelID string, digestSeed string) Evidence {
	evidence := fixtureEvidence()
	evidence.CaptureConfigSHA256 = "sha256:" + strings.Repeat(digestSeed, 64)
	evidence.Run.Runtime.ModelID = modelID
	evidence.Run.ID = "obs_" + id
	return evidence
}

func TestCompareMatrixProducesPerVariantSignalsAndTotals(t *testing.T) {
	shared := Observation{Kind: "file", Operation: "open-for-read", Subject: "$HOME/.aws/credentials", Outcome: "succeeded", Role: "external", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1}
	onlyB := Observation{Kind: "network", Operation: "connect", Subject: "93.184.216.34:443", Outcome: "succeeded", Role: "external", BaselineCount: 0, ExerciseCount: 2, DeltaCount: 2}

	variantA := completeVariantEvidence("a", "model-a", "1")
	variantA.Observations = []Observation{shared}
	variantB := completeVariantEvidence("b", "model-b", "2")
	variantB.Observations = []Observation{shared, onlyB}

	comparison, err := CompareMatrix([]MatrixComparisonInput{
		{VariantID: "model-a", Evidence: variantA},
		{VariantID: "model-b", Evidence: variantB},
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
}

func TestCompareMatrixRejectsDuplicateAndAmbiguousIdentities(t *testing.T) {
	variantA := completeVariantEvidence("a", "model-a", "1")
	variantB := completeVariantEvidence("b", "model-b", "2")

	if _, err := CompareMatrix([]MatrixComparisonInput{
		{VariantID: "same", Evidence: variantA},
		{VariantID: "Same", Evidence: variantB},
	}); err == nil || !strings.Contains(err.Error(), "duplicate or ambiguous variant identity") {
		t.Fatalf("duplicate id err = %v", err)
	}

	shared := completeVariantEvidence("shared", "model-x", "3")
	if _, err := CompareMatrix([]MatrixComparisonInput{
		{VariantID: "left", Evidence: shared},
		{VariantID: "right", Evidence: shared},
	}); err == nil || !strings.Contains(err.Error(), "share the same capture configuration") {
		t.Fatalf("ambiguous config err = %v", err)
	}
}

func TestCompareMatrixRefusesIncomparableCaptures(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Evidence)
		want   string
	}{
		{name: "target digest", change: func(e *Evidence) { e.Target.SHA256 = "sha256:" + strings.Repeat("9", 64) }, want: "target digest"},
		{name: "prompt", change: func(e *Evidence) { e.Exercise.PromptSHA256 = "sha256:" + strings.Repeat("9", 64) }, want: "exercise prompt"},
		{name: "coverage", change: func(e *Evidence) { e.Coverage.Limitations = append(e.Coverage.Limitations, "extra") }, want: "capture coverage"},
		{name: "isolation", change: func(e *Evidence) { e.Run.Isolation.NetworkMode = "sinkhole" }, want: "isolation network mode"},
		{name: "runtime version", change: func(e *Evidence) { e.Run.Runtime.OpenClawVersion = "OpenClaw other" }, want: "OpenClaw runtime version"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			variantA := completeVariantEvidence("a", "model-a", "1")
			variantB := completeVariantEvidence("b", "model-b", "2")
			test.change(&variantB)
			if _, err := CompareMatrix([]MatrixComparisonInput{
				{VariantID: "model-a", Evidence: variantA},
				{VariantID: "model-b", Evidence: variantB},
			}); err == nil || !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), "differ only in model/runtime") {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCompareMatrixExcludesIncompleteWithoutMislabeling(t *testing.T) {
	variantA := completeVariantEvidence("a", "model-a", "1")
	variantB := completeVariantEvidence("b", "model-b", "2")
	incomplete := completeVariantEvidence("c", "model-c", "3")
	incomplete.Run.Status = "incomplete"
	incomplete.Run.LaneExitCode.Exercise = 124

	comparison, err := CompareMatrix([]MatrixComparisonInput{
		{VariantID: "model-a", Evidence: variantA},
		{VariantID: "model-b", Evidence: variantB},
		{VariantID: "model-c", Evidence: incomplete},
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
		{VariantID: "model-a", Evidence: variantA},
		{VariantID: "model-c", Evidence: incomplete},
	}); err == nil || !strings.Contains(err.Error(), "at least 2 comparable complete captures") {
		t.Fatalf("single comparable err = %v", err)
	}
}

func TestCompareMatrixDerivesIdentityFromCaptureDigestWhenUnlabeled(t *testing.T) {
	variantA := completeVariantEvidence("a", "model-a", "1")
	variantB := completeVariantEvidence("b", "model-b", "2")
	comparison, err := CompareMatrix([]MatrixComparisonInput{
		{Evidence: variantA},
		{Evidence: variantB},
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
	skill := filepath.Join("..", "..", "testdata", "fixtures", "probe-skill")
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
	for _, run := range result.Runs {
		if run.Status != "completed" || run.Evidence == nil {
			t.Fatalf("run = %#v", run)
		}
		if runDirs[run.RunDirectory] {
			t.Fatalf("variants shared a run directory (not a fresh VM): %s", run.RunDirectory)
		}
		runDirs[run.RunDirectory] = true
		digests[run.CaptureConfigSHA256] = true
	}
	if len(digests) != 2 {
		t.Fatalf("variants did not bind distinct configs: %#v", digests)
	}
	if result.Comparison.Schema != MatrixComparisonSchema || len(result.Comparison.Variants) != 2 || len(result.Comparison.Excluded) != 0 {
		t.Fatalf("comparison = %#v", result.Comparison)
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
	result, err := RunMatrix(context.Background(), "/does/not/matter", config, executor, MatrixOptions{DryRun: true, Progress: progress})
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
	result, err := Scan(context.Background(), filepath.Join("..", "..", "testdata", "fixtures", "probe-skill"), config, &fixtureExecutor{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if result.Evidence.Run.Runtime.ModelID != "fixture-model" {
		t.Fatalf("default scan used a matrix variant model: %q", result.Evidence.Run.Runtime.ModelID)
	}
}
