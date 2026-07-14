package observatory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
)

const (
	// MatrixPlanSchema tags the pre-execution plan shown before any VM is
	// provisioned, and MatrixComparisonSchema tags the structured cross-variant
	// comparison. Neither carries a verdict, score, or recommendation.
	MatrixPlanSchema       = "observatory.matrix-plan.v1"
	MatrixComparisonSchema = "observatory.matrix.v1"
)

// MatrixPlan summarizes an opt-in comparison matrix before execution. It exists
// so the resource multiplier a matrix implies is always visible up front (and is
// the entire output of a dry run). Fields are secret-safe: model endpoints are
// reported as a class, never as raw addresses.
type MatrixPlan struct {
	Schema                    string              `json:"schema"`
	FixedConfigSHA256         string              `json:"fixedConfigSha256"`
	TargetSHA256              string              `json:"targetSha256"`
	VariantCount              int                 `json:"variantCount"`
	ResourceMultiplier        int                 `json:"resourceMultiplier"`
	FreshVMsProvisioned       int                 `json:"freshVmsProvisioned"`
	Execution                 string              `json:"execution"`
	WorstCaseWallClockSeconds int                 `json:"worstCaseWallClockSeconds"`
	Variants                  []MatrixPlanVariant `json:"variants"`
}

type MatrixPlanVariant struct {
	ID                  string `json:"id"`
	ModelProvider       string `json:"modelProvider"`
	ModelID             string `json:"modelId"`
	ModelEndpointClass  string `json:"modelEndpointClass"`
	TimeoutSeconds      int    `json:"timeoutSeconds"`
	CaptureConfigSHA256 string `json:"captureConfigSha256"`
}

// BuildMatrixPlan validates the matrix, securely inspects the local target, and
// describes what running it would cost. It never provisions anything. Target
// inspection is required so target-aware default prompts and capture receipts
// in a dry-run plan are the exact values a real scan will bind.
func BuildMatrixPlan(target string, config Config) (MatrixPlan, error) {
	if len(config.Matrix.Variants) == 0 {
		return MatrixPlan{}, errors.New("no matrix.variants are defined in the configuration")
	}
	if err := config.validateMatrix(); err != nil {
		return MatrixPlan{}, err
	}
	staged, err := InspectTarget(target, config.Limits)
	if err != nil {
		return MatrixPlan{}, fmt.Errorf("inspect matrix target for deterministic plan: %w", err)
	}
	baseEffective, err := effectiveConfigForTarget(config, staged.Evidence)
	if err != nil {
		return MatrixPlan{}, err
	}
	_, proxmoxTLSCASHA256, err := readAndValidateTLSCAFile(baseEffective.Executor.TLSCAFile, proxmoxAPIHostname(baseEffective.Executor.CrabboxConfig))
	if err != nil {
		return MatrixPlan{}, fmt.Errorf("read matrix Proxmox TLS CA: %w", err)
	}
	fixedReceipts := matrixInvariantReceipts(baseEffective, proxmoxTLSCASHA256)
	plan := MatrixPlan{
		Schema:              MatrixPlanSchema,
		FixedConfigSHA256:   fixedReceipts.FixedConfigSHA256,
		TargetSHA256:        staged.Evidence.SHA256,
		VariantCount:        len(config.Matrix.Variants),
		ResourceMultiplier:  len(config.Matrix.Variants),
		FreshVMsProvisioned: len(config.Matrix.Variants),
		Execution:           "sequential",
	}
	for _, variant := range config.Matrix.Variants {
		effective, err := effectiveConfigForTarget(config.VariantConfig(variant), staged.Evidence)
		if err != nil {
			return MatrixPlan{}, fmt.Errorf("matrix variant %q: %w", variant.ID, err)
		}
		captureConfigSHA, err := captureConfigSHA256(effective)
		if err != nil {
			return MatrixPlan{}, fmt.Errorf("matrix variant %q capture configuration digest: %w", variant.ID, err)
		}
		plan.Variants = append(plan.Variants, MatrixPlanVariant{
			ID:                  variant.ID,
			ModelProvider:       effective.Runtime.Model.Provider,
			ModelID:             effective.Runtime.Model.ID,
			ModelEndpointClass:  modelEndpointClass(effective.Runtime.Model.BaseURL),
			TimeoutSeconds:      config.Runtime.TimeoutSeconds,
			CaptureConfigSHA256: captureConfigSHA,
		})
		// Mirror the host-side per-scan budget used in Scan so the worst-case
		// wall clock reflects sequential execution honestly.
		plan.WorstCaseWallClockSeconds += effective.Runtime.TimeoutSeconds*2 + 300
	}
	return plan, nil
}

// Summary renders the plan as human-readable lines for pre-execution display.
func (plan MatrixPlan) Summary() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "matrix plan: %d variants, %s, %d fresh VM(s) — %dx the resources of a single default scan\n",
		plan.VariantCount, plan.Execution, plan.FreshVMsProvisioned, plan.ResourceMultiplier)
	fmt.Fprintf(&builder, "target: %s fixed-config: %s\n", plan.TargetSHA256, plan.FixedConfigSHA256)
	fmt.Fprintf(&builder, "worst-case wall clock: ~%ds (sum of per-variant budgets)\n", plan.WorstCaseWallClockSeconds)
	for _, variant := range plan.Variants {
		fmt.Fprintf(&builder, "  - %s: model %s/%s endpoint=%s timeout=%ds %s\n",
			variant.ID, variant.ModelProvider, variant.ModelID, variant.ModelEndpointClass,
			variant.TimeoutSeconds, variant.CaptureConfigSHA256)
	}
	return builder.String()
}

// MatrixOptions controls an opt-in matrix run. Execution is always sequential
// with a fresh VM per variant; these only govern dry runs and error handling.
type MatrixOptions struct {
	DryRun   bool
	FailFast bool
	Progress io.Writer
}

// MatrixRun is the operator-facing outcome of one variant. Note is a bounded,
// secret-free summary; it is not published in the comparison artifact.
type MatrixRun struct {
	ID                  string
	Status              string
	CaptureConfigSHA256 string
	RunDirectory        string
	Note                string
	Evidence            *Evidence
}

type MatrixResult struct {
	Plan       MatrixPlan
	Runs       []MatrixRun
	Comparison MatrixComparison
}

// RunMatrix executes each configured variant as its own paired scan, in order,
// reusing the shared executor and isolation and overriding only the model/runtime
// axis. Every variant provisions a fresh VM through the normal Scan path, so
// isolation is preserved per variant. It shows the resource multiplier before the
// first VM is provisioned, then returns a structured comparison of the comparable
// captures. Incomplete or failed variants are recorded as excluded, never as
// behavioral differences.
func RunMatrix(ctx context.Context, target string, config Config, executor CommandExecutor, options MatrixOptions) (MatrixResult, error) {
	plan, err := BuildMatrixPlan(target, config)
	if err != nil {
		return MatrixResult{}, err
	}
	result := MatrixResult{Plan: plan}
	if options.Progress != nil {
		fmt.Fprint(options.Progress, plan.Summary())
	}
	if options.DryRun {
		return result, nil
	}

	var inputs []MatrixComparisonInput
	var failed []MatrixExcludedVariant
	var runErrors []error
	for _, variant := range config.Matrix.Variants {
		if options.Progress != nil {
			fmt.Fprintf(options.Progress, "matrix: running variant %q\n", variant.ID)
		}
		effective := config.VariantConfig(variant)
		scanResult, scanErr := Scan(ctx, target, effective, executor)
		run := MatrixRun{ID: variant.ID, RunDirectory: scanResult.RunDirectory}
		if scanResult.Evidence.SchemaVersion != "" {
			evidence := scanResult.Evidence
			boundConfig, bindErr := effectiveConfigForTarget(effective, evidence.Target)
			if bindErr != nil {
				scanErr = errors.Join(scanErr, fmt.Errorf("bind matrix capture configuration: %w", bindErr))
			}
			run.Evidence = &evidence
			run.Status = evidence.Run.Status
			run.CaptureConfigSHA256 = evidence.CaptureConfigSHA256
			if bindErr == nil {
				inputs = append(inputs, MatrixComparisonInput{VariantID: variant.ID, Evidence: evidence, EffectiveConfig: &boundConfig})
			}
		} else {
			run.Status = "failed"
			failed = append(failed, MatrixExcludedVariant{ID: variant.ID, Reason: "capture-failed"})
		}
		if scanErr != nil {
			run.Note = sanitizeMatrixError(scanErr)
			runErrors = append(runErrors, fmt.Errorf("variant %q: %s", variant.ID, run.Note))
		}
		result.Runs = append(result.Runs, run)
		if scanErr != nil && options.FailFast {
			return result, fmt.Errorf("matrix stopped at variant %q under fail-fast: %w", variant.ID, errors.Join(runErrors...))
		}
	}

	comparison, compErr := CompareMatrix(inputs)
	if compErr != nil {
		runErrors = append(runErrors, compErr)
	} else {
		comparison.Excluded = append(comparison.Excluded, failed...)
		sortExcluded(comparison.Excluded)
		result.Comparison = comparison
	}
	if len(runErrors) != 0 {
		return result, errors.Join(runErrors...)
	}
	return result, nil
}

// MatrixComparisonInput pairs an operator label and evidence with the exact
// effective configuration whose digest the capture records. The configuration
// is required so comparison can prove that every non-model axis is fixed and
// that each model, prompt, isolation, firewall, and resource receipt is bound.
type MatrixComparisonInput struct {
	VariantID       string
	Evidence        Evidence
	EffectiveConfig *Config
}

// MatrixComparison is a structured, side-by-side comparison of grade-ready
// behavioral signals across model/runtime variants that hold everything except
// the model/runtime axis constant. It has no verdict, score, or recommendation.
// Evidence v1 has no grade or stage-delta receipt, so neither is inferred here;
// a later schema can add them at MatrixComparisonInput's receipt-binding seam.
type MatrixComparison struct {
	Schema       string                  `json:"schema"`
	Target       MatrixTarget            `json:"target"`
	PromptSHA256 string                  `json:"promptSha256"`
	TurnLimit    int                     `json:"turnLimit"`
	Coverage     CoverageEvidence        `json:"coverage"`
	HeldConstant MatrixConstants         `json:"heldConstant"`
	Variants     []MatrixVariantSummary  `json:"variants"`
	Excluded     []MatrixExcludedVariant `json:"excluded"`
	Signals      []MatrixSignalRow       `json:"signals"`
	Canaries     []MatrixCanaryRow       `json:"canaries"`
}

type MatrixTarget struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	ID      string `json:"id,omitempty"`
	Lineage string `json:"lineage,omitempty"`
	SHA256  string `json:"sha256"`
}

// MatrixConstants records the fields every compared variant shares. They are the
// controlled variables that make the model/runtime axis the only difference.
type MatrixConstants struct {
	CaptureProtocolRevision string `json:"captureProtocolRevision"`
	FixedConfigSHA256       string `json:"fixedConfigSha256"`
	TargetConfigSHA256      string `json:"targetConfigSha256"`
	ExecutorConfigSHA256    string `json:"executorConfigSha256"`
	IsolationConfigSHA256   string `json:"isolationConfigSha256"`
	RuntimeConstantsSHA256  string `json:"runtimeConstantsSha256"`
	ModelRelayConfigSHA256  string `json:"modelRelayConfigSha256"`
	MockEgressConfigSHA256  string `json:"mockEgressConfigSha256"`
	ExerciseConfigSHA256    string `json:"exerciseConfigSha256"`
	RedirectConfigSHA256    string `json:"redirectConfigSha256"`
	ResourceLimitsSHA256    string `json:"resourceLimitsSha256"`
	ProxmoxTLSCASHA256      string `json:"proxmoxTlsCaSha256"`
	IsolationSubstrate      string `json:"isolationSubstrate"`
	IsolationNetworkMode    string `json:"isolationNetworkMode"`
	ContainmentProfile      string `json:"containmentProfile"`
	Verification            string `json:"verification"`
	OpenClawVersion         string `json:"openclawVersion"`
	StraceVersion           string `json:"straceVersion"`
}

// matrixConfigReceipts is the receipt-only projection of every capture setting
// that matrix variants are forbidden to change. It deliberately excludes the
// documented model and model-endpoint allowlist axes.
type matrixConfigReceipts struct {
	CaptureProtocolRevision string
	FixedConfigSHA256       string
	TargetConfigSHA256      string
	ExecutorConfigSHA256    string
	IsolationConfigSHA256   string
	RuntimeConstantsSHA256  string
	ModelRelayConfigSHA256  string
	MockEgressConfigSHA256  string
	ExerciseConfigSHA256    string
	RedirectConfigSHA256    string
	ResourceLimitsSHA256    string
	ProxmoxTLSCASHA256      string
}

func matrixInvariantReceipts(config Config, proxmoxTLSCASHA256 string) matrixConfigReceipts {
	target := struct {
		TargetLineage string `json:"targetLineage"`
	}{TargetLineage: config.TargetLineage}
	executor := struct {
		Kind string `json:"kind"`
	}{Kind: config.Executor.Kind}
	runtimeConstants := struct {
		OpenClawCommand string `json:"openClawCommand"`
		AgentUser       string `json:"agentUser"`
		TimeoutSeconds  int    `json:"timeoutSeconds"`
	}{
		OpenClawCommand: config.Runtime.OpenClawCommand,
		AgentUser:       config.Runtime.AgentUser,
		TimeoutSeconds:  config.Runtime.TimeoutSeconds,
	}
	fixed := struct {
		CaptureProtocolRevision string           `json:"captureProtocolRevision"`
		ProxmoxTLSCASHA256      string           `json:"proxmoxTlsCaSha256"`
		Target                  any              `json:"target"`
		Executor                any              `json:"executor"`
		Isolation               IsolationConfig  `json:"isolation"`
		RuntimeConstants        any              `json:"runtimeConstants"`
		ModelRelay              ModelRelayConfig `json:"modelRelay"`
		MockEgress              MockEgressConfig `json:"mockEgress"`
		Exercise                ExerciseConfig   `json:"exercise"`
		Redirect                RedirectConfig   `json:"redirect"`
		Limits                  LimitsConfig     `json:"limits"`
	}{
		CaptureProtocolRevision: CaptureProtocolRevision,
		ProxmoxTLSCASHA256:      proxmoxTLSCASHA256,
		Target:                  target,
		Executor:                executor,
		Isolation:               config.Isolation,
		RuntimeConstants:        runtimeConstants,
		ModelRelay:              config.Runtime.ModelRelay,
		MockEgress:              config.Runtime.MockEgress,
		Exercise:                config.Exercise,
		Redirect:                config.Redirect,
		Limits:                  config.Limits,
	}
	return matrixConfigReceipts{
		CaptureProtocolRevision: CaptureProtocolRevision,
		FixedConfigSHA256:       matrixDigest(fixed),
		TargetConfigSHA256:      matrixDigest(target),
		ExecutorConfigSHA256:    matrixDigest(executor),
		IsolationConfigSHA256:   matrixDigest(config.Isolation),
		RuntimeConstantsSHA256:  matrixDigest(runtimeConstants),
		ModelRelayConfigSHA256:  matrixDigest(config.Runtime.ModelRelay),
		MockEgressConfigSHA256:  matrixDigest(config.Runtime.MockEgress),
		ExerciseConfigSHA256:    matrixDigest(config.Exercise),
		RedirectConfigSHA256:    matrixDigest(config.Redirect),
		ResourceLimitsSHA256:    matrixDigest(config.Limits),
		ProxmoxTLSCASHA256:      proxmoxTLSCASHA256,
	}
}

func matrixDigest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return digestBytes(data)
}

type MatrixVariantSummary struct {
	ID                        string             `json:"id"`
	RunID                     string             `json:"runId"`
	CaptureConfigSHA256       string             `json:"captureConfigSha256"`
	ModelProvider             string             `json:"modelProvider"`
	ModelID                   string             `json:"modelId"`
	ModelEndpoint             string             `json:"modelEndpoint"`
	GuestFirewallPolicySHA256 string             `json:"guestFirewallPolicySha256"`
	SignalTotals              MatrixSignalTotals `json:"signalTotals"`
}

type MatrixSignalTotals struct {
	File    int `json:"file"`
	Process int `json:"process"`
	Network int `json:"network"`
	Canary  int `json:"canary"`
}

// MatrixExcludedVariant names a variant left out of the behavioral comparison and
// why. Reasons are a fixed vocabulary, never a raw error, so incomparable or
// failed captures are surfaced without being relabeled as behavioral differences.
type MatrixExcludedVariant struct {
	ID                  string `json:"id"`
	Reason              string `json:"reason"`
	CaptureConfigSHA256 string `json:"captureConfigSha256,omitempty"`
}

// MatrixSignalRow is one observed behavior with its per-variant delta counts.
// Uniform is true when every compared variant produced the same delta.
type MatrixSignalRow struct {
	Kind      string         `json:"kind"`
	Operation string         `json:"operation"`
	Subject   string         `json:"subject"`
	Outcome   string         `json:"outcome"`
	Role      string         `json:"role,omitempty"`
	Deltas    map[string]int `json:"deltas"`
	Uniform   bool           `json:"uniform"`
}

type MatrixCanaryRow struct {
	ID      string         `json:"id"`
	Surface string         `json:"surface"`
	Deltas  map[string]int `json:"deltas"`
	Uniform bool           `json:"uniform"`
}

// CompareMatrix builds a structured comparison from per-variant evidence. It
// refuses to compare captures that differ in anything other than the model/runtime
// axis (returning an error rather than presenting incomparable captures as
// behavioral differences), excludes incomplete captures by reason, and rejects
// duplicate or ambiguous variant identities.
func CompareMatrix(inputs []MatrixComparisonInput) (MatrixComparison, error) {
	if len(inputs) < MinMatrixVariants {
		return MatrixComparison{}, fmt.Errorf("matrix comparison requires at least %d variants", MinMatrixVariants)
	}
	type variantEvidence struct {
		id       string
		evidence Evidence
		receipts matrixConfigReceipts
	}
	seenID := map[string]bool{}
	var complete []variantEvidence
	var excluded []MatrixExcludedVariant
	for _, input := range inputs {
		if err := ValidateEvidence(input.Evidence); err != nil {
			return MatrixComparison{}, fmt.Errorf("matrix comparison evidence is invalid: %w", err)
		}
		id := matrixVariantIdentity(input)
		if !matrixVariantIDPattern.MatchString(id) {
			return MatrixComparison{}, fmt.Errorf("matrix comparison variant identity is not a stable label: %q", id)
		}
		normalized := strings.ToLower(id)
		if seenID[normalized] {
			return MatrixComparison{}, fmt.Errorf("matrix comparison has a duplicate or ambiguous variant identity: %q", id)
		}
		seenID[normalized] = true
		receipts, err := validateMatrixInputBinding(input)
		if err != nil {
			return MatrixComparison{}, fmt.Errorf("matrix comparison variant %q is not receipt-bound: %w", id, err)
		}
		if input.Evidence.Run.Status != "completed" {
			excluded = append(excluded, MatrixExcludedVariant{ID: id, Reason: "incomplete-capture", CaptureConfigSHA256: input.Evidence.CaptureConfigSHA256})
			continue
		}
		complete = append(complete, variantEvidence{id: id, evidence: input.Evidence, receipts: receipts})
	}
	if len(complete) < MinMatrixVariants {
		return MatrixComparison{}, fmt.Errorf("matrix comparison requires at least %d comparable complete captures; %d excluded", MinMatrixVariants, len(excluded))
	}

	reference := complete[0].evidence
	referenceReceipts := complete[0].receipts
	seenDigest := map[string]string{}
	for _, variant := range complete {
		if variant.receipts != referenceReceipts {
			return MatrixComparison{}, fmt.Errorf("matrix comparison requires captures that differ only in model/runtime configuration, but fixed configuration receipts differ for variant %q", variant.id)
		}
		if field := matrixInvariantMismatch(reference, variant.evidence); field != "" {
			return MatrixComparison{}, fmt.Errorf("matrix comparison requires captures that differ only in model/runtime configuration, but %s differs for variant %q", field, variant.id)
		}
		if other, ok := seenDigest[variant.evidence.CaptureConfigSHA256]; ok {
			return MatrixComparison{}, fmt.Errorf("matrix comparison variants %q and %q share the same capture configuration and are ambiguous", other, variant.id)
		}
		seenDigest[variant.evidence.CaptureConfigSHA256] = variant.id
	}

	comparison := MatrixComparison{
		Schema: MatrixComparisonSchema,
		Target: MatrixTarget{
			Name: reference.Target.Name, Kind: reference.Target.Kind, ID: reference.Target.ID,
			Lineage: reference.Target.Lineage, SHA256: reference.Target.SHA256,
		},
		PromptSHA256: reference.Exercise.PromptSHA256,
		TurnLimit:    reference.Exercise.TurnLimit,
		Coverage:     reference.Coverage,
		HeldConstant: MatrixConstants{
			CaptureProtocolRevision: referenceReceipts.CaptureProtocolRevision,
			FixedConfigSHA256:       referenceReceipts.FixedConfigSHA256,
			TargetConfigSHA256:      referenceReceipts.TargetConfigSHA256,
			ExecutorConfigSHA256:    referenceReceipts.ExecutorConfigSHA256,
			IsolationConfigSHA256:   referenceReceipts.IsolationConfigSHA256,
			RuntimeConstantsSHA256:  referenceReceipts.RuntimeConstantsSHA256,
			ModelRelayConfigSHA256:  referenceReceipts.ModelRelayConfigSHA256,
			MockEgressConfigSHA256:  referenceReceipts.MockEgressConfigSHA256,
			ExerciseConfigSHA256:    referenceReceipts.ExerciseConfigSHA256,
			RedirectConfigSHA256:    referenceReceipts.RedirectConfigSHA256,
			ResourceLimitsSHA256:    referenceReceipts.ResourceLimitsSHA256,
			ProxmoxTLSCASHA256:      referenceReceipts.ProxmoxTLSCASHA256,
			IsolationSubstrate:      reference.Run.Isolation.Substrate,
			IsolationNetworkMode:    reference.Run.Isolation.NetworkMode,
			ContainmentProfile:      reference.Run.Isolation.ContainmentProfile,
			Verification:            reference.Run.Isolation.Verification,
			OpenClawVersion:         reference.Run.Runtime.OpenClawVersion,
			StraceVersion:           reference.Run.Runtime.StraceVersion,
		},
		Excluded: excluded,
		Signals:  []MatrixSignalRow{},
		Canaries: []MatrixCanaryRow{},
	}

	orderedIDs := make([]string, 0, len(complete))
	for _, variant := range complete {
		orderedIDs = append(orderedIDs, variant.id)
	}
	observationDeltas := map[string]map[string]int{}
	observationMeta := map[string]Observation{}
	canaryDeltas := map[string]map[string]int{}
	canaryMeta := map[string]CanaryObservation{}
	for _, variant := range complete {
		totals := MatrixSignalTotals{}
		for _, observation := range variant.evidence.Observations {
			key := publicObservationKey(observation)
			if observationDeltas[key] == nil {
				observationDeltas[key] = map[string]int{}
				observationMeta[key] = observation
			}
			observationDeltas[key][variant.id] = observation.DeltaCount
			switch observation.Kind {
			case "file":
				totals.File += observation.DeltaCount
			case "process":
				totals.Process += observation.DeltaCount
			case "network":
				totals.Network += observation.DeltaCount
			}
		}
		for _, canary := range variant.evidence.Canaries {
			key := canary.ID + "\x00" + canary.Surface
			if canaryDeltas[key] == nil {
				canaryDeltas[key] = map[string]int{}
				canaryMeta[key] = canary
			}
			canaryDeltas[key][variant.id] = canary.DeltaInteractions
			totals.Canary += canary.DeltaInteractions
		}
		comparison.Variants = append(comparison.Variants, MatrixVariantSummary{
			ID:                        variant.id,
			RunID:                     variant.evidence.Run.ID,
			CaptureConfigSHA256:       variant.evidence.CaptureConfigSHA256,
			ModelProvider:             variant.evidence.Run.Runtime.ModelProvider,
			ModelID:                   variant.evidence.Run.Runtime.ModelID,
			ModelEndpoint:             variant.evidence.Run.Runtime.ModelEndpoint,
			GuestFirewallPolicySHA256: variant.evidence.Run.Isolation.GuestFirewallPolicySHA256,
			SignalTotals:              totals,
		})
	}

	for key, deltas := range observationDeltas {
		observation := observationMeta[key]
		comparison.Signals = append(comparison.Signals, MatrixSignalRow{
			Kind: observation.Kind, Operation: observation.Operation, Subject: observation.Subject,
			Outcome: observation.Outcome, Role: observation.Role,
			Deltas:  fillVariantDeltas(orderedIDs, deltas),
			Uniform: deltasUniform(orderedIDs, deltas),
		})
	}
	for key, deltas := range canaryDeltas {
		canary := canaryMeta[key]
		comparison.Canaries = append(comparison.Canaries, MatrixCanaryRow{
			ID: canary.ID, Surface: canary.Surface,
			Deltas:  fillVariantDeltas(orderedIDs, deltas),
			Uniform: deltasUniform(orderedIDs, deltas),
		})
	}

	sort.Slice(comparison.Variants, func(i, j int) bool { return comparison.Variants[i].ID < comparison.Variants[j].ID })
	sort.Slice(comparison.Signals, func(i, j int) bool {
		a, b := comparison.Signals[i], comparison.Signals[j]
		return a.Kind+"\x00"+a.Operation+"\x00"+a.Subject+"\x00"+a.Outcome+"\x00"+a.Role <
			b.Kind+"\x00"+b.Operation+"\x00"+b.Subject+"\x00"+b.Outcome+"\x00"+b.Role
	})
	sort.Slice(comparison.Canaries, func(i, j int) bool {
		return comparison.Canaries[i].ID+"\x00"+comparison.Canaries[i].Surface < comparison.Canaries[j].ID+"\x00"+comparison.Canaries[j].Surface
	})
	sortExcluded(comparison.Excluded)
	return comparison, nil
}

func matrixVariantIdentity(input MatrixComparisonInput) string {
	if trimmed := strings.TrimSpace(input.VariantID); trimmed != "" {
		return trimmed
	}
	digest := strings.TrimPrefix(input.Evidence.CaptureConfigSHA256, "sha256:")
	if len(digest) > 16 {
		digest = digest[:16]
	}
	return "config-" + digest
}

func validateMatrixInputBinding(input MatrixComparisonInput) (matrixConfigReceipts, error) {
	if input.EffectiveConfig == nil {
		return matrixConfigReceipts{}, errors.New("effective configuration is required")
	}
	config := *input.EffectiveConfig
	if len(config.Matrix.Variants) != 0 {
		return matrixConfigReceipts{}, errors.New("effective configuration must not carry a matrix block")
	}
	if err := config.Validate(); err != nil {
		return matrixConfigReceipts{}, fmt.Errorf("effective configuration is invalid: %w", err)
	}
	evidence := input.Evidence
	expected, err := captureConfigSHA256(config)
	if err != nil {
		return matrixConfigReceipts{}, fmt.Errorf("compute effective capture configuration digest: %w", err)
	}
	if evidence.CaptureConfigSHA256 != expected {
		return matrixConfigReceipts{}, fmt.Errorf("capture configuration digest %q does not match effective configuration %q", evidence.CaptureConfigSHA256, expected)
	}
	_, proxmoxTLSCASHA256, err := readAndValidateTLSCAFile(config.Executor.TLSCAFile, proxmoxAPIHostname(config.Executor.CrabboxConfig))
	if err != nil {
		return matrixConfigReceipts{}, fmt.Errorf("read effective Proxmox TLS CA: %w", err)
	}
	if evidence.Run.Isolation.ProxmoxTLSCASHA256 != proxmoxTLSCASHA256 {
		return matrixConfigReceipts{}, errors.New("Proxmox TLS CA receipt does not match effective configuration")
	}
	if evidence.Target.Lineage != config.TargetLineage {
		return matrixConfigReceipts{}, errors.New("target lineage does not match effective configuration")
	}
	if evidence.Run.Executor != config.Executor.Kind {
		return matrixConfigReceipts{}, errors.New("executor receipt does not match effective configuration")
	}
	if evidence.Run.Isolation.Substrate != config.Isolation.Substrate ||
		evidence.Run.Isolation.NetworkMode != config.Isolation.NetworkMode ||
		evidence.Run.Isolation.Verification != config.Isolation.Verification {
		return matrixConfigReceipts{}, errors.New("isolation receipt does not match effective configuration")
	}
	if evidence.Run.Isolation.GuestFirewallPolicySHA256 != digestBytes([]byte(guestFirewallRules("policy", config.Runtime.ControlPlaneAddresses, config.Runtime.ModelRelay, config.Runtime.MockEgress))) {
		return matrixConfigReceipts{}, errors.New("guest firewall policy receipt does not match the model endpoint allowlist")
	}
	if evidence.Run.Runtime.ModelProvider != config.Runtime.Model.Provider ||
		evidence.Run.Runtime.ModelID != config.Runtime.Model.ID ||
		evidence.Run.Runtime.ModelEndpoint != modelEndpointClass(config.Runtime.Model.BaseURL) {
		return matrixConfigReceipts{}, errors.New("model receipt does not match effective configuration")
	}
	if evidence.Exercise.PromptSHA256 != digestBytes([]byte(config.Exercise.Prompt)) || evidence.Exercise.TurnLimit != config.Exercise.TurnLimit {
		return matrixConfigReceipts{}, errors.New("exercise receipt does not match effective configuration")
	}
	return matrixInvariantReceipts(config, proxmoxTLSCASHA256), nil
}

func matrixInvariantMismatch(reference Evidence, other Evidence) string {
	switch {
	case reference.Target.SHA256 != other.Target.SHA256:
		return "target digest"
	case reference.Target.Kind != other.Target.Kind:
		return "target kind"
	case reference.Target.ID != other.Target.ID:
		return "target id"
	case reference.Target.Lineage != other.Target.Lineage:
		return "target lineage"
	case !reflect.DeepEqual(reference.Target, other.Target):
		return "target evidence"
	case reference.Exercise.PromptSHA256 != other.Exercise.PromptSHA256:
		return "exercise prompt"
	case reference.Exercise.TurnLimit != other.Exercise.TurnLimit:
		return "exercise turn limit"
	case !reflect.DeepEqual(reference.Coverage, other.Coverage):
		return "capture coverage"
	case reference.Run.Isolation.Substrate != other.Run.Isolation.Substrate:
		return "isolation substrate"
	case reference.Run.Isolation.NetworkMode != other.Run.Isolation.NetworkMode:
		return "isolation network mode"
	case reference.Run.Isolation.ContainmentProfile != other.Run.Isolation.ContainmentProfile:
		return "isolation containment profile"
	case reference.Run.Isolation.Verification != other.Run.Isolation.Verification:
		return "isolation verification receipt"
	case reference.Run.Isolation.ProxmoxTLSCASHA256 != other.Run.Isolation.ProxmoxTLSCASHA256:
		return "Proxmox TLS CA receipt"
	case reference.Run.Runtime.OpenClawVersion != other.Run.Runtime.OpenClawVersion:
		return "OpenClaw runtime version"
	case reference.Run.Runtime.StraceVersion != other.Run.Runtime.StraceVersion:
		return "strace version"
	}
	return ""
}

func fillVariantDeltas(ids []string, deltas map[string]int) map[string]int {
	filled := make(map[string]int, len(ids))
	for _, id := range ids {
		filled[id] = deltas[id]
	}
	return filled
}

func deltasUniform(ids []string, deltas map[string]int) bool {
	if len(ids) == 0 {
		return true
	}
	first := deltas[ids[0]]
	for _, id := range ids[1:] {
		if deltas[id] != first {
			return false
		}
	}
	return true
}

func sortExcluded(excluded []MatrixExcludedVariant) {
	sort.Slice(excluded, func(i, j int) bool {
		if excluded[i].ID != excluded[j].ID {
			return excluded[i].ID < excluded[j].ID
		}
		return excluded[i].Reason < excluded[j].Reason
	})
}

func sanitizeMatrixError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if line, _, ok := strings.Cut(message, "\n"); ok {
		message = line
	}
	message = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, message)
	if len(message) > 200 {
		message = message[:200]
	}
	return message
}
