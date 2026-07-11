package observatory

import (
	"context"
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

// BuildMatrixPlan validates the matrix and describes what running it would cost.
// It never provisions anything.
func BuildMatrixPlan(config Config) (MatrixPlan, error) {
	if len(config.Matrix.Variants) == 0 {
		return MatrixPlan{}, errors.New("no matrix.variants are defined in the configuration")
	}
	if err := config.validateMatrix(); err != nil {
		return MatrixPlan{}, err
	}
	plan := MatrixPlan{
		Schema:              MatrixPlanSchema,
		VariantCount:        len(config.Matrix.Variants),
		ResourceMultiplier:  len(config.Matrix.Variants),
		FreshVMsProvisioned: len(config.Matrix.Variants),
		Execution:           "sequential",
	}
	for _, variant := range config.Matrix.Variants {
		effective := config.VariantConfig(variant)
		plan.Variants = append(plan.Variants, MatrixPlanVariant{
			ID:                  variant.ID,
			ModelProvider:       effective.Runtime.Model.Provider,
			ModelID:             effective.Runtime.Model.ID,
			ModelEndpointClass:  modelEndpointClass(effective.Runtime.Model.BaseURL),
			TimeoutSeconds:      effective.Runtime.TimeoutSeconds,
			CaptureConfigSHA256: captureConfigSHA256(effective),
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
	plan, err := BuildMatrixPlan(config)
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
			run.Evidence = &evidence
			run.Status = evidence.Run.Status
			run.CaptureConfigSHA256 = evidence.CaptureConfigSHA256
			inputs = append(inputs, MatrixComparisonInput{VariantID: variant.ID, Evidence: evidence})
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

// MatrixComparisonInput pairs an operator label with a variant's evidence. The
// label is optional; offline callers with only evidence files fall back to a
// stable identity derived from the bound capture-config digest.
type MatrixComparisonInput struct {
	VariantID string
	Evidence  Evidence
}

// MatrixComparison is a structured, side-by-side comparison of grade-ready
// behavioral signals across model/runtime variants that hold everything except
// the model/runtime axis constant. It has no verdict, score, or recommendation.
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
	IsolationSubstrate   string `json:"isolationSubstrate"`
	IsolationNetworkMode string `json:"isolationNetworkMode"`
	ContainmentProfile   string `json:"containmentProfile"`
	Verification         string `json:"verification"`
	OpenClawVersion      string `json:"openclawVersion"`
	StraceVersion        string `json:"straceVersion"`
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
		if input.Evidence.Run.Status != "completed" {
			excluded = append(excluded, MatrixExcludedVariant{ID: id, Reason: "incomplete-capture", CaptureConfigSHA256: input.Evidence.CaptureConfigSHA256})
			continue
		}
		complete = append(complete, variantEvidence{id: id, evidence: input.Evidence})
	}
	if len(complete) < MinMatrixVariants {
		return MatrixComparison{}, fmt.Errorf("matrix comparison requires at least %d comparable complete captures; %d excluded", MinMatrixVariants, len(excluded))
	}

	reference := complete[0].evidence
	seenDigest := map[string]string{}
	for _, variant := range complete {
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
			IsolationSubstrate:   reference.Run.Isolation.Substrate,
			IsolationNetworkMode: reference.Run.Isolation.NetworkMode,
			ContainmentProfile:   reference.Run.Isolation.ContainmentProfile,
			Verification:         reference.Run.Isolation.Verification,
			OpenClawVersion:      reference.Run.Runtime.OpenClawVersion,
			StraceVersion:        reference.Run.Runtime.StraceVersion,
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
