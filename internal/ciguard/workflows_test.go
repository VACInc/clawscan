package ciguard

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

const workflowDir = "../../.github/workflows"

func loadAll(t *testing.T) []Workflow {
	t.Helper()
	workflows, err := Load(workflowDir)
	if err != nil {
		t.Fatalf("load workflows: %v", err)
	}
	return workflows
}

func TestWorkflowsParse(t *testing.T) {
	for _, workflow := range loadAll(t) {
		if len(workflow.Jobs) == 0 {
			t.Errorf("%s declares no jobs", workflow.Base())
		}
		if len(workflow.Triggers()) == 0 {
			t.Errorf("%s declares no triggers", workflow.Base())
		}
	}
}

// TestNoSecretBearingJobConsumesUntrustedRefs is the workflow-graph half of the
// SkillTrustBench profile-gate trust repair. A job that can observe secrets must
// not select, check out, or forward a pull-request-controlled ref or config.
func TestNoSecretBearingJobConsumesUntrustedRefs(t *testing.T) {
	for _, workflow := range loadAll(t) {
		for name, job := range workflow.Jobs {
			if !job.SecretBearing() {
				continue
			}
			if reasons := job.ConsumesUntrustedRef(); len(reasons) > 0 {
				t.Errorf("%s job %q holds secrets and consumes untrusted input: %s",
					workflow.Base(), name, strings.Join(reasons, "; "))
			}
		}
	}
}

// TestNoWorkflowCheckoutOfPullRequestBranches keeps `gh pr checkout` out of
// every retained workflow. Reviewing a proposal never requires materializing an
// unreviewed branch in a workflow that a maintainer dispatches.
func TestNoWorkflowCheckoutOfPullRequestBranches(t *testing.T) {
	for _, workflow := range loadAll(t) {
		for name, job := range workflow.Jobs {
			for _, step := range job.Steps {
				if strings.Contains(step.Run, "gh pr checkout") {
					t.Errorf("%s job %q step %q runs gh pr checkout", workflow.Base(), name, step.Name)
				}
			}
		}
	}
}

// TestBenchmarkWorkflowRequiresTrustedCommit proves the benchmark lane cannot be
// pointed at an arbitrary ref: it accepts a commit SHA and verifies ancestry
// against the trusted branch before building anything.
func TestBenchmarkWorkflowRequiresTrustedCommit(t *testing.T) {
	workflow := findWorkflow(t, "run-clawscan-benchmark.yml")
	for _, name := range untrustedInputNames {
		if workflow.DeclaresInput(name) {
			t.Errorf("run-clawscan-benchmark.yml still declares untrusted input %q", name)
		}
	}
	if errors := benchmarkTrustErrors(workflow); len(errors) > 0 {
		t.Fatalf("run-clawscan-benchmark.yml trust guard is incomplete: %s", strings.Join(errors, "; "))
	}
	if !strings.Contains(workflow.Raw, "sandbox_image must be pinned by sha256 digest") {
		t.Error("benchmark workflow must fail closed on a tag-only runtime image")
	}
}

func benchmarkTrustErrors(workflow Workflow) []string {
	var problems []string
	for _, trigger := range []string{"workflow_dispatch", "workflow_call"} {
		if !workflow.RequiresInput(trigger, "commit_sha") {
			problems = append(problems, trigger+" does not require commit_sha")
		}
	}
	job, ok := workflow.Jobs["benchmark"]
	if !ok {
		return append(problems, "benchmark job is missing")
	}
	verified := false
	for _, step := range job.Steps {
		ancestryIndex := strings.Index(step.Run, "merge-base --is-ancestor")
		checkoutIndex := strings.Index(step.Run, "git checkout --detach")
		if ancestryIndex >= 0 {
			if strings.TrimSpace(step.If) != "" {
				problems = append(problems, "ancestry validation is conditional")
			}
			if !strings.Contains(step.Run, "git ls-remote --exit-code --refs") ||
				!strings.Contains(step.Run, `"$TRUSTED_SHA"`) {
				problems = append(problems, "trusted_ref is not resolved to an exact SHA")
			}
			if checkoutIndex < 0 || checkoutIndex < ancestryIndex {
				problems = append(problems, "detached checkout does not follow ancestry validation")
			}
			verified = true
		}
		if isCheckout(step.Uses) && !verified {
			problems = append(problems, "checkout action runs before ancestry validation")
		}
		if strings.Contains(step.Run, "go build") {
			if !verified {
				problems = append(problems, fmt.Sprintf("step %q builds before the trusted-commit check", step.Name))
			}
		}
	}
	if !verified {
		problems = append(problems, "benchmark job does not verify commit ancestry")
	}
	return problems
}

func TestBenchmarkTrustGuardRejectsOptionalOrConditionalValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Workflow)
	}{
		{
			name: "optional workflow dispatch SHA",
			mutate: func(workflow *Workflow) {
				setInputRequired(t, workflow, "workflow_dispatch", "commit_sha", false)
			},
		},
		{
			name: "optional workflow call SHA",
			mutate: func(workflow *Workflow) {
				setInputRequired(t, workflow, "workflow_call", "commit_sha", false)
			},
		},
		{
			name: "conditional ancestry step",
			mutate: func(workflow *Workflow) {
				job := workflow.Jobs["benchmark"]
				job.Steps[0].If = `${{ inputs.commit_sha != '' }}`
				workflow.Jobs["benchmark"] = job
			},
		},
		{
			name: "checkout before ancestry",
			mutate: func(workflow *Workflow) {
				job := workflow.Jobs["benchmark"]
				job.Steps[0].Run = "git checkout --detach \"$COMMIT_SHA\"\n" + job.Steps[0].Run
				workflow.Jobs["benchmark"] = job
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workflow := findWorkflow(t, "run-clawscan-benchmark.yml")
			test.mutate(&workflow)
			if problems := benchmarkTrustErrors(workflow); len(problems) == 0 {
				t.Fatal("mutated workflow unexpectedly passed the trust guard")
			}
		})
	}
}

func TestSkillTrustBenchCallerPassesOnlyRequiredSecrets(t *testing.T) {
	workflow := findWorkflow(t, "skilltrustbench-benchmark.yml")
	job, ok := workflow.Jobs["run-benchmark"]
	if !ok {
		t.Fatal("skilltrustbench-benchmark.yml must define run-benchmark")
	}
	secrets, ok := job.Secrets.(map[string]any)
	if !ok {
		t.Fatalf("run-benchmark secrets = %#v", job.Secrets)
	}
	var names []string
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "CODEX_API_KEY,OPENAI_API_KEY,VIRUSTOTAL_API_KEY" {
		t.Fatalf("SkillTrustBench secret set = %q", got)
	}

	reusable := findWorkflow(t, "run-clawscan-benchmark.yml")
	benchmark := reusable.Jobs["benchmark"]
	var skillTrustStep, genericStep *Step
	for index := range benchmark.Steps {
		step := &benchmark.Steps[index]
		switch step.Name {
		case "Run SkillTrustBench benchmark":
			skillTrustStep = step
		case "Run benchmark":
			genericStep = step
		}
	}
	if skillTrustStep == nil || genericStep == nil {
		t.Fatal("reusable benchmark workflow must separate SkillTrustBench from the generic credential scope")
	}
	names = names[:0]
	for name, value := range skillTrustStep.Env {
		if secretExpression.MatchString(fmt.Sprint(value)) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "CODEX_API_KEY,OPENAI_API_KEY,VIRUSTOTAL_API_KEY" {
		t.Fatalf("SkillTrustBench command secret env = %q", got)
	}
	if !strings.Contains(skillTrustStep.If, "contains(") || !strings.Contains(genericStep.If, "!contains(") {
		t.Fatal("SkillTrustBench and generic benchmark command steps are not mutually exclusive")
	}
}

func setInputRequired(t *testing.T, workflow *Workflow, triggerName string, inputName string, required bool) {
	t.Helper()
	on := workflow.On.(map[string]any)
	trigger := on[triggerName].(map[string]any)
	inputs := trigger["inputs"].(map[string]any)
	input := inputs[inputName].(map[string]any)
	input["required"] = required
}

// TestProposalLaneIsUnprivileged proves the pull-request lane runs read-only,
// without secrets, and without pushing anything back to the proposal branch.
func TestProposalLaneIsUnprivileged(t *testing.T) {
	workflow := findWorkflow(t, "profile-proposal-validate.yml")
	if writes := WritePermissions(workflow.Permissions); len(writes) > 0 {
		t.Errorf("proposal lane grants write permissions: %v", writes)
	}
	for name, job := range workflow.Jobs {
		if job.SecretBearing() {
			t.Errorf("proposal lane job %q is secret bearing", name)
		}
		if writes := WritePermissions(job.Permissions); len(writes) > 0 {
			t.Errorf("proposal lane job %q grants write permissions: %v", name, writes)
		}
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "git push") {
				t.Errorf("proposal lane job %q step %q pushes commits", name, step.Name)
			}
		}
	}
	if !strings.Contains(workflow.Raw, "validate-profile-proposal") {
		t.Error("proposal lane must run the data-only proposal validator")
	}
}

// TestNoWorkflowPushesToPullRequestBranches covers T4 of the release-gate
// ledger across the whole workflow set.
func TestNoWorkflowPushesToPullRequestBranches(t *testing.T) {
	for _, workflow := range loadAll(t) {
		for name, job := range workflow.Jobs {
			pushes := false
			for _, step := range job.Steps {
				if strings.Contains(step.Run, "git push") {
					pushes = true
				}
			}
			if !pushes {
				continue
			}
			if reasons := job.ConsumesUntrustedRef(); len(reasons) > 0 {
				t.Errorf("%s job %q pushes commits while consuming untrusted input: %s",
					workflow.Base(), name, strings.Join(reasons, "; "))
			}
		}
	}
}

// TestEveryWorkflowPinsActions rejects mutable action tags anywhere in the
// workflow directory, including newly added publication or automation files.
func TestEveryWorkflowPinsActions(t *testing.T) {
	for _, workflow := range loadAll(t) {
		if unpinned := workflow.UnpinnedUses(); len(unpinned) > 0 {
			t.Errorf("%s uses mutable action references: %s", workflow.Base(), strings.Join(unpinned, ", "))
		}
	}
}

// TestEveryWorkflowDeclaresPermissions rejects workflows that fall back to the
// repository default token scope.
func TestEveryWorkflowDeclaresPermissions(t *testing.T) {
	for _, workflow := range loadAll(t) {
		if workflow.Permissions == nil {
			t.Errorf("%s does not declare top-level permissions", workflow.Base())
			continue
		}
		if writes := WritePermissions(workflow.Permissions); slicesHas(writes, "write-all") {
			t.Errorf("%s grants write-all", workflow.Base())
		}
	}
}

func slicesHas(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// TestSecretBearingJobsAreDispatchOnly proves no push, pull_request, or issue
// event can start a job that holds secrets and executes repository code in the
// retained gate path.
func TestSecretBearingJobsAreDispatchOnly(t *testing.T) {
	for _, name := range []string{"profile-proposal-validate.yml", "skilltrustbench-benchmark.yml"} {
		workflow := findWorkflow(t, name)
		secretBearing := false
		for _, job := range workflow.Jobs {
			if job.SecretBearing() {
				secretBearing = true
			}
		}
		if !secretBearing {
			continue
		}
		for _, trigger := range workflow.Triggers() {
			switch trigger {
			case "workflow_dispatch", "workflow_call":
			default:
				t.Errorf("%s exposes secrets on trigger %q", name, trigger)
			}
		}
	}
}

func findWorkflow(t *testing.T, base string) Workflow {
	t.Helper()
	for _, workflow := range loadAll(t) {
		if workflow.Base() == base {
			return workflow
		}
	}
	t.Fatalf("workflow %s not found", base)
	return Workflow{}
}

func TestSecretBearingDetection(t *testing.T) {
	cases := []struct {
		job  Job
		want bool
	}{
		{Job{Secrets: "inherit"}, true},
		{Job{Secrets: map[string]any{"LLM_API_KEY": "${{ secrets.LLM_API_KEY }}"}}, true},
		{Job{Steps: []Step{{Env: map[string]any{"TOKEN": "${{ secrets.SNYK_TOKEN }}"}}}}, true},
		{Job{Steps: []Step{{Run: "echo ${{ secrets.VIRUSTOTAL_API_KEY }}"}}}, true},
		{Job{Steps: []Step{{Run: "go test ./..."}}}, false},
		{Job{Steps: []Step{{Env: map[string]any{"GH_TOKEN": "${{ github.token }}"}}}}, false},
	}
	for index, testCase := range cases {
		if got := testCase.job.SecretBearing(); got != testCase.want {
			t.Errorf("case %d: SecretBearing()=%v want %v", index, got, testCase.want)
		}
	}
}

func TestUntrustedRefDetection(t *testing.T) {
	job := Job{
		With:  map[string]any{"pr_number": "${{ inputs.pr_number }}"},
		Steps: []Step{{Name: "checkout pr", Run: `gh pr checkout "$PR_NUMBER"`}},
	}
	reasons := job.ConsumesUntrustedRef()
	if len(reasons) != 2 {
		t.Fatalf("expected two reasons, got %v", reasons)
	}
	checkoutJob := Job{Steps: []Step{{
		Name: "checkout",
		Uses: "actions/checkout@" + strings.Repeat("a", 40),
		With: map[string]any{"ref": "${{ github.event.pull_request.head.sha }}"},
	}}}
	if got := checkoutJob.ConsumesUntrustedRef(); len(got) != 1 {
		t.Fatalf("expected untrusted checkout detection, got %v", got)
	}
}

func TestUnpinnedUsesDetection(t *testing.T) {
	workflow := Workflow{Jobs: map[string]Job{
		"build": {Steps: []Step{
			{Uses: "actions/checkout@v4"},
			{Uses: "actions/setup-go@" + strings.Repeat("b", 40)},
			{Uses: "./.github/actions/local"},
		}},
	}}
	unpinned := workflow.UnpinnedUses()
	if len(unpinned) != 1 || !strings.Contains(unpinned[0], "actions/checkout@v4") {
		t.Fatalf("unexpected unpinned set: %v", unpinned)
	}
}

func TestWritePermissionsDetection(t *testing.T) {
	if got := WritePermissions(map[string]any{"contents": "write", "pull-requests": "read"}); fmt.Sprint(got) != "[contents]" {
		t.Fatalf("unexpected write scopes: %v", got)
	}
	if got := WritePermissions("write-all"); len(got) != 1 {
		t.Fatalf("expected write-all detection, got %v", got)
	}
	if got := WritePermissions(map[string]any{"contents": "read"}); len(got) != 0 {
		t.Fatalf("expected no write scopes, got %v", got)
	}
}
