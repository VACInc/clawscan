package ciguard

import (
	"fmt"
	"strings"
	"testing"
)

const workflowDir = "../../.github/workflows"

// mvpWorkflows is the retained release-critical workflow set. Every file listed
// here is covered by the pinning and trust invariants below.
var mvpWorkflows = []string{
	"ci.yml",
	"profile-proposal-validate.yml",
	"skilltrustbench-benchmark.yml",
	"run-clawscan-benchmark.yml",
	"release.yml",
}

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
	if !workflow.DeclaresInput("commit_sha") {
		t.Fatal("run-clawscan-benchmark.yml must accept an exact commit_sha")
	}

	job, ok := workflow.Jobs["benchmark"]
	if !ok {
		t.Fatal("run-clawscan-benchmark.yml must define the benchmark job")
	}
	var verified, built bool
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "merge-base --is-ancestor") {
			verified = true
		}
		if strings.Contains(step.Run, "go build") {
			if !verified {
				t.Fatalf("step %q builds before the trusted-commit check", step.Name)
			}
			built = true
		}
	}
	if !verified {
		t.Error("benchmark job must verify that commit_sha is an ancestor of the trusted branch")
	}
	if !built {
		t.Error("benchmark job must build ClawScan")
	}
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

// TestMVPWorkflowsPinActions rejects mutable action tags in the retained
// release-critical workflows.
func TestMVPWorkflowsPinActions(t *testing.T) {
	byName := map[string]Workflow{}
	for _, workflow := range loadAll(t) {
		byName[workflow.Base()] = workflow
	}
	for _, name := range mvpWorkflows {
		workflow, ok := byName[name]
		if !ok {
			t.Errorf("retained MVP workflow %s is missing", name)
			continue
		}
		if unpinned := workflow.UnpinnedUses(); len(unpinned) > 0 {
			t.Errorf("%s uses mutable action references: %s", name, strings.Join(unpinned, ", "))
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

// TestPublicationWorkflowsPinActions covers the documentation publication path
// in addition to the retained MVP set.
func TestPublicationWorkflowsPinActions(t *testing.T) {
	for _, name := range []string{"pages.yml"} {
		workflow := findWorkflow(t, name)
		if unpinned := workflow.UnpinnedUses(); len(unpinned) > 0 {
			t.Errorf("%s uses mutable action references: %s", name, strings.Join(unpinned, ", "))
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
