package ciguard

import (
	"os"
	"strings"
	"testing"
)

const releaseScriptPath = "../../scripts/build-release.sh"

// TestReleasePackagingIsObservatoryComplete asserts the archive contents the
// MVP promises: both CLIs, documentation, a configuration example, the license,
// limitations, the proof-packet index, and checksums.
func TestReleasePackagingIsObservatoryComplete(t *testing.T) {
	data, err := os.ReadFile(releaseScriptPath)
	if err != nil {
		t.Fatalf("read release script: %v", err)
	}
	script := string(data)
	required := []string{
		"cmd/clawscan",
		"cmd/observatory",
		"observatory_platforms",
		"cp README.md",
		"cp LICENSE",
		"cp docs/observatory.md",
		"observatory.example.yml",
		"LIMITATIONS.md",
		"PROOF-PACKET.md",
		"shasum -a 256",
	}
	for _, needle := range required {
		if !strings.Contains(script, needle) {
			t.Errorf("release packaging is missing %q", needle)
		}
	}
}

// TestReleasePackagingPublishesNothing keeps the local release path build-only.
func TestReleasePackagingPublishesNothing(t *testing.T) {
	data, err := os.ReadFile(releaseScriptPath)
	if err != nil {
		t.Fatalf("read release script: %v", err)
	}
	script := string(data)
	forbidden := []string{"npm publish", "gh release", "curl ", "wget ", "brew "}
	for _, needle := range forbidden {
		if strings.Contains(script, needle) {
			t.Errorf("release packaging performs external publication: %q", needle)
		}
	}
}

// TestOfficialNamespacePublicationIsUpstreamOnly proves a fork cannot mutate the
// official npm package or Homebrew formula, and that a tagless preflight cannot
// publish anything at all.
func TestOfficialNamespacePublicationIsUpstreamOnly(t *testing.T) {
	release := findWorkflow(t, "release.yml")
	guarded := 0
	for name, job := range release.Jobs {
		if !jobPublishesOfficialNamespace(job) {
			continue
		}
		guarded++
		condition := jobCondition(t, release.Raw, name)
		if !strings.Contains(condition, "github.repository == 'openclaw/clawscan'") {
			t.Errorf("release.yml job %q can publish to an official namespace without an upstream-repository guard: %q", name, condition)
		}
		if !strings.Contains(condition, "startsWith(needs.build.outputs.version, 'v')") {
			t.Errorf("release.yml job %q can publish without a version tag: %q", name, condition)
		}
	}

	if guarded < 2 {
		t.Fatalf("expected the npm and Homebrew publication jobs to be inspected, inspected %d", guarded)
	}

	npmRelease := findWorkflow(t, "npm-release.yml")
	if !strings.Contains(npmRelease.Raw, "github.repository == 'openclaw/clawscan'") {
		t.Error("npm-release.yml does not restrict publication to the upstream repository")
	}
	if !strings.Contains(npmRelease.Raw, "Publishing @openclaw/clawscan is restricted to openclaw/clawscan") {
		t.Error("npm-release.yml does not fail closed on a fork before publishing")
	}
}

// TestTaglessReleaseBuildCannotPublish proves the GitHub Release job requires a
// version tag even when a maintainer dispatches the workflow.
func TestTaglessReleaseBuildCannotPublish(t *testing.T) {
	release := findWorkflow(t, "release.yml")
	condition := jobCondition(t, release.Raw, "publish")
	if !strings.Contains(condition, "startsWith(needs.build.outputs.version, 'v')") {
		t.Fatalf("a tagless release build can still publish a GitHub Release: %q", condition)
	}
}

func jobPublishesOfficialNamespace(job Job) bool {
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "npm publish") ||
			strings.Contains(step.Run, "homebrew") ||
			strings.Contains(step.Run, "update-formula.yml") {
			return true
		}
	}
	return false
}

// jobCondition extracts the raw `if:` expression declared for a job. The parsed
// model intentionally does not carry conditions, because GitHub evaluates the
// literal expression text.
func jobCondition(t *testing.T, raw string, job string) string {
	t.Helper()
	marker := "\n  " + job + ":\n"
	start := strings.Index(raw, marker)
	if start < 0 {
		t.Fatalf("job %q not found", job)
	}
	body := raw[start+len(marker):]
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "if:") {
			return trimmed
		}
		if strings.HasPrefix(trimmed, "steps:") {
			break
		}
		if len(line) > 0 && !strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "  ") {
			break
		}
	}
	return ""
}
