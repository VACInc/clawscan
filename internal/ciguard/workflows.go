// Package ciguard models GitHub Actions workflow definitions well enough to
// assert trust-boundary invariants about them.
//
// The invariants this package supports are semantic rather than textual: they
// describe which jobs can hold credentials and which jobs can be influenced by
// an unreviewed pull request, instead of searching for particular spellings such
// as "secrets: inherit".
package ciguard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow is the subset of a workflow file this package reasons about.
type Workflow struct {
	Path        string
	Name        string         `yaml:"name"`
	Permissions any            `yaml:"permissions"`
	Jobs        map[string]Job `yaml:"jobs"`

	// Raw keeps the original document so text-level checks (expression usage)
	// can run against the exact bytes that GitHub evaluates.
	Raw string `yaml:"-"`
	// On is intentionally decoded as a free-form node: the trigger key accepts
	// a string, a list, or a mapping.
	On any `yaml:"on"`
}

// Job is the subset of a workflow job this package reasons about.
type Job struct {
	Name        string         `yaml:"name"`
	Uses        string         `yaml:"uses"`
	Secrets     any            `yaml:"secrets"`
	Permissions any            `yaml:"permissions"`
	With        map[string]any `yaml:"with"`
	Env         map[string]any `yaml:"env"`
	Steps       []Step         `yaml:"steps"`
}

// Step is the subset of a workflow step this package reasons about.
type Step struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
	Env  map[string]any `yaml:"env"`
}

var (
	secretExpression = regexp.MustCompile(`\$\{\{\s*secrets\.[A-Za-z0-9_]+`)
	pinnedUses       = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)

	// untrustedInputNames are workflow inputs whose value selects code or
	// configuration authored by an unreviewed pull request.
	untrustedInputNames = []string{"pr_number", "pr_ref", "pr_branch", "head_ref", "head_sha"}
)

// Load reads every workflow definition in dir.
func Load(dir string) ([]Workflow, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, err
	}
	extra, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	matches = append(matches, extra...)
	sort.Strings(matches)

	workflows := make([]Workflow, 0, len(matches))
	for _, match := range matches {
		data, err := os.ReadFile(match)
		if err != nil {
			return nil, err
		}
		var workflow Workflow
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			return nil, fmt.Errorf("parse %s: %w", match, err)
		}
		workflow.Path = match
		workflow.Raw = string(data)
		workflows = append(workflows, workflow)
	}
	if len(workflows) == 0 {
		return nil, fmt.Errorf("no workflows found in %s", dir)
	}
	return workflows, nil
}

// Base returns the workflow file name.
func (w Workflow) Base() string { return filepath.Base(w.Path) }

// SecretBearing reports whether the job can observe repository or organization
// secrets, either by inheriting them, by being handed named secrets, or by
// referencing a secret expression anywhere in its own definition.
func (j Job) SecretBearing() bool {
	switch secrets := j.Secrets.(type) {
	case string:
		if strings.EqualFold(strings.TrimSpace(secrets), "inherit") {
			return true
		}
	case map[string]any:
		if len(secrets) > 0 {
			return true
		}
	}
	return jobReferencesSecrets(j)
}

func jobReferencesSecrets(j Job) bool {
	if mapReferencesSecrets(j.With) || mapReferencesSecrets(j.Env) {
		return true
	}
	for _, step := range j.Steps {
		if secretExpression.MatchString(step.Run) ||
			mapReferencesSecrets(step.With) ||
			mapReferencesSecrets(step.Env) {
			return true
		}
	}
	return false
}

func mapReferencesSecrets(values map[string]any) bool {
	for _, value := range values {
		if secretExpression.MatchString(fmt.Sprint(value)) {
			return true
		}
	}
	return false
}

// ConsumesUntrustedRef reports whether the job selects, checks out, or otherwise
// resolves a pull-request-controlled ref or a pull-request-controlled config
// path.
func (j Job) ConsumesUntrustedRef() []string {
	var reasons []string
	for key, value := range j.With {
		rendered := fmt.Sprint(value)
		for _, name := range untrustedInputNames {
			if strings.EqualFold(key, name) ||
				strings.Contains(rendered, "inputs."+name) ||
				strings.Contains(rendered, "github.event.pull_request") {
				reasons = append(reasons, fmt.Sprintf("passes untrusted input %q", key))
				break
			}
		}
	}
	for _, step := range j.Steps {
		if strings.Contains(step.Run, "gh pr checkout") {
			reasons = append(reasons, fmt.Sprintf("step %q runs gh pr checkout", step.Name))
		}
		if strings.Contains(step.Run, "gh pr diff") || strings.Contains(step.Run, "gh pr view") {
			// Reading PR metadata is not by itself a code-execution boundary,
			// so it is reported but not treated as a checkout.
			continue
		}
		if isCheckout(step.Uses) {
			ref := fmt.Sprint(step.With["ref"])
			for _, name := range untrustedInputNames {
				if strings.Contains(ref, "inputs."+name) || strings.Contains(ref, "github.event.pull_request") {
					reasons = append(reasons, fmt.Sprintf("step %q checks out %s", step.Name, ref))
					break
				}
			}
		}
		for _, name := range untrustedInputNames {
			if strings.Contains(step.Run, "inputs."+name) {
				reasons = append(reasons, fmt.Sprintf("step %q interpolates inputs.%s", step.Name, name))
				break
			}
		}
	}
	sort.Strings(reasons)
	return reasons
}

func isCheckout(uses string) bool {
	return strings.HasPrefix(uses, "actions/checkout@")
}

// UnpinnedUses returns every non-local action reference that is not pinned to a
// full commit SHA.
func (w Workflow) UnpinnedUses() []string {
	var unpinned []string
	for name, job := range w.Jobs {
		if job.Uses != "" && !strings.HasPrefix(job.Uses, "./") && !pinnedUses.MatchString(job.Uses) {
			unpinned = append(unpinned, fmt.Sprintf("%s: %s", name, job.Uses))
		}
		for _, step := range job.Steps {
			if step.Uses == "" || strings.HasPrefix(step.Uses, "./") {
				continue
			}
			if !pinnedUses.MatchString(step.Uses) {
				unpinned = append(unpinned, fmt.Sprintf("%s: %s", name, step.Uses))
			}
		}
	}
	sort.Strings(unpinned)
	return unpinned
}

// WritePermissions returns the permission scopes granted at workflow level that
// are not read-only.
func WritePermissions(permissions any) []string {
	scopes, ok := permissions.(map[string]any)
	if !ok {
		if rendered, isString := permissions.(string); isString && strings.EqualFold(rendered, "write-all") {
			return []string{"write-all"}
		}
		return nil
	}
	var writes []string
	for scope, value := range scopes {
		if strings.EqualFold(fmt.Sprint(value), "write") {
			writes = append(writes, scope)
		}
	}
	sort.Strings(writes)
	return writes
}

// Triggers returns the workflow trigger names.
func (w Workflow) Triggers() []string {
	switch on := w.On.(type) {
	case string:
		return []string{on}
	case []any:
		names := make([]string, 0, len(on))
		for _, value := range on {
			names = append(names, fmt.Sprint(value))
		}
		sort.Strings(names)
		return names
	case map[string]any:
		names := make([]string, 0, len(on))
		for name := range on {
			names = append(names, name)
		}
		sort.Strings(names)
		return names
	}
	return nil
}

// DeclaresInput reports whether a workflow declares the named input for any
// trigger.
func (w Workflow) DeclaresInput(name string) bool {
	on, ok := w.On.(map[string]any)
	if !ok {
		return false
	}
	for _, trigger := range on {
		triggerMap, ok := trigger.(map[string]any)
		if !ok {
			continue
		}
		inputs, ok := triggerMap["inputs"].(map[string]any)
		if !ok {
			continue
		}
		if _, exists := inputs[name]; exists {
			return true
		}
	}
	return false
}
