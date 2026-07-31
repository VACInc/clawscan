// Command validate-profile-proposal validates an untrusted ClawHub profile
// proposal as data.
//
// It is the pull-request lane of the SkillTrustBench profile gate. It never
// executes a profile field, never resolves a referenced prompt or schema file,
// never contacts the network, and never requires a repository or provider
// secret. Executing a proposed profile requires a separate maintainer-triggered
// lane running a reviewed, trusted commit.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/openclaw/clawscan/internal/profiles"
)

const maxProposalBytes = 256 * 1024

var (
	proposalPathPattern = regexp.MustCompile(`^proposals/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/clawscan\.yml$`)
	baselinePathPattern = regexp.MustCompile(`^benchmarks/skilltrustbench-leaderboard-10pct/[0-9]{4}-[0-9]{2}-[0-9]{2}\.json$`)
	baselineDatePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// promotedProfilePaths are maintainer-owned bundled profile files that a
// proposal pull request is allowed to touch alongside its proposal.
var promotedProfilePaths = []string{
	"internal/profiles/clawhub/clawscan.yml",
	"internal/profiles/clawhub/prompt.md",
	"internal/profiles/clawhub/output.schema.json",
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("validate-profile-proposal", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		root         = flags.String("root", ".", "Repository root that contains the proposal.")
		proposal     = flags.String("proposal", "", "Proposal path, for example proposals/GHSA-xxxx-yyyy-zzzz/clawscan.yml.")
		changedFiles = flags.String("changed-files", "", "Optional file holding one changed path per line, produced by a trusted diff.")
		baselineDate = flags.String("baseline-date", "", "Expected baseline date (YYYY-MM-DD) for this run.")
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*proposal) == "" {
		return errors.New("--proposal is required")
	}
	if err := validateProposalPath(*proposal); err != nil {
		return err
	}
	if *baselineDate != "" && !baselineDatePattern.MatchString(*baselineDate) {
		return fmt.Errorf("--baseline-date must be YYYY-MM-DD, got %q", *baselineDate)
	}

	data, err := readRegularFile(path.Join(*root, *proposal), maxProposalBytes)
	if err != nil {
		return err
	}
	config, err := profiles.ValidateConfigBytes(*proposal, data)
	if err != nil {
		return err
	}

	if *changedFiles != "" {
		listed, err := readRegularFile(*changedFiles, maxProposalBytes)
		if err != nil {
			return err
		}
		if err := validateChangedFiles(*proposal, *baselineDate, strings.Split(string(listed), "\n")); err != nil {
			return err
		}
	}

	names := make([]string, 0, len(config.Profiles))
	for name := range config.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintf(stdout, "proposal: %s\n", *proposal)
	fmt.Fprintf(stdout, "profiles: %s\n", strings.Join(names, ", "))
	for _, name := range names {
		profile := config.Profiles[name]
		judge := "none"
		if profile.Judge != nil {
			judge = "declared"
		}
		fmt.Fprintf(stdout, "profile %s: scanners=%s judge=%s\n", name, strings.Join(profile.Scanners, ","), judge)
	}
	fmt.Fprintln(stdout, "validated as data; no profile field was executed")
	return nil
}

func validateProposalPath(proposal string) error {
	if proposal != path.Clean(proposal) || path.IsAbs(proposal) || strings.Contains(proposal, "..") {
		return fmt.Errorf("proposal path must be a clean repository-relative path: %s", proposal)
	}
	if !proposalPathPattern.MatchString(proposal) {
		return fmt.Errorf("proposal path must match proposals/<GHSA-ID>/clawscan.yml: %s", proposal)
	}
	return nil
}

func readRegularFile(target string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(target)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", target)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", target, maxBytes)
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", target, maxBytes)
	}
	return data, nil
}

// validateChangedFiles enforces the proposal pull-request file scope. The diff
// itself is produced by the trusted side; this function only classifies paths.
func validateChangedFiles(proposal string, baselineDate string, changed []string) error {
	var unexpected []string
	for _, raw := range changed {
		candidate := strings.TrimSpace(raw)
		if candidate == "" {
			continue
		}
		if candidate == proposal {
			continue
		}
		if slicesContains(promotedProfilePaths, candidate) {
			continue
		}
		if baselinePathPattern.MatchString(candidate) {
			date := strings.TrimSuffix(path.Base(candidate), ".json")
			if baselineDate != "" && date > baselineDate {
				unexpected = append(unexpected, candidate+" (future-dated baseline)")
				continue
			}
			continue
		}
		unexpected = append(unexpected, candidate)
	}
	if len(unexpected) > 0 {
		return fmt.Errorf(
			"profile proposal pull requests may only change the proposal, non-future dated baselines, and maintainer-promoted bundled profile files; unexpected paths:\n  %s",
			strings.Join(unexpected, "\n  "),
		)
	}
	return nil
}

func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
