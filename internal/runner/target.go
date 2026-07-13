package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openclaw/clawscan/internal/observatory"
)

// Target kinds recorded in run artifacts and used for scanner compatibility.
// skill and url preserve the historical Clawscan behavior; plugin is the
// first-class native OpenClaw plugin target added alongside them.
const (
	targetKindSkill  = "skill"
	targetKindPlugin = "plugin"
	targetKindURL    = "url"
)

const maxPluginManifestBytes = 1 << 20

// resolvedTarget is the small target abstraction the runner threads from the
// scan input through scanner dispatch and into the artifact. It carries enough
// to run scanners (resolvedPath), decide scanner compatibility (kind), and
// report a stable identity (id) without leaking that identity from a host path.
type resolvedTarget struct {
	kind         string
	input        string
	resolvedPath string
	// id is a stable, host-path-free identity. It is populated for plugin
	// targets from their manifest and empty for skills and URLs.
	id string
}

func resolveTarget(input string) (resolvedTarget, error) {
	if isURLTarget(input) {
		return resolvedTarget{kind: targetKindURL, input: input, resolvedPath: input}, nil
	}
	resolved, err := filepath.Abs(input)
	if err != nil {
		return resolvedTarget{}, err
	}
	if info, err := os.Lstat(resolved); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if evaluated, evalErr := filepath.EvalSymlinks(resolved); evalErr == nil {
			resolved = evaluated
		}
	}
	kind, id, err := classifyLocalTarget(resolved, input)
	if err != nil {
		return resolvedTarget{}, err
	}
	return resolvedTarget{kind: kind, input: input, resolvedPath: resolved, id: id}, nil
}

// classifyLocalTarget decides whether a resolved local path is a skill or a
// native plugin. It defaults to skill so existing skill scans, single-file
// targets, and missing paths behave exactly as before; only an explicit plugin
// manifest promotes the target to a plugin. A directory carrying both manifests
// is rejected as ambiguous rather than silently guessed.
func classifyLocalTarget(resolvedPath string, input string) (kind string, id string, err error) {
	info, statErr := os.Stat(resolvedPath)
	if statErr != nil {
		return targetKindSkill, "", nil
	}
	dir := resolvedPath
	if !info.IsDir() {
		switch filepath.Base(resolvedPath) {
		case observatory.PluginManifestName:
			dir = filepath.Dir(resolvedPath)
		default:
			// SKILL.md or any other single file keeps the historical skill kind.
			return targetKindSkill, "", nil
		}
	}
	hasPlugin := regularManifestExists(filepath.Join(dir, observatory.PluginManifestName))
	hasSkill := regularManifestExists(filepath.Join(dir, observatory.SkillManifestName))
	if !hasPlugin {
		return targetKindSkill, "", nil
	}
	if hasSkill {
		return "", "", fmt.Errorf("target %s contains both %s and %s; point Clawscan at a directory with exactly one manifest", displayTargetInput(input), observatory.SkillManifestName, observatory.PluginManifestName)
	}
	id, err = readPluginID(filepath.Join(dir, observatory.PluginManifestName))
	if err != nil {
		return "", "", fmt.Errorf("target %s is not a valid plugin: %w", displayTargetInput(input), err)
	}
	return targetKindPlugin, id, nil
}

// regularManifestExists reports whether path is an existing regular file
// without following symlinks. A target cannot present a symlinked or special
// manifest to be classified: an untrusted target could point its manifest at a
// host file outside the target, so only a real regular file counts here.
func regularManifestExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

// readPluginID parses the stable plugin identity from a plugin manifest and
// validates it against the canonical OpenClaw plugin identifier grammar shared
// with the Observatory stager, so a plugin the runner accepts also stages.
//
// It never follows a symlink: the manifest is opened O_NOFOLLOW and re-checked
// against a leading lstat, so a target that swaps its regular manifest for a
// symlink (racing between classification and read) fails closed instead of
// exposing an outside host file. The lstat/fstat identity check backstops
// platforms without an O_NOFOLLOW equivalent.
func readPluginID(manifestPath string) (string, error) {
	before, err := os.Lstat(manifestPath)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular file, not a symlink or special file", observatory.PluginManifestName)
	}
	file, err := os.OpenFile(manifestPath, os.O_RDONLY|openNoFollowFlag, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", fmt.Errorf("%s changed while it was being read", observatory.PluginManifestName)
	}
	if opened.Size() > maxPluginManifestBytes {
		return "", fmt.Errorf("%s exceeds 1 MiB", observatory.PluginManifestName)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPluginManifestBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxPluginManifestBytes {
		return "", fmt.Errorf("%s exceeds 1 MiB", observatory.PluginManifestName)
	}
	var manifest struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", fmt.Errorf("parse %s: %w", observatory.PluginManifestName, err)
	}
	id := strings.TrimSpace(manifest.ID)
	if !observatory.ValidPluginID(id) {
		return "", fmt.Errorf("%s has an invalid plugin id %q", observatory.PluginManifestName, id)
	}
	return id, nil
}

// displayTargetInput echoes the operator-provided target back in errors. It is
// the input the caller typed, not a resolved host path, so classification
// failures stay legible without widening host-path exposure.
func displayTargetInput(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return "the scan target"
	}
	return input
}

func isURLTarget(input string) bool {
	parsed, err := url.Parse(input)
	return err == nil && parsed.Scheme != "" && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

func runnableScanners(opts Options, kind string) []string {
	var scanners []string
	for _, scanner := range opts.Scanners {
		if opts.ScannerResultPaths[scanner] != "" || scannerSupportsTargetKind(scanner, kind) {
			scanners = append(scanners, scanner)
		}
	}
	return scanners
}

// scannerSupportsTargetKind reports whether a built-in scanner can run against a
// target of the given kind. Unknown scanner IDs are permitted here so the
// scanner runner can still emit its own skipped result for them.
func scannerSupportsTargetKind(scanner string, kind string) bool {
	adapter, ok := DefaultScannerRegistry().Adapter(scanner)
	if !ok {
		return true
	}
	return adapter.SupportsTargetKind(kind)
}

// unsupportedTargetKindResult is the explicit skipped result a skill-only
// scanner returns for a target kind it cannot analyze.
func unsupportedTargetKindResult(scanner string, kind string, startedAt string) ScannerResult {
	return ScannerResult{
		Status:      "skipped",
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Error:       fmt.Sprintf("Scanner %s does not support %s targets.", scanner, kind),
	}
}
