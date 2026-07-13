package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const probePluginManifest = `{
  "id": "observatory-probe",
  "name": "Observatory Probe Plugin",
  "contracts": { "tools": ["observatory_probe"] }
}`

const behaviorPluginFixture = `{
  "schemaVersion":"observatory.behavior.v1",
  "captureConfigSha256":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "target":{"name":"Observatory Probe Plugin","kind":"plugin","id":"observatory-probe","declaredTools":["observatory_probe"],"sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","fileCount":1,"directoryCount":1,"totalBytes":7,"files":[{"path":"openclaw.plugin.json","bytes":7,"mode":"0644"}],"directories":[{"path":".","mode":"0755"}]},
  "run":{"id":"obs_test","status":"completed","startedAt":"2026-07-10T12:00:00Z","completedAt":"2026-07-10T12:00:01Z","durationMs":1000,"executor":"fixture","isolation":{"substrate":"fixture","networkMode":"none","containmentProfile":"fixture","guestFirewallSha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","guestFirewallPolicySha256":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","verification":"fixture"},"runtime":{"openclawVersion":"OpenClaw fixture","straceVersion":"strace fixture","modelProvider":"fixture","modelId":"fixture","modelEndpoint":"private"},"laneExitCode":{"baseline":0,"exercise":0}},
  "exercise":{"promptSha256":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","turnLimit":1},
  "observations":[],"canaries":[],
  "persistence":{"scope":"selected-persistence-surfaces","inventoryPaired":false,"surfaces":[{"id":"shell-init","category":"shell-init","scope":"user","description":"User shell initialization files."}],"findings":[],"limitations":["Fixture persistence limitation."]},
  "coverage":{"syscallScope":"selected-mvp-syscalls","fileSyscalls":true,"processSyscalls":true,"networkSyscalls":true,"baselinePaired":true,"limitations":[]}
}`

func writeProbePlugin(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openclaw.plugin.json"), []byte(probePluginManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("// synthetic probe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveTargetClassifiesPluginDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	resolved, err := resolveTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindPlugin {
		t.Fatalf("kind = %q", resolved.kind)
	}
	if resolved.id != "observatory-probe" {
		t.Fatalf("id = %q", resolved.id)
	}
	expected, err := filepath.EvalSymlinks(dir)
	if err != nil {
		expected = dir
	}
	if resolved.resolvedPath != expected {
		t.Fatalf("resolvedPath = %q, want %q", resolved.resolvedPath, expected)
	}
}

func TestResolveTargetClassifiesPluginManifestFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	resolved, err := resolveTarget(filepath.Join(dir, "openclaw.plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindPlugin || resolved.id != "observatory-probe" {
		t.Fatalf("resolved = %#v", resolved)
	}
}

func TestResolveTargetKeepsSkillClassification(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skill")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindSkill || resolved.id != "" {
		t.Fatalf("resolved = %#v", resolved)
	}
}

func TestResolveTargetDefaultsPlainInputsToSkill(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "README.md")
	if err := os.WriteFile(file, []byte("# readme\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{file, dir, filepath.Join(dir, "missing")} {
		resolved, err := resolveTarget(input)
		if err != nil {
			t.Fatalf("resolveTarget(%q) error = %v", input, err)
		}
		if resolved.kind != targetKindSkill || resolved.id != "" {
			t.Fatalf("resolveTarget(%q) = %#v", input, resolved)
		}
	}
}

func TestResolveTargetRejectsAmbiguousManifests(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ambiguous")
	writeProbePlugin(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := resolveTarget(dir)
	if err == nil || !strings.Contains(err.Error(), "exactly one manifest") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveTargetIgnoresSymlinkedPluginManifest(t *testing.T) {
	// A hostile target must not be able to point openclaw.plugin.json at a host
	// file outside the target and be classified/read as that plugin.
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "openclaw.plugin.json")
	if err := os.WriteFile(outside, []byte(`{"id":"outside-evil"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "probe-plugin")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "openclaw.plugin.json")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	resolved, err := resolveTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindSkill || resolved.id != "" {
		t.Fatalf("symlinked manifest was followed: %#v", resolved)
	}
}

func TestReadPluginIDRejectsSymlinkManifest(t *testing.T) {
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "secret.json")
	if err := os.WriteFile(outside, []byte(`{"id":"outside-evil"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "openclaw.plugin.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	id, err := readPluginID(link)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("id = %q err = %v", id, err)
	}
	if id != "" {
		t.Fatalf("id leaked from symlinked manifest: %q", id)
	}
}

func TestReadPluginIDReadsRegularManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	id, err := readPluginID(filepath.Join(dir, "openclaw.plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if id != "observatory-probe" {
		t.Fatalf("id = %q", id)
	}
}

func TestResolveTargetIgnoresSymlinkManifestNextToSkill(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mixed")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "openclaw.plugin.json")
	if err := os.WriteFile(outside, []byte(`{"id":"outside-evil"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "openclaw.plugin.json")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	// The symlinked plugin manifest is not a real manifest, so the directory is
	// an unambiguous skill rather than a rejected ambiguous target.
	resolved, err := resolveTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.kind != targetKindSkill || resolved.id != "" {
		t.Fatalf("resolved = %#v", resolved)
	}
}

func TestResolveTargetRejectsInvalidPluginID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bad-plugin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openclaw.plugin.json"), []byte(`{"id":"Not Valid ID"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := resolveTarget(dir)
	if err == nil || !strings.Contains(err.Error(), "invalid plugin id") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunSkipsSkillOnlyScannerForPluginTarget(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	opts, err := ParseArgs([]string{dir, "--scanner", "clawscan-static"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{Env: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Target.Kind != targetKindPlugin || artifact.Target.ID != "observatory-probe" {
		t.Fatalf("target = %#v", artifact.Target)
	}
	result := artifact.Scanners["clawscan-static"]
	if result.Status != "skipped" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "does not support plugin targets") {
		t.Fatalf("error = %q", result.Error)
	}
	if len(result.Raw) != 0 {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestRunPassesPluginTargetToBehaviorScanner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "probe-plugin")
	writeProbePlugin(t, dir)
	recorder := &behaviorRecordingRunner{stdout: behaviorPluginFixture}
	opts, err := ParseArgs([]string{dir, "--scanner", "behavior", "--sandbox", "off"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{"CLAWSCAN_BEHAVIOR_CONFIG": "/private/config.yml"},
		CommandRunner: recorder,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Target.Kind != targetKindPlugin || artifact.Target.ID != "observatory-probe" {
		t.Fatalf("target = %#v", artifact.Target)
	}
	result := artifact.Scanners["behavior"]
	if result.Status != "completed" || len(result.Raw) == 0 {
		t.Fatalf("result = %#v", result)
	}
	if len(recorder.calls) != 1 {
		t.Fatalf("calls = %#v", recorder.calls)
	}
	if got := recorder.calls[0].args[len(recorder.calls[0].args)-1]; got != dir {
		t.Fatalf("behavior target = %q, want %q", got, dir)
	}
	rawArtifact, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawArtifact, []byte("/private/config.yml")) {
		t.Fatalf("artifact leaked config path: %s", rawArtifact)
	}
}

func TestRunFailsForInvalidPluginManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bad-plugin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openclaw.plugin.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{dir, "--scanner", "clawscan-static"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(opts, RunContext{Env: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "not a valid plugin") {
		t.Fatalf("err = %v", err)
	}
}
