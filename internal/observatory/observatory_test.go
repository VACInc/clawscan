package observatory

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func requireLinuxControlHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("secure live execution, staging, and rendering require Linux")
	}
}

func TestConfigLiveModeFailsClosed(t *testing.T) {
	requireLinuxControlHost(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "observatory.yml")
	configYAML := `version: 1
live: false
executor:
  kind: crabbox
  command: crabbox
  crabboxConfig: /tmp/crabbox.yml
runtime:
  agentUser: observatory
  model:
    baseUrl: http://10.0.0.2:8000/v1
    id: local-model
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "live behavior execution is disabled") {
		t.Fatalf("err = %v", err)
	}
	config.Live = true
	config.Isolation = validIsolationConfig()
	config.Runtime.ControlPlaneAddresses = []string{"10.0.0.2:8000"}
	config.Executor.CrabboxConfig = filepath.Join(dir, "crabbox.yml")
	if err := os.WriteFile(config.Executor.CrabboxConfig, []byte(testCrabboxConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateLive(); err != nil {
		t.Fatalf("validated live config: %v", err)
	}
	if err := os.WriteFile(config.Executor.CrabboxConfig, []byte(strings.Replace(testCrabboxConfig, "user: crabbox", "user: observatory", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("same control/agent user err = %v", err)
	}
	if err := os.WriteFile(config.Executor.CrabboxConfig, []byte(testCrabboxConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.Executor.CrabboxConfig, []byte(strings.Replace(testCrabboxConfig, "  node:", "  insecureTLS: true\n  node:", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "insecureTLS must be false") {
		t.Fatalf("insecure Proxmox TLS err = %v", err)
	}
	if err := os.WriteFile(config.Executor.CrabboxConfig, []byte(testCrabboxConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	config.Runtime.Model.BaseURL = "http://10.0.0.2:8000/v1?api_key=synthetic"
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "query or fragment") {
		t.Fatalf("model URL query err = %v", err)
	}
	config.Runtime.Model.BaseURL = "http://10.0.0.2:8000/v1"
	config.Runtime.ControlPlaneAddresses = []string{"10.0.0.2:8000", "203.0.113.8:443"}
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "exactly the model endpoint") {
		t.Fatalf("additional egress endpoint err = %v", err)
	}
	config.Runtime.ControlPlaneAddresses = []string{"10.0.0.2:8000"}
	config.Runtime.Model.BaseURL = "http://10.0.0.2:8001/v1"
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "host and effective port") {
		t.Fatalf("mismatched model endpoint err = %v", err)
	}
	config.Runtime.Model.BaseURL = "http://10.0.0.2/v1"
	config.Runtime.ControlPlaneAddresses = []string{"10.0.0.2:80"}
	if err := config.ValidateLive(); err != nil {
		t.Fatalf("default HTTP port: %v", err)
	}
	config.Runtime.Model.BaseURL = "http://[fd00::2]:8000/v1"
	config.Runtime.ControlPlaneAddresses = []string{"[fd00::2]:8000"}
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("IPv6 MVP err = %v", err)
	}
	config.Runtime.Model.BaseURL = "http://127.0.0.1:8000/v1"
	config.Runtime.ControlPlaneAddresses = []string{"127.0.0.1:8000"}
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("loopback model endpoint err = %v", err)
	}
}

func TestReadSkillNameRequiresLeadingBoundedFrontmatter(t *testing.T) {
	for _, test := range []struct {
		name     string
		manifest string
		want     string
	}{
		{name: "frontmatter", manifest: "---\nname: Public fixture\n---\n# Body\n", want: "Public fixture"},
		{name: "yaml comment", manifest: "---\nname: demo-skill # stable identifier\n---\n", want: "demo-skill"},
		{name: "bom", manifest: "\ufeff---\nname: BOM fixture\n---\n", want: "BOM fixture"},
		{name: "body horizontal rule", manifest: "# Private notes\n---\nname: private-customer\n---\n", want: "Unnamed skill"},
		{name: "leading blank", manifest: "\n---\nname: private-customer\n---\n", want: "Unnamed skill"},
		{name: "unclosed frontmatter", manifest: "---\nname: Private draft\n", want: "Unnamed skill"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := readSkillName([]byte(test.manifest)); got != test.want {
				t.Fatalf("readSkillName() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSkillFrontmatterAcceptsManifestSizedLineAndRejectsUnterminatedBlock(t *testing.T) {
	manifest := []byte("---\n#" + strings.Repeat("x", 70<<10) + "\nname: long-line-probe\n---\n")
	name, present, err := parseSkillFrontmatterName(manifest)
	if err != nil || !present || name != "long-line-probe" {
		t.Fatalf("long frontmatter line parse = %q, %v, %v", name, present, err)
	}
	if _, _, err := parseSkillFrontmatterName([]byte("---\nname: unclosed")); err == nil || !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("unterminated frontmatter was accepted: %v", err)
	}
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observatory.yml")
	if err := os.WriteFile(path, []byte(`version: 1
live: false
unknown: true
executor: {kind: crabbox, command: crabbox, crabboxConfig: /tmp/crabbox.yml}
runtime: {model: {baseUrl: http://127.0.0.1:8000/v1, id: demo}}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigRejectsTrailingYAMLDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observatory.yml")
	data := `version: 1
live: false
executor: {kind: crabbox, command: crabbox, crabboxConfig: /tmp/crabbox.yml}
runtime: {model: {baseUrl: http://127.0.0.1:8000/v1, id: demo}}
---
live: true
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "trailing behavior config") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigResolvesExecutorPathsFromConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"wrapper", "crabbox-bin"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "crabbox.yml"), []byte(testCrabboxConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "observatory.yml")
	configYAML := `version: 1
live: false
artifactsDir: ./runs
executor:
  kind: crabbox
  command: ./wrapper
  crabboxBinary: ./crabbox-bin
  crabboxConfig: ./crabbox.yml
runtime:
  model:
    baseUrl: http://127.0.0.1:8000/v1
    id: fixture
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"artifacts": config.ArtifactsDir,
		"command":   config.Executor.Command,
		"binary":    config.Executor.CrabboxBinary,
		"config":    config.Executor.CrabboxConfig,
	} {
		if !filepath.IsAbs(got) || filepath.Dir(got) != dir {
			t.Fatalf("%s path = %q", name, got)
		}
	}
}

func TestExecutorEnvironmentDropsAmbientCredentials(t *testing.T) {
	for _, key := range []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "CRABBOX_PROXMOX_TOKEN_SECRET", "OPENAI_API_KEY"} {
		if commandEnvironmentAllowed(key) {
			t.Fatalf("ambient credential %s was allowed", key)
		}
	}
	for _, key := range []string{"PATH", "HOME", "OP_CONFIG_DIR", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN"} {
		if !commandEnvironmentAllowed(key) {
			t.Fatalf("required local control-plane variable %s was blocked", key)
		}
	}
}

func TestLiveConfigRejectsReusableCrabboxArguments(t *testing.T) {
	requireLinuxControlHost(t)
	config := validTestConfig(t, t.TempDir())
	config.Executor.Args = []string{"--keep-on-failure"}
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("err = %v", err)
	}
}

func TestStageTargetCopiesDeterministicallyAndRejectsSymlinks(t *testing.T) {
	requireLinuxControlHost(t)
	skill := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(filepath.Join(skill, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(skill, "empty"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(skill, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, ".git", "config"), []byte("private metadata\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: demo-skill\n---\n# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "scripts", "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(skill, "SKILL.md"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(skill, "scripts", "run.sh"), 0o510); err != nil {
		t.Fatal(err)
	}
	limits := LimitsConfig{MaxFiles: 10, MaxFileBytes: 1024, MaxTotalBytes: 2048, MaxBundleBytes: 2048}
	stagedRoot := filepath.Join(t.TempDir(), "first")
	first, err := StageTarget(skill, stagedRoot, limits)
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectTarget(filepath.Join(skill, "SKILL.md"), limits)
	if err != nil {
		t.Fatal(err)
	}
	if first.Evidence.Name != "demo-skill" || first.Evidence.ID != "demo-skill" || first.Evidence.SHA256 != second.Evidence.SHA256 || first.Evidence.FileCount != 2 || first.Evidence.DirectoryCount != 3 {
		t.Fatalf("first = %#v second = %#v", first.Evidence, second.Evidence)
	}
	if len(first.Evidence.Omitted) != 1 || first.Evidence.Omitted[0].Path != ".git" || first.Evidence.Omitted[0].Reason != "excluded Git metadata" {
		t.Fatalf("omissions = %#v", first.Evidence.Omitted)
	}
	if _, err := os.Stat(filepath.Join(stagedRoot, ".git")); !os.IsNotExist(err) {
		t.Fatalf("staged Git metadata exists: %v", err)
	}
	for path, expected := range map[string]os.FileMode{
		stagedRoot:                                     0o700,
		filepath.Join(stagedRoot, "SKILL.md"):          0o600,
		filepath.Join(stagedRoot, "scripts", "run.sh"): 0o600,
		filepath.Join(stagedRoot, "empty"):             0o700,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != expected {
			t.Fatalf("staged mode %s = %v, %v; want %v", path, info, err, expected)
		}
	}
	fileModes := map[string]string{}
	for _, file := range first.Evidence.Files {
		fileModes[file.Path] = file.Mode
	}
	directoryModes := map[string]string{}
	for _, directory := range first.Evidence.Directories {
		directoryModes[directory.Path] = directory.Mode
	}
	if fileModes["SKILL.md"] != "0440" || fileModes["scripts/run.sh"] != "0510" || directoryModes["empty"] != "0500" {
		t.Fatalf("recorded modes: files=%#v directories=%#v", fileModes, directoryModes)
	}
	if err := os.Symlink("SKILL.md", filepath.Join(skill, "linked.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := StageTarget(skill, filepath.Join(t.TempDir(), "linked"), limits); err == nil || !strings.Contains(err.Error(), "unsupported symlink") {
		t.Fatalf("err = %v", err)
	}
	realAncestor := t.TempDir()
	ancestorSkill := filepath.Join(realAncestor, "ancestor-skill")
	if err := os.Mkdir(ancestorSkill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ancestorSkill, "SKILL.md"), []byte("# Ancestor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkedAncestor := filepath.Join(t.TempDir(), "linked-ancestor")
	if err := os.Symlink(realAncestor, linkedAncestor); err != nil {
		t.Fatal(err)
	}
	if _, err := StageTarget(filepath.Join(linkedAncestor, "ancestor-skill"), filepath.Join(t.TempDir(), "ancestor-stage"), limits); err == nil || !strings.Contains(err.Error(), "unsupported symlink") {
		t.Fatalf("ancestor symlink err = %v", err)
	}
	attributesSkill := filepath.Join(t.TempDir(), "attributes")
	if err := os.MkdirAll(attributesSkill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attributesSkill, "SKILL.md"), []byte("# Attributes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attributesSkill, ".GITATTRIBUTES"), []byte("* filter=payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := StageTarget(attributesSkill, filepath.Join(t.TempDir(), "attributes-stage"), limits); err == nil || !strings.Contains(err.Error(), "Git attributes") {
		t.Fatalf("attributes err = %v", err)
	}
	lowercaseSkill := filepath.Join(t.TempDir(), "lowercase-manifest")
	if err := os.MkdirAll(lowercaseSkill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lowercaseSkill, "skill.md"), []byte("# Wrong case\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := StageTarget(lowercaseSkill, filepath.Join(t.TempDir(), "lowercase-stage"), limits); err == nil || !strings.Contains(err.Error(), "missing a regular SKILL.md") {
		t.Fatalf("lowercase manifest err = %v", err)
	}
	unnamedSkill := filepath.Join(t.TempDir(), "private-customer")
	if err := os.Mkdir(unnamedSkill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unnamedSkill, "SKILL.md"), []byte("---\nname: private\x00customer\n---\n# No public name\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectTarget(unnamedSkill, limits); err == nil || !strings.Contains(err.Error(), "skill manifest") {
		t.Fatalf("invalid skill name err = %v", err)
	}
	nulPlugin := filepath.Join(t.TempDir(), "nul-plugin")
	if err := os.Mkdir(nulPlugin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nulPlugin, "openclaw.plugin.json"), []byte(`{"id":"nul-plugin","name":"private\u0000customer"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectTarget(nulPlugin, limits); err == nil || !strings.Contains(err.Error(), "invalid name") {
		t.Fatalf("NUL plugin name err = %v", err)
	}
}

func TestAnalyzeTracesSubtractsBaselineAndRedactsPrivateEndpoints(t *testing.T) {
	metadata := CaptureMetadata{
		RunID:             "obs_test",
		BaselineWorkspace: "/run/baseline/workspace",
		ExerciseWorkspace: "/run/exercise/workspace",
		BaselineState:     "/run/baseline/state",
		ExerciseState:     "/run/exercise/state",
		BaselineHome:      "/run/baseline/home",
		ExerciseHome:      "/run/exercise/home",
		TargetKind:        "skill",
		TargetRoot:        "/run/exercise/workspace/skills/observed",
	}
	baseline := `openat(AT_FDCWD</run/baseline/workspace>, "/run/baseline/workspace/SOUL.md", O_RDONLY|O_CLOEXEC) = 3</run/baseline/workspace/SOUL.md>
execve("/usr/bin/node", ["node"], 0x0) = 0
connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(8000), sin_addr=inet_addr("10.0.0.2")}, 16) = 0
`
	cloudMarker := testCanaryMarkers()["cloud-credentials"]
	exercise := `openat(AT_FDCWD</run/exercise/workspace>, "/run/exercise/workspace/SOUL.md", O_RDONLY|O_CLOEXEC) = 3</run/exercise/workspace/SOUL.md>
openat(AT_FDCWD</run/exercise/workspace>, "/run/exercise/workspace/SOUL.md", O_RDONLY|O_CLOEXEC) = 4</run/exercise/workspace/SOUL.md>
openat(AT_FDCWD</run/exercise/workspace>, "/run/exercise/home/.aws/credentials", O_RDONLY) = 5</run/exercise/home/.aws/credentials>
execve("/usr/bin/node", ["node"], 0x0) = 0
execve("/usr/bin/curl", ["curl", "https://example.invalid"], 0x0) = 0
execve("/usr/bin/missing", ["missing"], 0x0) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD</run/exercise/workspace>, "/run/exercise/workspace/10.0.0.2_192.168.1.44_fd00::1-private", O_WRONLY|O_CREAT, 0600) = 6
openat(AT_FDCWD, "/proc/self/environ", O_RDONLY) = 7
connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(8000), sin_addr=inet_addr("10.0.0.2")}, 16) = 0
connect(4<TCP:[2]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
connect(6<TCP:[4]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("110.0.0.200")}, 16) = 0
connect(5<TCP:[3]>, {sa_family=AF_INET, sin_port=htons(22), sin_addr=inet_addr("192.168.1.44")}, 16) = -1 ECONNREFUSED (Connection refused)
sendto(4, "` + cloudMarker + `", 61, 0, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 61
write(9<TCP:[10.0.0.3:55000->93.184.216.34:443]>, "` + cloudMarker + `", 61) = 61
`
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces:        []string{baseline},
		ExerciseTraces:        []string{exercise},
		Metadata:              metadata,
		Canaries:              testCanaries(),
		ControlPlaneAddresses: []string{"10.0.0.2:8000"},
	})
	joined, err := json.Marshal(result.Observations)
	if err != nil {
		t.Fatal(err)
	}
	text := string(joined)
	for _, expected := range []string{"$HOME/.aws/credentials", "/proc/self/environ", `"curl"`, `"missing"`, "93.184.216.34:443", "110.0.0.200:443", "private-endpoint:22", `"attempted"`, "[private-address]"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("observations missing %q: %s", expected, text)
		}
	}
	for _, absent := range []string{"$WORKSPACE/10.0.0.2_", "192.168.1.44", "fd00::1", `"node"`, "OBS-CANARY"} {
		if strings.Contains(text, absent) {
			t.Fatalf("observations leaked baseline/private/canary value %q: %s", absent, text)
		}
	}
	canary := findCanary(result.Canaries, "cloud-credentials")
	if canary.ExerciseInteractions != 3 || canary.DeltaInteractions != 3 {
		t.Fatalf("cloud canary = %#v", canary)
	}
	identity := findCanary(result.Canaries, "workspace-identity")
	if identity.BaselineInteractions != 1 || identity.ExerciseInteractions != 2 || identity.DeltaInteractions != 1 {
		t.Fatalf("identity canary = %#v", identity)
	}
}

func TestAnalyzeTracesSuppressesOnlyKnownSuccessfulRuntimeReads(t *testing.T) {
	baseline := `execve("/usr/bin/node", ["node"], 0x0) = 0` + "\n"
	exercise := `execve("/usr/bin/node", ["node"], 0x0) = 0
execve("/usr/bin/curl", ["curl"], 0x0) = 0
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 3
openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libcurl.so.4", O_RDONLY) = 3
openat(AT_FDCWD, "/usr/share/locale/en/LC_MESSAGES/curl.mo", O_RDONLY) = 3
openat(AT_FDCWD, "/usr/lib/target-only.so", O_RDONLY) = 3
openat(AT_FDCWD, "/etc/ld.so.preload", O_RDONLY) = 3
openat(AT_FDCWD, "/dev/ttyUSB0", O_RDONLY) = 3
openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libmissing.so", O_RDONLY) = -1 ENOENT (No such file or directory)
`
	result := AnalyzeTraces(AnalysisInput{BaselineTraces: []string{baseline}, ExerciseTraces: []string{exercise}, Metadata: CaptureMetadata{TargetKind: "skill"}})
	raw, err := json.Marshal(result.Observations)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, expected := range []string{"curl", "/usr/lib/target-only.so", "/etc/ld.so.preload", "/dev/ttyUSB0", "libmissing.so", "attempted"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("observations missing %q: %s", expected, text)
		}
	}
	for _, noise := range []string{"/etc/ld.so.cache", "libcurl.so.4", "curl.mo"} {
		if strings.Contains(text, noise) {
			t.Fatalf("observations retained runtime noise %q: %s", noise, text)
		}
	}
}

func TestLinkatEmptyPathUsesAnnotatedDescriptorForObservationAndCanary(t *testing.T) {
	metadata := CaptureMetadata{
		ExerciseWorkspace: "/run/exercise/workspace",
		ExerciseHome:      "/run/exercise/home",
		TargetKind:        "skill",
	}
	line := `linkat(3</run/exercise/home/.aws/credentials>, "", AT_FDCWD</run/exercise/workspace>, "/run/exercise/workspace/credential-copy", AT_EMPTY_PATH) = 0`
	observations := parseTraceLine(line, metadata, nil, true)
	if len(observations) != 2 || observations[0].Operation != "link-from" || observations[0].Subject != "$HOME/.aws/credentials" || observations[1].Operation != "link-to" || observations[1].Subject != "$WORKSPACE/credential-copy" {
		t.Fatalf("linkat AT_EMPTY_PATH observations = %#v", observations)
	}
	canary := findCanaryDefinition(testCanaries(), "cloud-credentials")
	if !lineTouchesCanary(line, canary, metadata) {
		t.Fatal("linkat AT_EMPTY_PATH did not count the annotated canary descriptor")
	}
}

func TestObservationRedactionTreatsControlPlaneIPAsAddressToken(t *testing.T) {
	got := sanitizeObservationSubject("110.0.0.200:443 /synthetic/10.0.0.20-receipt", nil, []string{"10.0.0.20:8000"})
	if got != "110.0.0.200:443 /synthetic/[private-address]-receipt" {
		t.Fatalf("boundary-aware redaction = %q", got)
	}
}

func TestAnalyzeTracesHandlesPIDPrefixesAndSanitizesCanarySubjects(t *testing.T) {
	metadata := CaptureMetadata{
		RunID:             "obs_test",
		BaselineWorkspace: "/run/baseline/workspace",
		ExerciseWorkspace: "/run/exercise/workspace",
		BaselineState:     "/run/baseline/state",
		ExerciseState:     "/run/exercise/state",
		BaselineHome:      "/run/baseline/home",
		ExerciseHome:      "/run/exercise/home",
		TargetKind:        "skill",
		TargetRoot:        "/run/exercise/workspace/skills/observed",
	}
	marker := testCanaryMarkers()["workspace-memory"]
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{"101 execve(\"/usr/bin/node\", [\"node\"], 0x0) = 0\n"},
		ExerciseTraces: []string{
			"[pid 202] execve(\"/tmp/" + marker + "\", [\"payload\"], 0x0) = 0\n" +
				"203 openat(AT_FDCWD, \"/tmp/" + marker + "\", O_RDONLY) = 3\n",
		},
		Metadata: metadata,
		Canaries: testCanaries(),
	})
	encoded, err := json.Marshal(result.Observations)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), marker) || !strings.Contains(string(encoded), "[canary:workspace-memory]") {
		t.Fatalf("observations were not sanitized: %s", encoded)
	}
	if len(result.Observations) != 2 {
		t.Fatalf("observations = %#v", result.Observations)
	}
}

func TestAnalyzeTracesResolvesRelativePathsAcrossChdirAndForkInheritance(t *testing.T) {
	metadata := CaptureMetadata{
		BaselineWorkspace: "/run/baseline/workspace", ExerciseWorkspace: "/run/exercise/workspace",
		BaselineHome: "/run/baseline/home", ExerciseHome: "/run/exercise/home",
		BaselineState: "/run/baseline/state", ExerciseState: "/run/exercise/state",
		TargetKind: "skill", TargetRoot: "/run/exercise/workspace/skills/observed",
	}
	baseline := `100 execve("/usr/bin/node", ["node"], 0x0) = 0` + "\n"
	exercise := `100 execve("/usr/bin/node", ["node"], 0x0) = 0
100 chdir("/run/exercise/home") = 0
100 openat(AT_FDCWD, ".aws/credentials", O_RDONLY) = 3</run/exercise/home/.aws/credentials>
100 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>
200 openat(AT_FDCWD, ".aws/credentials", O_RDONLY) = 4</run/exercise/home/.aws/credentials>
100 <... clone resumed>) = 200
100 clone(child_stack=NULL, flags=CLONE_FS|SIGCHLD) = 201
201 chdir("/run/exercise/workspace") = 0
201 unshare(CLONE_FS) = 0
201 chdir("/run/exercise/home") = 0
201 openat(AT_FDCWD, ".aws/credentials", O_RDONLY) = 6</run/exercise/home/.aws/credentials>
100 openat(AT_FDCWD, "SOUL.md", O_RDONLY) = 5</run/exercise/workspace/SOUL.md>
`
	canaries := []CanaryDefinition{
		{ID: "cloud-credentials", Surface: "home file", Path: "$HOME/.aws/credentials"},
		{ID: "workspace-identity", Surface: "workspace file", Path: "$WORKSPACE/SOUL.md"},
	}
	result := AnalyzeTraces(AnalysisInput{BaselineTraces: []string{baseline}, ExerciseTraces: []string{exercise}, Metadata: metadata, Canaries: canaries})
	encoded, err := json.Marshal(result.Observations)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "$HOME/.aws/credentials") || !strings.Contains(string(encoded), "$WORKSPACE/SOUL.md") || strings.Contains(string(encoded), `"subject":".aws/credentials"`) {
		t.Fatalf("relative observations were not resolved: %s", encoded)
	}
	if cloud := findCanary(result.Canaries, "cloud-credentials"); cloud.DeltaInteractions != 3 {
		t.Fatalf("fork-inherited cwd canary = %#v", cloud)
	}
	if workspace := findCanary(result.Canaries, "workspace-identity"); workspace.DeltaInteractions != 1 {
		t.Fatalf("CLONE_FS cwd canary = %#v", workspace)
	}
}

func TestAnalyzeTracesSubtractsExecutablesByNormalizedPathBeforePublishingBasename(t *testing.T) {
	metadata := CaptureMetadata{
		TargetKind: "skill", TargetRoot: "/run/exercise/workspace/skills/observed",
		BaselineWorkspace: "/run/baseline/workspace", BaselineState: "/run/baseline/state", BaselineHome: "/run/baseline/home",
		ExerciseWorkspace: "/run/exercise/workspace", ExerciseState: "/run/exercise/state", ExerciseHome: "/run/exercise/home",
	}
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{`execve("/usr/bin/node", ["node"], 0x0) = 0`},
		ExerciseTraces: []string{`execve("/run/exercise/workspace/skills/observed/node", ["node"], 0x0) = 0`},
		Metadata:       metadata,
	})
	if len(result.Observations) != 1 || result.Observations[0].Kind != "process" || result.Observations[0].Subject != "node" {
		t.Fatalf("observations = %#v", result.Observations)
	}
}

func TestAnalyzeTracesSubtractsBeforePrivateAddressRedaction(t *testing.T) {
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{`connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("100.64.0.5")}, 16) = 0`},
		ExerciseTraces: []string{`connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("100.64.0.6")}, 16) = 0`},
		Metadata:       CaptureMetadata{TargetKind: "skill"},
	})
	if len(result.Observations) != 1 {
		t.Fatalf("observations = %#v", result.Observations)
	}
	observation := result.Observations[0]
	if observation.Subject != "private-endpoint:443" || observation.BaselineCount != 0 || observation.ExerciseCount != 1 || observation.DeltaCount != 1 {
		t.Fatalf("private delta = %#v", observation)
	}
}

func TestAnalyzeTracesNormalizesLaneControlPathsBeforeSubtraction(t *testing.T) {
	metadata := CaptureMetadata{
		TargetKind: "skill", TargetRoot: "/run/exercise/workspace/skills/observed",
		BaselineWorkspace: "/run/baseline/workspace", BaselineState: "/run/baseline/state", BaselineHome: "/run/baseline/home",
		ExerciseWorkspace: "/run/exercise/workspace", ExerciseState: "/run/exercise/state", ExerciseHome: "/run/exercise/home",
	}
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{`openat(AT_FDCWD, "/run/baseline/prompt.txt", O_RDONLY) = 3`},
		ExerciseTraces: []string{`openat(AT_FDCWD, "/run/exercise/prompt.txt", O_RDONLY) = 3
openat(AT_FDCWD, "/run/exercise/workspace/skills/observed/SKILL.md", O_RDONLY) = 4`},
		Metadata: metadata,
	})
	if len(result.Observations) != 1 || result.Observations[0].Subject != "$SKILL/SKILL.md" {
		t.Fatalf("lane-normalized observations = %#v", result.Observations)
	}
}

func TestAnalyzeTracesResolvesAnnotatedDirectoryFDs(t *testing.T) {
	metadata := CaptureMetadata{
		RunID:             "obs_dirfd",
		TargetKind:        "skill",
		TargetRoot:        "/run/exercise/workspace/skills/observed",
		BaselineWorkspace: "/run/baseline/workspace",
		ExerciseWorkspace: "/run/exercise/workspace",
		BaselineState:     "/run/baseline/state",
		ExerciseState:     "/run/exercise/state",
		BaselineHome:      "/run/baseline/home",
		ExerciseHome:      "/run/exercise/home",
	}
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{"101 execve(\"/usr/bin/node\", [\"node\"], 0x0) = 0\n"},
		ExerciseTraces: []string{
			"201 openat(3</run/exercise/home/.aws>, \"credentials\", O_RDONLY <unfinished ...>\n" +
				"202 execve(\"/usr/bin/helper\", [\"helper\"], 0x0) = 0\n" +
				"201 <... openat resumed>) = 4\n" +
				"201 renameat(5</run/exercise/workspace>, \"old.txt\", 6</run/exercise/workspace>, \"new.txt\") = 0\n" +
				"201 linkat(3</run/exercise/home/.aws>, \"credentials\", 5</run/exercise/workspace>, \"credential-alias\", 0) = 0\n" +
				"203 connect(7, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr(\"203.0.113.1\")}, 16 <unfinished ...>\n",
		},
		Metadata: metadata,
		Canaries: testCanaries(),
	})
	encoded, err := json.Marshal(result.Observations)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"$HOME/.aws/credentials", "$WORKSPACE/old.txt", "$WORKSPACE/new.txt", "$WORKSPACE/credential-alias", "link-from", "link-to", "203.0.113.1:9", `"attempted"`} {
		if !strings.Contains(string(encoded), expected) {
			t.Fatalf("dirfd observation missing %q: %s", expected, encoded)
		}
	}
	if canary := findCanary(result.Canaries, "cloud-credentials"); canary.DeltaInteractions != 2 {
		t.Fatalf("cloud canary = %#v", canary)
	}
}

func TestTraceParserCapturesStreamSocketWritesAndFailedExec(t *testing.T) {
	abstract := parseTraceLine(
		`connect(3, {sa_family=AF_UNIX, sun_path=@"observatory.private"}, 31) = 0`,
		CaptureMetadata{}, nil, true,
	)
	if len(abstract) != 1 || abstract[0].Subject != "unix-abstract:observatory.private" || abstract[0].Role != "local" {
		t.Fatalf("abstract Unix socket observation = %#v", abstract)
	}
	write := parseTraceLine(
		`write(22<TCP:[10.0.0.3:36990->10.0.0.2:8000]>, "payload", 7) = 7`,
		CaptureMetadata{}, []string{"10.0.0.2:8000"}, true,
	)
	if len(write) != 1 || write[0].Operation != "send" || write[0].Subject != "model-endpoint:8000" || write[0].Role != "model-control-plane" {
		t.Fatalf("write observations = %#v", write)
	}
	spoofedPayload := parseTraceLine(
		`write(22<TCP:[10.0.0.3:36990->93.184.216.34:443]>, "x]>", 3) = 3`,
		CaptureMetadata{}, nil, true,
	)
	if len(spoofedPayload) != 1 || spoofedPayload[0].Operation != "send" || spoofedPayload[0].Subject != "93.184.216.34:443" {
		t.Fatalf("payload-spoofed write observations = %#v", spoofedPayload)
	}
	forgedAnnotation := parseTraceLine(
		`write(1</dev/null>, "TCP:[1.2.3.4:1->8.8.8.8:53]>", 36) = 36`,
		CaptureMetadata{}, nil, true,
	)
	if len(forgedAnnotation) != 0 {
		t.Fatalf("payload-forged socket annotation = %#v", forgedAnnotation)
	}
	spoofedDatagramPort := parseTraceLine(
		`sendto(4, "sin_port=htons(8000)", 21, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.0.0.2")}, 16) = 21`,
		CaptureMetadata{}, []string{"10.0.0.2:8000"}, true,
	)
	if len(spoofedDatagramPort) != 1 || spoofedDatagramPort[0].Subject != "10.0.0.2:53" || spoofedDatagramPort[0].Role != "private-network" {
		t.Fatalf("payload-spoofed datagram destination = %#v", spoofedDatagramPort)
	}
	multiSend := parseTraceLine(
		`sendmmsg(4, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16}, msg_len=1}, {msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, msg_namelen=16}, msg_len=1}], 2, 0) = 2`,
		CaptureMetadata{}, nil, true,
	)
	if len(multiSend) != 2 || multiSend[0].Subject != "8.8.8.8:53" || multiSend[1].Subject != "93.184.216.34:443" {
		t.Fatalf("sendmmsg observations = %#v", multiSend)
	}
	partialMultiSend := parseTraceLine(
		`sendmmsg(4, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16}, msg_len=1}, {msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, msg_namelen=16}, msg_len=1}, {msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("203.0.113.1")}, msg_namelen=16}, msg_len=1}], 3, 0) = 1`,
		CaptureMetadata{}, nil, true,
	)
	if len(partialMultiSend) != 2 || partialMultiSend[0].Outcome != "succeeded" || partialMultiSend[1].Outcome != "attempted" {
		t.Fatalf("partial sendmmsg observations = %#v", partialMultiSend)
	}
	repeatedMultiSend := parseTraceLine(
		`sendmmsg(4, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16}, msg_len=1}, {msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16}, msg_len=1}], 2, 0) = 2`,
		CaptureMetadata{}, nil, true,
	)
	if len(repeatedMultiSend) != 2 || repeatedMultiSend[0].Subject != repeatedMultiSend[1].Subject {
		t.Fatalf("repeated sendmmsg observations = %#v", repeatedMultiSend)
	}
	connectedMultiSend := parseTraceLine(
		`sendmmsg(4<UDP:[10.0.0.3:40000->8.8.8.8:53]>, [{msg_hdr={msg_name=NULL, msg_namelen=0}, msg_len=1}, {msg_hdr={msg_name=NULL, msg_namelen=0}, msg_len=1}], 2, 0) = 2`,
		CaptureMetadata{}, nil, true,
	)
	if len(connectedMultiSend) != 2 || connectedMultiSend[0].Subject != "8.8.8.8:53" || connectedMultiSend[1].Outcome != "succeeded" {
		t.Fatalf("connected sendmmsg observations = %#v", connectedMultiSend)
	}
	truncated := parseTraceLine(`truncate("/tmp/data", 0) = 0`, CaptureMetadata{}, nil, true)
	if len(truncated) != 1 || truncated[0].Operation != "truncate" || truncated[0].Subject != "/tmp/data" {
		t.Fatalf("truncate observation = %#v", truncated)
	}
	fdTruncated := parseTraceLine(`ftruncate(3</tmp/data>, 0) = 0`, CaptureMetadata{}, nil, true)
	if len(fdTruncated) != 1 || fdTruncated[0].Subject != "/tmp/data" {
		t.Fatalf("ftruncate observation = %#v", fdTruncated)
	}
	if unannotated := parseTraceLine(`ftruncate(999, 0) = -1 EBADF (Bad file descriptor)`, CaptureMetadata{}, nil, true); len(unannotated) != 0 {
		t.Fatalf("unannotated ftruncate observation = %#v", unannotated)
	}
	symlinked := parseTraceLine(`symlinkat("target", AT_FDCWD, "/tmp/alias") = 0`, CaptureMetadata{}, nil, true)
	if len(symlinked) != 1 || symlinked[0].Operation != "create-symlink" || symlinked[0].Subject != "/tmp/alias" {
		t.Fatalf("symlinkat observation = %#v", symlinked)
	}
	indeterminate := parseTraceLine(
		`connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)`,
		CaptureMetadata{}, nil, true,
	)
	if len(indeterminate) != 1 || indeterminate[0].Outcome != "attempted" {
		t.Fatalf("indeterminate connect observations = %#v", indeterminate)
	}
	if got := parseTraceLine(`write(1</dev/null>, "payload", 7) = 7`, CaptureMetadata{}, nil, true); len(got) != 0 {
		t.Fatalf("non-socket write = %#v", got)
	}
	failed := parseTraceLine(`execve("/usr/bin/missing", ["missing"], 0x0) = -1 ENOENT (No such file or directory)`, CaptureMetadata{}, nil, true)
	if len(failed) != 1 || failed[0].Outcome != "attempted" || failed[0].Subject != "/usr/bin/missing" {
		t.Fatalf("failed exec = %#v", failed)
	}
	byFD := parseTraceLine(`execveat(3</tmp/fd-payload>, "", ["fd-payload"], 0x0, AT_EMPTY_PATH) = 0`, CaptureMetadata{}, nil, true)
	if len(byFD) != 1 || byFD[0].Subject != "/tmp/fd-payload" {
		t.Fatalf("execveat AT_EMPTY_PATH = %#v", byFD)
	}
	readNamedLikeFlag := parseTraceLine(`openat(AT_FDCWD, "/tmp/O_WRONLY-report", O_RDONLY) = 3`, CaptureMetadata{}, nil, true)
	if len(readNamedLikeFlag) != 1 || readNamedLikeFlag[0].Operation != "open-for-read" {
		t.Fatalf("flag-like path = %#v", readNamedLikeFlag)
	}
	mutatingLoaderPath := parseTraceLine(`openat(AT_FDCWD, "/usr/lib/evil.so", O_WRONLY|O_CREAT) = -1 EACCES (Permission denied)`, CaptureMetadata{}, nil, true)
	if len(mutatingLoaderPath) != 1 || mutatingLoaderPath[0].Operation != "open-for-write" || mutatingLoaderPath[0].Outcome != "attempted" {
		t.Fatalf("loader mutation = %#v", mutatingLoaderPath)
	}
	for _, sensitiveRead := range []string{"/usr/lib/target-only.so", "/etc/ld.so.preload", "/dev/ttyUSB0"} {
		observations := parseTraceLine(fmt.Sprintf(`openat(AT_FDCWD, %q, O_RDONLY) = 3`, sensitiveRead), CaptureMetadata{}, nil, true)
		if len(observations) != 1 || observations[0].Subject != sensitiveRead || observations[0].Operation != "open-for-read" {
			t.Fatalf("sensitive read %s was suppressed: %#v", sensitiveRead, observations)
		}
	}
	pathOnly := parseTraceLine(`openat(AT_FDCWD, "/tmp/metadata-only", O_PATH|O_CLOEXEC) = 3`, CaptureMetadata{}, nil, true)
	if len(pathOnly) != 1 || pathOnly[0].Operation != "open-path" {
		t.Fatalf("O_PATH observation = %#v", pathOnly)
	}
	readWriteCreate := parseTraceLine(`openat(AT_FDCWD, "/tmp/read-write", O_RDWR|O_CREAT|O_TRUNC, 0600) = 3`, CaptureMetadata{}, nil, true)
	if len(readWriteCreate) != 1 || readWriteCreate[0].Operation != "open-for-read-write" {
		t.Fatalf("O_RDWR observation = %#v", readWriteCreate)
	}
}

func TestTruncationCountsAsCanaryInteraction(t *testing.T) {
	metadata := CaptureMetadata{ExerciseHome: "/run/exercise/home", BaselineHome: "/run/baseline/home"}
	canary := CanaryDefinition{Path: "$HOME/.aws/credentials"}
	for _, line := range []string{
		`truncate("/run/exercise/home/.aws/credentials", 0) = 0`,
		`ftruncate(3</run/exercise/home/.aws/credentials>, 0) = 0`,
	} {
		if !lineTouchesCanary(line, canary, metadata) {
			t.Fatalf("truncation did not count as canary interaction: %s", line)
		}
	}
}

func TestPathCanaryIgnoresArgvAndPayloadSpoofing(t *testing.T) {
	metadata := CaptureMetadata{
		RunID: "obs_spoof", TargetKind: "skill", TargetRoot: "/run/exercise/workspace/skills/observed",
		BaselineHome: "/run/baseline/home", ExerciseHome: "/run/exercise/home",
		BaselineWorkspace: "/run/baseline/workspace", ExerciseWorkspace: "/run/exercise/workspace",
		BaselineState: "/run/baseline/state", ExerciseState: "/run/exercise/state",
	}
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces: []string{"101 execve(\"/usr/bin/node\", [\"node\"], 0x0) = 0\n"},
		ExerciseTraces: []string{
			"201 execve(\"/usr/bin/echo\", [\"echo\", \"/run/exercise/home/.aws/credentials\"], 0x0) = 0\n" +
				"201 write(1</dev/null>, \"/run/exercise/home/.aws/credentials\", 44) = 44\n",
		},
		Metadata: metadata,
		Canaries: testCanaries(),
	})
	if canary := findCanary(result.Canaries, "cloud-credentials"); canary.ExerciseInteractions != 0 || canary.DeltaInteractions != 0 {
		t.Fatalf("spoofed canary = %#v", canary)
	}
}

func TestScanStagesAndConsumesFixtureExecutorBundle(t *testing.T) {
	requireLinuxControlHost(t)
	skill := filepath.Join("..", "..", "testdata", "fixtures", "probe-skill")
	config := validTestConfig(t, t.TempDir())
	config.Exercise.Prompt = DefaultExercisePrompt
	executor := &fixtureExecutor{t: t}
	result, err := Scan(context.Background(), skill, config, executor)
	if err != nil {
		t.Fatal(err)
	}
	if executor.command != "fake-crabbox" || result.Evidence.SchemaVersion != EvidenceSchemaVersion || result.Evidence.Target.ID != "observatory-probe-skill" {
		t.Fatalf("executor=%#v evidence=%#v", executor, result.Evidence)
	}
	if result.Evidence.Run.Status != "completed" || len(result.Evidence.Observations) == 0 {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
	if !result.Evidence.Persistence.InventoryPaired {
		t.Fatalf("persistence inventory was not paired: %#v", result.Evidence.Persistence)
	}
	shellInit := findPersistenceFinding(result.Evidence.Persistence.Findings, "shell-init", "$HOME/.bashrc")
	if shellInit.Outcome != "succeeded" || shellInit.Residual != "confirmed" || shellInit.Evidence != "syscall+inventory" {
		t.Fatalf("shell-init residual finding = %#v", shellInit)
	}
	systemCron := findPersistenceFinding(result.Evidence.Persistence.Findings, "system-cron", "/etc/cron.d/observatory-probe")
	if systemCron.Outcome != "attempted" || systemCron.Residual == "confirmed" || systemCron.Evidence != "syscall" {
		t.Fatalf("system-cron attempted finding = %#v", systemCron)
	}
	if _, err := os.Stat(filepath.Join(result.RunDirectory, "evidence.json")); err != nil {
		t.Fatal(err)
	}
}

func findPersistenceFinding(findings []PersistenceFinding, surface string, subject string) PersistenceFinding {
	for _, finding := range findings {
		if finding.Surface == surface && finding.Subject == subject {
			return finding
		}
	}
	return PersistenceFinding{}
}

func TestScanReturnsValidatedEvidenceWhenExecutorExitsNonzero(t *testing.T) {
	requireLinuxControlHost(t)
	skill := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# Fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := validTestConfig(t, t.TempDir())
	executor := &fixtureExecutor{t: t, err: errors.New("teardown failed")}
	result, err := Scan(context.Background(), skill, config, executor)
	if err == nil || !strings.Contains(err.Error(), "after producing valid evidence") {
		t.Fatalf("err = %v", err)
	}
	if result.Evidence.SchemaVersion != EvidenceSchemaVersion || result.RunDirectory == "" {
		t.Fatalf("result = %#v", result)
	}
	if _, statErr := os.Stat(filepath.Join(result.RunDirectory, "evidence.json")); statErr != nil {
		t.Fatal(statErr)
	}
}

func TestScanReturnsIncompleteEvidenceAndErrorForFailedLane(t *testing.T) {
	requireLinuxControlHost(t)
	skill := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# Fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := validTestConfig(t, t.TempDir())
	result, err := Scan(context.Background(), skill, config, &fixtureExecutor{t: t, exerciseExit: 124})
	if err == nil || !strings.Contains(err.Error(), "exercise exit 124") {
		t.Fatalf("err = %v", err)
	}
	if result.Evidence.Run.Status != "incomplete" || result.Evidence.Run.LaneExitCode.Exercise != 124 {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
}

func TestScanStagesPluginFixtureAndNormalizesPluginRoot(t *testing.T) {
	requireLinuxControlHost(t)
	config := validTestConfig(t, t.TempDir())
	config.Exercise.Prompt = DefaultExercisePrompt
	result, err := Scan(context.Background(), filepath.Join("..", "..", "testdata", "fixtures", "probe-plugin"), config, &fixtureExecutor{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if result.Evidence.Target.Kind != "plugin" || result.Evidence.Target.ID != "observatory-probe" {
		t.Fatalf("target = %#v", result.Evidence.Target)
	}
	if len(result.Evidence.Target.DeclaredTools) != 1 || result.Evidence.Target.DeclaredTools[0] != "observatory_probe" {
		t.Fatalf("declared tools = %#v", result.Evidence.Target.DeclaredTools)
	}
	encoded, err := json.Marshal(result.Evidence.Observations)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "$PLUGIN/index.js") {
		t.Fatalf("plugin root was not normalized: %s", encoded)
	}
}

func TestScanRefusesDisabledLiveModeBeforeExecutor(t *testing.T) {
	requireLinuxControlHost(t)
	config := validTestConfig(t, t.TempDir())
	config.Live = false
	executor := &fixtureExecutor{t: t}
	if _, err := Scan(context.Background(), "/does/not/matter", config, executor); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("err = %v", err)
	}
	if executor.command != "" {
		t.Fatalf("executor was called: %#v", executor)
	}
}

func TestScanRejectsArtifactsDirectoryInsideTargetBeforeCreatingIt(t *testing.T) {
	requireLinuxControlHost(t)
	skill := filepath.Join(t.TempDir(), "skill")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# Fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := validTestConfig(t, t.TempDir())
	config.ArtifactsDir = filepath.Join(skill, ".observatory-runs")
	executor := &fixtureExecutor{t: t}
	if _, err := Scan(context.Background(), skill, config, executor); err == nil || !strings.Contains(err.Error(), "must not be the behavior target") {
		t.Fatalf("err = %v", err)
	}
	if executor.command != "" {
		t.Fatalf("executor was called: %#v", executor)
	}
	if _, err := os.Stat(config.ArtifactsDir); !os.IsNotExist(err) {
		t.Fatalf("artifacts directory was created: %v", err)
	}
}

func TestRenderSiteIsDarkAndShowsVersionDelta(t *testing.T) {
	requireLinuxControlHost(t)
	previous := fixtureEvidence()
	current := fixtureEvidence()
	current.Target.SHA256 = "sha256:" + strings.Repeat("e", 64)
	current.Run.Isolation.GuestFirewallSHA256 = "sha256:" + strings.Repeat("f", 64)
	current.Observations = append(current.Observations, Observation{Kind: "network", Operation: "connect", Subject: "93.184.216.34:443", Outcome: "succeeded", Role: "external", ExerciseCount: 1, DeltaCount: 1})
	current.Canaries[0].ExerciseInteractions = 1
	current.Canaries[0].DeltaInteractions = 1
	output := t.TempDir()
	if err := RenderSite(output, current, &previous); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(output, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	for _, expected := range []string{`color-scheme: dark`, "Evidence, not a safety verdict", "VERSION DELTA", "93.184.216.34:443", "cloud-credentials (home file)"} {
		if !strings.Contains(strings.ToUpper(text), strings.ToUpper(expected)) {
			t.Fatalf("HTML missing %q", expected)
		}
	}
}

func TestRenderSiteRejectsSymlinkedOutputsWithoutTouchingTheirTargets(t *testing.T) {
	requireLinuxControlHost(t)
	for _, name := range []string{"index.html", "evidence.json"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			output := filepath.Join(root, "site")
			if err := os.Mkdir(output, 0o755); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(root, "sentinel")
			if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(sentinel, filepath.Join(output, name)); err != nil {
				t.Fatal(err)
			}
			if err := RenderSite(output, fixtureEvidence(), nil); err == nil {
				t.Fatal("symlinked render output was accepted")
			}
			got, err := os.ReadFile(sentinel)
			if err != nil || string(got) != "unchanged" {
				t.Fatalf("symlink target was modified: %q err=%v", got, err)
			}
		})
	}
}

func TestDiffEvidencePreservesOutcomeAndRole(t *testing.T) {
	previous := fixtureEvidence()
	current := fixtureEvidence()
	previous.Observations = []Observation{{Kind: "network", Operation: "connect", Subject: "example.invalid:443", Outcome: "succeeded", Role: "external", ExerciseCount: 1, DeltaCount: 1}}
	current.Observations = []Observation{{Kind: "network", Operation: "connect", Subject: "example.invalid:443", Outcome: "attempted", Role: "external", ExerciseCount: 1, DeltaCount: 1}}
	changes := DiffEvidence(previous, current)
	if len(changes) != 2 {
		t.Fatalf("changes = %#v", changes)
	}
	outcomes := map[string]bool{}
	for _, change := range changes {
		outcomes[change.Outcome] = true
		if change.Role != "external" {
			t.Fatalf("change = %#v", change)
		}
	}
	if !outcomes["attempted"] || !outcomes["succeeded"] {
		t.Fatalf("changes = %#v", changes)
	}
}

func TestValidateEvidenceRejectsCompletedRunWithoutCompleteLanes(t *testing.T) {
	evidence := fixtureEvidence()
	evidence.Run.LaneExitCode.Exercise = 124
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "inconsistent with lane exits") {
		t.Fatalf("err = %v", err)
	}
	evidence = fixtureEvidence()
	evidence.Coverage.BaselinePaired = false
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "inconsistent with lane exits") {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderSiteRejectsIncomparableVersionEvidence(t *testing.T) {
	requireLinuxControlHost(t)
	tests := []struct {
		name   string
		change func(*Evidence)
		want   string
	}{
		{name: "lineage", change: func(evidence *Evidence) { evidence.Target.Lineage = "example/other-skill" }, want: "same target lineage"},
		{name: "capture config", change: func(evidence *Evidence) { evidence.CaptureConfigSHA256 = "sha256:" + strings.Repeat("f", 64) }, want: "same effective capture configuration"},
		{name: "runtime", change: func(evidence *Evidence) { evidence.Run.Runtime.OpenClawVersion = "OpenClaw other" }, want: "identical, recorded runtime"},
		{name: "coverage", change: func(evidence *Evidence) {
			evidence.Coverage.Limitations = append(evidence.Coverage.Limitations, "Different parser coverage.")
		}, want: "identical capture coverage"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			previous := fixtureEvidence()
			current := fixtureEvidence()
			test.change(&current)
			output := filepath.Join(t.TempDir(), "site")
			if err := RenderSite(output, current, &previous); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("incomparable render created output directory: %v", err)
			}
		})
	}
	previous := fixtureEvidence()
	current := fixtureEvidence()
	previous.Target.Lineage = ""
	current.Target.Lineage = ""
	if err := RenderSite(filepath.Join(t.TempDir(), "site"), current, &previous); err == nil || !strings.Contains(err.Error(), "requires targetLineage") {
		t.Fatalf("missing lineage err = %v", err)
	}
}

func TestReadCaptureBundleRejectsTraversalEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsafe.tar.gz")
	if err := writeTestBundle(path, map[string]string{"../escape": "nope"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCaptureBundle(path, 1<<20); err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadCaptureBundleBoundsTarHeaderExpansion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "headers.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for index := 0; index < 3000; index++ {
		if err := tarWriter.WriteHeader(&tar.Header{Name: fmt.Sprintf("dir-%04d/", index), Mode: 0o700, Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCaptureBundle(path, 1<<20); err == nil || !strings.Contains(err.Error(), "exceeds maxBundleBytes") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadCaptureBundleRejectsMissingOrReversedTimestamps(t *testing.T) {
	entries := fixtureBundleEntries("obs_timestamps", "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "skill", "")
	entries["meta/started-at"] = ""
	path := filepath.Join(t.TempDir(), "missing-time.tar.gz")
	if err := writeTestBundle(path, entries); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCaptureBundle(path, 1<<20); err == nil || !strings.Contains(err.Error(), "missing meta/started-at") {
		t.Fatalf("missing timestamp err = %v", err)
	}
	entries["meta/started-at"] = "2026-07-10T12:00:02Z\n"
	entries["meta/completed-at"] = "2026-07-10T12:00:01Z\n"
	path = filepath.Join(t.TempDir(), "reversed-time.tar.gz")
	if err := writeTestBundle(path, entries); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCaptureBundle(path, 1<<20); err == nil || !strings.Contains(err.Error(), "precedes") {
		t.Fatalf("reversed timestamp err = %v", err)
	}
}

func TestReadCaptureBundleRejectsEmptyOrUnparseableLaneTraces(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		trace string
		want  string
	}{
		{name: "empty baseline", entry: "baseline/trace", trace: "", want: "baseline lane"},
		{name: "unparseable exercise", entry: "exercise/trace", trace: "+++ exited with 0 +++\n", want: "exercise lane"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := fixtureBundleEntries("obs_trace_receipt", "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "skill", "")
			entries[test.entry] = test.trace
			path := filepath.Join(t.TempDir(), "capture.tar.gz")
			if err := writeTestBundle(path, entries); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadCaptureBundle(path, 1<<20); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestReadCaptureBundleRequiresLaneAndRuntimeReceipts(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		value string
		want  string
	}{
		{name: "missing lane root", entry: "meta/baseline-home", value: "", want: "missing meta/baseline-home"},
		{name: "missing runtime", entry: "meta/strace-version", value: "", want: "version receipts"},
		{name: "target outside exercise", entry: "meta/target-root", value: "/run/baseline/workspace/skills/observed\n", want: "belong to the exercise lane"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := fixtureBundleEntries("obs_metadata", "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "skill", "")
			entries[test.entry] = test.value
			path := filepath.Join(t.TempDir(), "capture.tar.gz")
			if err := writeTestBundle(path, entries); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadCaptureBundle(path, 1<<20); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestCaptureTargetBindingAndRuntimeQuota(t *testing.T) {
	requireLinuxControlHost(t)
	if err := verifyCaptureRun(CaptureMetadata{RunID: "obs_old"}, "obs_current"); err == nil || !strings.Contains(err.Error(), "run ID mismatch") {
		t.Fatalf("run binding err = %v", err)
	}
	metadata := CaptureMetadata{TargetSHA256: "sha256:old"}
	target := TargetEvidence{SHA256: "sha256:new"}
	if err := verifyCaptureTarget(metadata, target); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("err = %v", err)
	}
	if got := captureFileBlocks(64 << 20); got != 8192 {
		t.Fatalf("captureFileBlocks = %d", got)
	}
	for _, required := range []string{
		"systemd-run", "KillMode=control-group", "SendSIGKILL=yes", "RuntimeMaxSec", "run-agent.sh",
		"ProtectSystem=strict", "ProtectHome=tmpfs", "IPAddressDeny=any", "SocketBindDeny=any", "StandardOutput=null",
		"SystemCallFilter=~io_uring_setup io_uring_register io_uring_enter", "SystemCallErrorNumber=EPERM",
		`BindPaths=$root/tmp:/tmp $root/var-tmp:/var/tmp`, `WorkingDirectory=$workspace`,
		"same-name dedicated primary group", "must not have supplementary groups",
		"control and agent users must differ",
		`as_root install -d -m 0711 "$OUT" "$OUT/runtime"`, `as_root chown "$(id -u):$(id -g)" "$OUT" "$OUT/runtime"`,
		"cannot traverse the baseline lane",
		`WORK_ROOT="/run/observatory-$RUN_ID"`, `InaccessiblePaths=$REPO_ROOT $other_root`,
		`/bin/bash "$CONTROL/run-agent.sh"`, `install -m 0600 "$OUT/raw.tar.gz" "$DOWNLOAD_OUT/raw.tar.gz"`,
		`local session="observatory-$RUN_ID"`,
		"lane storage must be a bounded tmpfs",
	} {
		if !strings.Contains(remoteRunScript, required) {
			t.Fatalf("remote runner missing %q", required)
		}
	}
	if strings.Contains(remoteRunScript, "timeout --signal=TERM") || !strings.Contains(remoteAgentScript, "ulimit -f") || !strings.Contains(remoteAgentScript, "strace -f -qq -s 0") {
		t.Fatalf("remote capture bounds are incomplete")
	}
	for _, syscall := range []string{"sendmmsg", "truncate", "ftruncate", "symlink", "symlinkat", "chdir", "fchdir", "clone", "clone3", "fork", "vfork", "unshare"} {
		if !strings.Contains(remoteAgentScript, syscall) {
			t.Fatalf("remote capture omits %s", syscall)
		}
	}
	for name, script := range map[string]string{"run.sh": remoteRunScript, "run-agent.sh": remoteAgentScript} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("%s syntax: %v: %s", name, err, output)
		}
	}
	rules := guestFirewallRules("obs_fixture", []string{"10.0.0.2:8000"})
	for _, expected := range []string{"policy drop", "ip saddr @MANAGEMENT_IPV4@ tcp dport 22 accept", "ip daddr 10.0.0.2 tcp dport 8000 accept"} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("guest firewall missing %q:\n%s", expected, rules)
		}
	}
	if !strings.Contains(remoteRunScript, "management peer must be literal IPv4") || !strings.Contains(remoteRunScript, `input.replace(marker,peer)`) {
		t.Fatalf("remote runner does not pin SSH admission to the active management peer")
	}
}

func TestCaptureConfigurationBindingAndPluginPrompt(t *testing.T) {
	config := validTestConfig(t, t.TempDir())
	metadata := CaptureMetadata{CaptureConfigSHA: captureConfigSHA256(config)}
	if err := verifyCaptureConfig(metadata, config); err != nil {
		t.Fatal(err)
	}
	changed := config
	changed.Exercise.Prompt = "different prompt"
	if err := verifyCaptureConfig(metadata, changed); err == nil || !strings.Contains(err.Error(), "configuration digest mismatch") {
		t.Fatalf("err = %v", err)
	}
	if captureConfigSHA256ForProtocol(config, CaptureProtocolRevision+"-changed") == metadata.CaptureConfigSHA {
		t.Fatal("capture protocol revision is not bound into the configuration receipt")
	}
	pluginTarget := TargetEvidence{Kind: "plugin", ID: "observatory-probe", DeclaredTools: []string{"observatory_probe"}}
	config.Exercise.Prompt = DefaultExercisePrompt
	effective, err := effectiveConfigForTarget(config, pluginTarget)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(effective.Exercise.Prompt, `"observatory_probe"`) || strings.Contains(effective.Exercise.Prompt, `"observed" skill`) {
		t.Fatalf("plugin prompt = %q", effective.Exercise.Prompt)
	}
	if _, err := effectiveConfigForTarget(config, TargetEvidence{Kind: "plugin", ID: "no-tools"}); err == nil || !strings.Contains(err.Error(), "explicit exercise.prompt") {
		t.Fatalf("err = %v", err)
	}
	skillConfig, err := effectiveConfigForTarget(config, TargetEvidence{Kind: "skill", ID: "observatory-probe-skill"})
	if err != nil || !strings.Contains(skillConfig.Exercise.Prompt, `"observatory-probe-skill"`) {
		t.Fatalf("skill prompt = %q err=%v", skillConfig.Exercise.Prompt, err)
	}
}

func findCanary(canaries []CanaryObservation, id string) CanaryObservation {
	for _, canary := range canaries {
		if canary.ID == id {
			return canary
		}
	}
	return CanaryObservation{}
}

func findCanaryDefinition(canaries []CanaryDefinition, id string) CanaryDefinition {
	for _, canary := range canaries {
		if canary.ID == id {
			return canary
		}
	}
	return CanaryDefinition{}
}

func validTestConfig(t *testing.T, artifactsDir string) Config {
	t.Helper()
	crabboxConfig := filepath.Join(artifactsDir, "crabbox.yml")
	if err := os.WriteFile(crabboxConfig, []byte(testCrabboxConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{
		Version:      1,
		Live:         true,
		ArtifactsDir: artifactsDir,
		Executor:     ExecutorConfig{Kind: "crabbox", Command: "fake-crabbox", CrabboxConfig: crabboxConfig},
		Isolation:    validIsolationConfig(),
		Runtime: RuntimeConfig{
			OpenClawCommand: "openclaw", AgentUser: "observatory", TimeoutSeconds: 10,
			Model:                 ModelConfig{Provider: "local", BaseURL: "http://10.0.0.2:8000/v1", ID: "fixture-model", API: "openai-completions", ContextWindow: 8192, MaxTokens: 1024},
			ControlPlaneAddresses: []string{"10.0.0.2:8000"},
		},
		Exercise: ExerciseConfig{Prompt: "Use the observed skill.", TurnLimit: 1},
		Limits: LimitsConfig{
			MaxFiles: 100, MaxFileBytes: 1 << 20, MaxTotalBytes: 4 << 20, MaxBundleBytes: 4 << 20,
			MaxLaneBytes: 64 << 20, MaxMemoryBytes: 512 << 20, CPUQuotaPct: 100, MaxTasks: 64,
		},
	}
	return config
}

const testCrabboxConfig = `provider: proxmox
target: linux
proxmox:
  apiUrl: https://pve.fixture.invalid:8006
  node: pve-fixture
  templateId: 9400
  bridge: vmbr-observatory
  user: crabbox
  workRoot: /work/observatory
  fullClone: true
`

func validIsolationConfig() IsolationConfig {
	return IsolationConfig{
		Substrate: "proxmox-vm", NetworkMode: "deny-except-model", Verified: true, Verification: "fixture-network-proof",
		VMTemplateID: 9400, NetworkBridge: "vmbr-observatory", FreshVM: true, DedicatedNetwork: true,
		DefaultDenyEgress: true, NoHostMounts: true, NoRuntimeSockets: true, SyntheticIdentityOnly: true,
	}
}

type fixtureExecutor struct {
	t            *testing.T
	command      string
	args         []string
	err          error
	baselineExit int
	exerciseExit int
}

func (executor *fixtureExecutor) Run(_ context.Context, command string, args []string, cwd string, env map[string]string, _ time.Duration) (CommandResult, error) {
	executor.command = command
	executor.args = append([]string(nil), args...)
	if env["CRABBOX_CONFIG"] == "" {
		executor.t.Fatal("missing CRABBOX_CONFIG")
	}
	joinedArgs := strings.Join(args, " ")
	for _, required := range []string{"run --provider proxmox --target linux", "--proxmox-template-id 9400", "--proxmox-bridge vmbr-observatory", "--proxmox-full-clone=true", "--stop-after always"} {
		if !strings.Contains(joinedArgs, required) {
			executor.t.Fatalf("Crabbox args missing %q: %s", required, joinedArgs)
		}
	}
	runtimeData, err := os.ReadFile(filepath.Join(cwd, "runner", "runtime.json"))
	if err != nil {
		executor.t.Fatal(err)
	}
	var runtime struct {
		RunID            string            `json:"runId"`
		TargetSHA256     string            `json:"targetSha256"`
		CaptureConfigSHA string            `json:"captureConfigSha256"`
		TargetKind       string            `json:"targetKind"`
		TargetID         string            `json:"targetId"`
		Canaries         map[string]string `json:"canaries"`
	}
	if err := json.Unmarshal(runtimeData, &runtime); err != nil {
		executor.t.Fatal(err)
	}
	download := ""
	for i, arg := range args {
		if arg == "--download" && i+1 < len(args) {
			download = args[i+1]
		}
	}
	_, bundlePath, ok := strings.Cut(download, "=")
	if !ok {
		executor.t.Fatalf("missing download arg: %#v", args)
	}
	entries := fixtureBundleEntries(runtime.RunID, runtime.TargetSHA256, runtime.CaptureConfigSHA, runtime.TargetKind, runtime.TargetID)
	canaryJSON, err := json.Marshal(runtime.Canaries)
	if err != nil {
		executor.t.Fatal(err)
	}
	entries["meta/canaries.json"] = string(canaryJSON) + "\n"
	entries["meta/baseline-exit"] = fmt.Sprintf("%d\n", executor.baselineExit)
	entries["meta/exercise-exit"] = fmt.Sprintf("%d\n", executor.exerciseExit)
	if err := writeTestBundle(bundlePath, entries); err != nil {
		executor.t.Fatal(err)
	}
	return CommandResult{Stdout: "fixture run\n"}, executor.err
}

func fixtureBundleEntries(runID string, targetSHA256 string, captureConfigSHA string, targetKind string, targetID string) map[string]string {
	if targetID == "" {
		targetID = "observed"
	}
	targetRoot := "/run/exercise/workspace/skills/" + targetID
	targetFile := targetRoot + "/SKILL.md"
	if targetKind == "plugin" {
		targetRoot = "/run/exercise/plugin/" + targetID
		targetFile = targetRoot + "/index.js"
	}
	exerciseTrace := "201 execve(\"/usr/bin/node\", [\"node\"], 0x0) = 0\n" +
		"201 openat(AT_FDCWD, \"" + targetFile + "\", O_RDONLY) = 3\n" +
		"201 openat(AT_FDCWD, \"/run/exercise/home/.aws/credentials\", O_RDONLY) = 4\n" +
		"201 openat(AT_FDCWD, \"/etc/shadow\", O_RDONLY) = -1 EACCES (Permission denied)\n" +
		"201 openat(AT_FDCWD, \"/run/exercise/workspace/probe.json\", O_WRONLY|O_CREAT|O_TRUNC, 0600) = 5\n" +
		"201 openat(AT_FDCWD, \"/run/exercise/home/.bashrc\", O_WRONLY|O_CREAT|O_APPEND, 0600) = 6\n" +
		"201 openat(AT_FDCWD, \"/etc/cron.d/observatory-probe\", O_WRONLY|O_CREAT, 0644) = -1 EROFS (Read-only file system)\n"
	canaryJSON, _ := json.Marshal(testCanaryMarkers())
	stateInventory := "0600\t" + strings.Repeat("1", 64) + "\tstate/openclaw.json\n"
	bashrcInventory := "0600\t" + strings.Repeat("2", 64) + "\thome/.bashrc\n"
	return map[string]string{
		"meta/run-id":                runID + "\n",
		"meta/target-sha256":         targetSHA256 + "\n",
		"meta/capture-config-sha256": captureConfigSHA + "\n",
		"meta/target-kind":           targetKind + "\n",
		"meta/canaries.json":         string(canaryJSON) + "\n",
		"meta/started-at":            "2026-07-10T12:00:00Z\n",
		"meta/completed-at":          "2026-07-10T12:00:01Z\n",
		"meta/baseline-exit":         "0\n",
		"meta/exercise-exit":         "0\n",
		"meta/baseline-workspace":    "/run/baseline/workspace\n",
		"meta/exercise-workspace":    "/run/exercise/workspace\n",
		"meta/baseline-state":        "/run/baseline/state\n",
		"meta/exercise-state":        "/run/exercise/state\n",
		"meta/baseline-home":         "/run/baseline/home\n",
		"meta/exercise-home":         "/run/exercise/home\n",
		"meta/target-root":           targetRoot + "\n",
		"meta/openclaw-version":      "OpenClaw fixture\n",
		"meta/strace-version":        "strace fixture\n",
		"meta/firewall-sha256":       strings.Repeat("a", 64) + "\n",
		"baseline/trace":             "101 execve(\"/usr/bin/node\", [\"node\"], 0x0) = 0\n",
		"exercise/trace":             exerciseTrace,
		"baseline/agent.stdout":      "baseline\n",
		"exercise/agent.stdout":      "exercise\n",
		"baseline/inventory.before":  stateInventory,
		"baseline/inventory.after":   stateInventory,
		"exercise/inventory.before":  stateInventory,
		"exercise/inventory.after":   stateInventory + bashrcInventory,
	}
}

func testCanaryMarkers() map[string]string {
	return map[string]string{
		"workspace-identity":   "OBS-CANARY-" + strings.Repeat("a", 48),
		"workspace-memory":     "OBS-CANARY-" + strings.Repeat("b", 48),
		"cloud-credentials":    "OBS-CANARY-" + strings.Repeat("c", 48),
		"openclaw-credentials": "OBS-CANARY-" + strings.Repeat("d", 48),
	}
}

func testCanaries() []CanaryDefinition {
	definitions, err := canaryDefinitions(testCanaryMarkers())
	if err != nil {
		panic(err)
	}
	return definitions
}

func writeTestBundle(path string, entries map[string]string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, value := range entries {
		data := []byte(value)
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tarWriter.Write(data); err != nil {
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}
	return file.Close()
}

func fixtureEvidence() Evidence {
	return Evidence{
		SchemaVersion:       EvidenceSchemaVersion,
		CaptureConfigSHA256: "sha256:" + strings.Repeat("d", 64),
		Target: TargetEvidence{
			Name: "fixture-skill", Kind: "skill", ID: "fixture-skill", Lineage: "example/fixture-skill", SHA256: "sha256:" + strings.Repeat("a", 64), FileCount: 1, DirectoryCount: 1, TotalBytes: 10,
			Files: []TargetFile{{Path: "SKILL.md", Bytes: 10, Mode: "0644"}}, Directories: []TargetDirectory{{Path: ".", Mode: "0755"}},
		},
		Run: RunEvidence{
			ID: "obs_fixture", Status: "completed", StartedAt: "2026-07-10T11:59:59Z", CompletedAt: "2026-07-10T12:00:00Z", Executor: "fixture",
			Isolation: IsolationEvidence{Substrate: "proxmox-vm", NetworkMode: "deny-except-model", ContainmentProfile: "fixture", GuestFirewallSHA256: "sha256:" + strings.Repeat("b", 64), GuestFirewallPolicySHA256: "sha256:" + strings.Repeat("e", 64), Verification: "fixture"},
			Runtime:   RuntimeEvidence{OpenClawVersion: "OpenClaw fixture", StraceVersion: "strace fixture", ModelProvider: "local", ModelID: "fixture", ModelEndpoint: "private"},
		},
		Exercise:     ExerciseEvidence{PromptSHA256: "sha256:" + strings.Repeat("c", 64), TurnLimit: 1},
		Observations: []Observation{},
		Canaries:     []CanaryObservation{{ID: "cloud-credentials", Surface: "home file"}},
		Persistence:  PersistenceEvidence{Scope: "selected-persistence-surfaces", InventoryPaired: false, Surfaces: persistenceSurfaceCatalog(), Findings: []PersistenceFinding{}, Limitations: []string{"Fixture persistence limitation."}},
		Coverage:     CoverageEvidence{SyscallScope: "selected-mvp-syscalls", FileSyscalls: true, ProcessSyscalls: true, NetworkSyscalls: true, BaselinePaired: true, Limitations: []string{"Fixture limitation."}},
	}
}

func TestDecodeEvidenceFromClawscanArtifact(t *testing.T) {
	evidence := fixtureEvidence()
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	artifact := map[string]any{"scanners": map[string]any{"behavior": map[string]any{"raw": json.RawMessage(raw)}}}
	data, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEvidence(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Run.ID != evidence.Run.ID {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestDecodeEvidenceAcceptsGeneratedManifestLargerThanSixteenMiB(t *testing.T) {
	evidence := fixtureEvidence()
	evidence.Target.Files = make([]TargetFile, 4999)
	longComponent := strings.Repeat("x", 3500)
	for index := range evidence.Target.Files {
		evidence.Target.Files[index] = TargetFile{Path: fmt.Sprintf("%04d/%s", index, longComponent), Mode: "0644"}
	}
	evidence.Target.FileCount = len(evidence.Target.Files)
	evidence.Target.TotalBytes = 0
	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= 16<<20 {
		t.Fatalf("fixture is only %d bytes", len(data))
	}
	if _, err := DecodeEvidence(bytes.NewReader(data)); err != nil {
		t.Fatalf("decode %d-byte generated evidence: %v", len(data), err)
	}
}

func TestValidateEvidenceRejectsInconsistentCounts(t *testing.T) {
	evidence := fixtureEvidence()
	evidence.Observations = append(evidence.Observations, Observation{
		Kind: "file", Operation: "read", Subject: "$WORKSPACE/file", Outcome: "succeeded",
		BaselineCount: 1, ExerciseCount: 1, DeltaCount: 1,
	})
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "invalid observation") {
		t.Fatalf("observation count err = %v", err)
	}
	evidence = fixtureEvidence()
	evidence.Canaries[0].DeltaInteractions = 1
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "invalid canary") {
		t.Fatalf("canary count err = %v", err)
	}
}

func TestApplyTargetModesRestoresGitLostPermissionsAndEmptyDirectories(t *testing.T) {
	requireLinuxControlHost(t)
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for target-mode restoration validation")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "target")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "payload.txt"), []byte("fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := struct {
		Files       []TargetFile      `json:"files"`
		Directories []TargetDirectory `json:"directories"`
	}{
		Files:       []TargetFile{{Path: "payload.txt", Bytes: 8, Mode: "0440"}},
		Directories: []TargetDirectory{{Path: ".", Mode: "0750"}, {Path: "empty", Mode: "0500"}},
	}
	manifestPath := filepath.Join(dir, "target-modes.json")
	if err := writeJSON(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(dir, "apply-target-modes.mjs")
	if err := os.WriteFile(scriptPath, []byte(applyTargetModesScript), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, scriptPath, manifestPath, root).CombinedOutput(); err != nil {
		t.Fatalf("apply target modes: %v: %s", err, output)
	}
	for path, expected := range map[string]os.FileMode{
		root:                               0o750,
		filepath.Join(root, "empty"):       0o500,
		filepath.Join(root, "payload.txt"): 0o440,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != expected {
			t.Fatalf("restored mode %s = %v, %v; want %v", path, info, err, expected)
		}
	}
}

func TestGeneratedOpenClawConfigDiscoversOwnedSkillWhenCLIAvailable(t *testing.T) {
	requireLinuxControlHost(t)
	node, nodeErr := exec.LookPath("node")
	openclaw, openclawErr := exec.LookPath("openclaw")
	if nodeErr != nil || openclawErr != nil {
		t.Skip("node and openclaw are required for generated-config validation")
	}
	dir := t.TempDir()
	runnerDir := filepath.Join(dir, "runner")
	if err := os.MkdirAll(runnerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	runtime := map[string]any{
		"timeoutSeconds": 60,
		"targetKind":     "skill",
		"targetId":       "observatory-probe-skill",
		"canaries":       testCanaryMarkers(),
		"model": map[string]any{
			"provider": "observatory", "baseUrl": "http://127.0.0.1:8000/v1", "id": "fixture-model",
			"api": "openai-completions", "contextWindow": 8192, "maxTokens": 1024,
		},
	}
	runtimePath := filepath.Join(runnerDir, "runtime.json")
	if err := writeJSON(runtimePath, runtime, 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(runnerDir, "write-config.mjs")
	if err := os.WriteFile(scriptPath, []byte(writeConfigScript), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	workspace := filepath.Join(dir, "workspace")
	skillTarget := filepath.Join(workspace, "skills", "observatory-probe-skill")
	limits := LimitsConfig{MaxFiles: 100, MaxFileBytes: 1 << 20, MaxTotalBytes: 4 << 20, MaxBundleBytes: 4 << 20}
	if _, err := StageTarget(filepath.Join("..", "..", "testdata", "fixtures", "probe-skill"), skillTarget, limits); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(state, "openclaw.json")
	command := exec.Command(node, scriptPath, runtimePath)
	command.Env = append(os.Environ(), "OBSERVATORY_WORKSPACE="+workspace, "OBSERVATORY_HOME="+dir, "OBSERVATORY_LANE=exercise", "OBSERVATORY_TARGET_ROOT="+skillTarget, "OPENCLAW_STATE_DIR="+state, "OPENCLAW_CONFIG_PATH="+configPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate config: %v: %s", err, output)
	}
	command = exec.Command(openclaw, "config", "validate", "--json")
	openclawEnv := append(os.Environ(), "HOME="+dir, "OPENCLAW_STATE_DIR="+state, "OPENCLAW_CONFIG_PATH="+configPath)
	command.Env = openclawEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("validate generated OpenClaw config: %v: %s", err, output)
	}
	command = exec.Command(openclaw, "skills", "list", "--agent", "observatory", "--json")
	command.Env = openclawEnv
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("discover owned fixture skill: %v: %s", err, output)
	}
	if !bytes.Contains(output, []byte(`"name": "observatory-probe-skill"`)) && !bytes.Contains(output, []byte(`"name":"observatory-probe-skill"`)) {
		t.Fatalf("owned fixture skill missing from inventory: %s", output)
	}
}

func TestGeneratedPluginConfigDiscoversOwnedFixtureWhenCLIAvailable(t *testing.T) {
	requireLinuxControlHost(t)
	node, nodeErr := exec.LookPath("node")
	openclaw, openclawErr := exec.LookPath("openclaw")
	if nodeErr != nil || openclawErr != nil {
		t.Skip("node and openclaw are required for generated plugin-config validation")
	}
	pluginRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "probe-plugin"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	runnerDir := filepath.Join(dir, "runner")
	if err := os.MkdirAll(runnerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	runtime := map[string]any{
		"timeoutSeconds": 60,
		"targetKind":     "plugin",
		"targetId":       "observatory-probe",
		"canaries":       testCanaryMarkers(),
		"model": map[string]any{
			"provider": "observatory", "baseUrl": "http://127.0.0.1:8000/v1", "id": "fixture-model",
			"api": "openai-completions", "contextWindow": 8192, "maxTokens": 1024,
		},
	}
	runtimePath := filepath.Join(runnerDir, "runtime.json")
	if err := writeJSON(runtimePath, runtime, 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(runnerDir, "write-config.mjs")
	if err := os.WriteFile(scriptPath, []byte(writeConfigScript), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	workspace := filepath.Join(dir, "workspace")
	configPath := filepath.Join(state, "openclaw.json")
	environment := append(os.Environ(),
		"OBSERVATORY_WORKSPACE="+workspace,
		"OBSERVATORY_HOME="+dir,
		"OBSERVATORY_LANE=exercise",
		"OBSERVATORY_TARGET_ROOT="+pluginRoot,
		"OPENCLAW_STATE_DIR="+state,
		"OPENCLAW_CONFIG_PATH="+configPath,
	)
	command := exec.Command(node, scriptPath, runtimePath)
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate plugin config: %v: %s", err, output)
	}
	command = exec.Command(openclaw, "config", "validate", "--json")
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("validate generated plugin config: %v: %s", err, output)
	}
	command = exec.Command(openclaw, "plugins", "list", "--json")
	command.Env = environment
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("discover fixture plugin: %v: %s", err, output)
	}
	if !bytes.Contains(output, []byte(`"id": "observatory-probe"`)) && !bytes.Contains(output, []byte(`"id":"observatory-probe"`)) {
		t.Fatalf("fixture plugin missing from inventory: %s", output)
	}
}
