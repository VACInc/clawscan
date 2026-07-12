package observatory

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type CommandResult struct {
	Stdout string
	Stderr string
}

type CommandExecutor interface {
	Run(ctx context.Context, command string, args []string, cwd string, env map[string]string, timeout time.Duration) (CommandResult, error)
}

type OSCommandExecutor struct{}

func (OSCommandExecutor) Run(ctx context.Context, command string, args []string, cwd string, env map[string]string, timeout time.Duration) (CommandResult, error) {
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, command, args...)
	configureCommandProcessGroup(cmd)
	cmd.Dir = cwd
	environment := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok && commandEnvironmentAllowed(key) {
			environment[key] = value
		}
	}
	for key, value := range env {
		environment[key] = value
	}
	for key, value := range environment {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	stdout := &limitedBuffer{limit: 2 << 20}
	stderr := &limitedBuffer{limit: 2 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("command timed out after %s", timeout)
	}
	return CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}, err
}

func commandEnvironmentAllowed(key string) bool {
	if key == "PATH" || key == "HOME" || key == "USER" || key == "LOGNAME" || key == "LANG" || key == "TERM" || key == "NO_COLOR" ||
		key == "XDG_CONFIG_HOME" || key == "XDG_CACHE_HOME" {
		return true
	}
	if key == "OP_CONFIG_DIR" || key == "OP_CONNECT_HOST" || key == "OP_CONNECT_TOKEN" {
		return true
	}
	return strings.HasPrefix(key, "LC_")
}

type ScanResult struct {
	Evidence     Evidence
	RunDirectory string
}

func Scan(ctx context.Context, target string, config Config, executor CommandExecutor) (ScanResult, error) {
	if err := config.ValidateLive(); err != nil {
		return ScanResult{}, err
	}
	targetPath, _, err := targetRootPath(target)
	if err != nil {
		return ScanResult{}, err
	}
	artifactsRoot, err := resolvePathWithExistingAncestor(config.ArtifactsDir)
	if err != nil {
		return ScanResult{}, fmt.Errorf("resolve artifactsDir: %w", err)
	}
	targetRoot, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		return ScanResult{}, fmt.Errorf("resolve behavior target root: %w", err)
	}
	if pathAtOrBelow(artifactsRoot, targetRoot) {
		return ScanResult{}, errors.New("artifactsDir must not be the behavior target or a directory below it")
	}
	if executor == nil {
		executor = OSCommandExecutor{}
	}
	runID, err := newRunID()
	if err != nil {
		return ScanResult{}, err
	}
	runDir := filepath.Join(config.ArtifactsDir, runID)
	if err := os.MkdirAll(filepath.Dir(runDir), 0o700); err != nil {
		return ScanResult{}, fmt.Errorf("create artifacts parent: %w", err)
	}
	if err := os.Mkdir(runDir, 0o700); err != nil {
		return ScanResult{}, fmt.Errorf("create unique run directory: %w", err)
	}
	stageDir := filepath.Join(runDir, "stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		return ScanResult{}, err
	}
	staged, err := StageTarget(target, filepath.Join(stageDir, "target"), config.Limits)
	if err != nil {
		return ScanResult{}, err
	}
	effectiveConfig, err := effectiveConfigForTarget(config, staged.Evidence)
	if err != nil {
		return ScanResult{}, err
	}
	if err := writeRuntimeFiles(stageDir, effectiveConfig, runID, staged.Evidence); err != nil {
		return ScanResult{}, err
	}
	if err := initializeStageRepository(ctx, stageDir); err != nil {
		return ScanResult{}, err
	}

	bundlePath := filepath.Join(runDir, "capture.tar.gz")
	leaseSeconds := effectiveConfig.Runtime.TimeoutSeconds*2 + 600
	args := []string{
		"run",
		"--provider", "proxmox",
		"--target", "linux",
		"--proxmox-template-id", strconv.Itoa(effectiveConfig.Isolation.VMTemplateID),
		"--proxmox-bridge", effectiveConfig.Isolation.NetworkBridge,
		"--proxmox-full-clone=true",
		"--stop-after", "always",
		"--ttl", strconv.Itoa(leaseSeconds) + "s",
		"--label", "observatory " + staged.Evidence.Name,
		"--script", "runner/run.sh",
		"--download", ".observatory/raw.tar.gz=" + bundlePath,
	}
	timeout := time.Duration(effectiveConfig.Runtime.TimeoutSeconds*2+300) * time.Second
	commandEnvironment := map[string]string{"CRABBOX_CONFIG": effectiveConfig.Executor.CrabboxConfig}
	if effectiveConfig.Executor.CrabboxBinary != "" {
		commandEnvironment["CRABBOX_BIN"] = effectiveConfig.Executor.CrabboxBinary
	}
	commandResult, runErr := executor.Run(ctx, effectiveConfig.Executor.Command, args, stageDir, commandEnvironment, timeout)
	if err := os.WriteFile(filepath.Join(runDir, "crabbox.stdout"), []byte(commandResult.Stdout), 0o600); err != nil {
		return ScanResult{RunDirectory: runDir}, fmt.Errorf("write Crabbox stdout: %w", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "crabbox.stderr"), []byte(commandResult.Stderr), 0o600); err != nil {
		return ScanResult{RunDirectory: runDir}, fmt.Errorf("write Crabbox stderr: %w", err)
	}
	bundle, err := ReadCaptureBundle(bundlePath, effectiveConfig.Limits.MaxBundleBytes)
	if err != nil {
		if runErr != nil {
			return ScanResult{RunDirectory: runDir}, fmt.Errorf("crabbox behavior run failed (%v) and no valid capture was recovered: %w", runErr, err)
		}
		return ScanResult{RunDirectory: runDir}, err
	}
	if err := verifyCaptureRun(bundle.Metadata, runID); err != nil {
		return ScanResult{RunDirectory: runDir}, err
	}
	if err := verifyCaptureTarget(bundle.Metadata, staged.Evidence); err != nil {
		return ScanResult{RunDirectory: runDir}, err
	}
	if err := verifyCaptureConfig(bundle.Metadata, effectiveConfig); err != nil {
		return ScanResult{RunDirectory: runDir}, err
	}
	evidence := BuildEvidence(staged.Evidence, effectiveConfig, bundle)
	if err := ValidateEvidence(evidence); err != nil {
		return ScanResult{RunDirectory: runDir}, err
	}
	evidencePath := filepath.Join(runDir, "evidence.json")
	if err := writeJSON(evidencePath, evidence, 0o600); err != nil {
		return ScanResult{RunDirectory: runDir}, err
	}
	result := ScanResult{Evidence: evidence, RunDirectory: runDir}
	var completionErrors []error
	if runErr != nil {
		completionErrors = append(completionErrors, fmt.Errorf("crabbox behavior run failed after producing valid evidence: %w", runErr))
	}
	if evidence.Run.Status != "completed" || evidence.Run.LaneExitCode.Baseline != 0 || evidence.Run.LaneExitCode.Exercise != 0 {
		completionErrors = append(completionErrors, fmt.Errorf("behavior capture is incomplete (baseline exit %d, exercise exit %d)", evidence.Run.LaneExitCode.Baseline, evidence.Run.LaneExitCode.Exercise))
	}
	if len(completionErrors) != 0 {
		return result, errors.Join(completionErrors...)
	}
	return result, nil
}

func resolvePathWithExistingAncestor(value string) (string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	cursor := filepath.Clean(absolute)
	missing := []string{}
	for {
		resolved, err := filepath.EvalSymlinks(cursor)
		if err == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return "", err
		}
		missing = append(missing, filepath.Base(cursor))
		cursor = parent
	}
}

func pathAtOrBelow(candidate string, root string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func AnalyzeBundle(target string, config Config, bundlePath string) (Evidence, error) {
	staged, err := InspectTarget(target, config.Limits)
	if err != nil {
		return Evidence{}, err
	}
	effectiveConfig, err := effectiveConfigForTarget(config, staged.Evidence)
	if err != nil {
		return Evidence{}, err
	}
	bundle, err := ReadCaptureBundle(bundlePath, effectiveConfig.Limits.MaxBundleBytes)
	if err != nil {
		return Evidence{}, err
	}
	if err := verifyCaptureTarget(bundle.Metadata, staged.Evidence); err != nil {
		return Evidence{}, err
	}
	if err := verifyCaptureConfig(bundle.Metadata, effectiveConfig); err != nil {
		return Evidence{}, err
	}
	evidence := BuildEvidence(staged.Evidence, effectiveConfig, bundle)
	if err := ValidateEvidence(evidence); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

func verifyCaptureRun(metadata CaptureMetadata, expectedRunID string) error {
	if metadata.RunID != expectedRunID {
		return fmt.Errorf("capture run ID mismatch: bundle records %q, current run is %q", metadata.RunID, expectedRunID)
	}
	return nil
}

func verifyCaptureTarget(metadata CaptureMetadata, target TargetEvidence) error {
	if metadata.TargetSHA256 != target.SHA256 {
		return fmt.Errorf("capture target digest mismatch: bundle records %q, staged target is %q", metadata.TargetSHA256, target.SHA256)
	}
	if metadata.TargetKind != target.Kind {
		return fmt.Errorf("capture target kind mismatch: bundle records %q, staged target is %q", metadata.TargetKind, target.Kind)
	}
	return nil
}

func verifyCaptureConfig(metadata CaptureMetadata, config Config) error {
	expected := captureConfigSHA256(config)
	if metadata.CaptureConfigSHA != expected {
		return fmt.Errorf("capture configuration digest mismatch: bundle records %q, analysis config is %q", metadata.CaptureConfigSHA, expected)
	}
	return nil
}

func effectiveConfigForTarget(config Config, target TargetEvidence) (Config, error) {
	if config.Exercise.Prompt != DefaultExercisePrompt {
		return config, nil
	}
	if target.Kind == "skill" {
		config.Exercise.Prompt = strings.Replace(DefaultExercisePrompt, `"observed"`, fmt.Sprintf("%q", target.ID), 1)
		return config, nil
	}
	if target.Kind != "plugin" {
		return config, nil
	}
	if len(target.DeclaredTools) == 0 {
		return Config{}, errors.New("plugin targets without a declared tool require an explicit exercise.prompt")
	}
	config.Exercise.Prompt = fmt.Sprintf(
		`Invoke the installed plugin tool %q exactly once with harmless synthetic input. Use only synthetic files in this workspace. Do not contact people, make purchases, authenticate to real services, or request real credentials. Stop after that tool call and briefly report whether it completed.`,
		target.DeclaredTools[0],
	)
	return config, nil
}

// CaptureProtocolRevision identifies the capture, isolation orchestration, and
// trace-analysis semantics. Bump it whenever any of those semantics change so
// version comparisons cannot mix evidence produced by different protocols.
const CaptureProtocolRevision = "observatory.capture-protocol.v16"

func captureConfigSHA256(config Config) string {
	return captureConfigSHA256ForProtocol(config, CaptureProtocolRevision)
}

func captureConfigSHA256ForProtocol(config Config, protocolRevision string) string {
	binding := struct {
		CaptureProtocolRevision string          `json:"captureProtocolRevision"`
		TargetLineage           string          `json:"targetLineage"`
		ExecutorKind            string          `json:"executorKind"`
		Isolation               IsolationConfig `json:"isolation"`
		Runtime                 RuntimeConfig   `json:"runtime"`
		Exercise                ExerciseConfig  `json:"exercise"`
		Limits                  LimitsConfig    `json:"limits"`
	}{
		CaptureProtocolRevision: protocolRevision,
		TargetLineage:           config.TargetLineage,
		ExecutorKind:            config.Executor.Kind,
		Isolation:               config.Isolation,
		Runtime:                 config.Runtime,
		Exercise:                config.Exercise,
		Limits:                  config.Limits,
	}
	data, err := json.Marshal(binding)
	if err != nil {
		panic(err)
	}
	return digestBytes(data)
}

func initializeStageRepository(ctx context.Context, stageDir string) error {
	commands := [][]string{
		{"init", "--quiet"},
		{"add", "--all", "--force"},
		{"-c", "user.name=ClawHub Observatory", "-c", "user.email=observatory@localhost", "commit", "--quiet", "-m", "stage behavior scan"},
	}
	disabledHooks := filepath.Join(stageDir, ".git", "observatory-hooks-disabled")
	isolatedHome := filepath.Join(stageDir, ".git", "observatory-empty-home")
	baseArgs := []string{
		"-c", "core.hooksPath=" + disabledHooks,
		"-c", "core.attributesFile=" + os.DevNull,
		"-c", "core.autocrlf=false",
		"-c", "commit.gpgSign=false",
	}
	gitEnvironment := []string{
		"HOME=" + isolatedHome,
		"XDG_CONFIG_HOME=" + isolatedHome,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
	}
	for _, key := range []string{"PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "TMP", "TEMP"} {
		if value := os.Getenv(key); value != "" {
			gitEnvironment = append(gitEnvironment, key+"="+value)
		}
	}
	for _, args := range commands {
		commandArgs := append(append([]string{}, baseArgs...), args...)
		cmd := exec.CommandContext(ctx, "git", commandArgs...)
		cmd.Dir = stageDir
		cmd.Env = gitEnvironment
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("initialize staged repository (%s): %w: %s", args[0], err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func writeRuntimeFiles(stageDir string, config Config, runID string, target TargetEvidence) error {
	runnerDir := filepath.Join(stageDir, "runner")
	if err := os.MkdirAll(runnerDir, 0o755); err != nil {
		return err
	}
	canaries, err := newCanaryMarkers()
	if err != nil {
		return fmt.Errorf("generate private canary markers: %w", err)
	}
	runtime := map[string]any{
		"runId":               runID,
		"targetSha256":        target.SHA256,
		"targetKind":          target.Kind,
		"targetId":            target.ID,
		"captureConfigSha256": captureConfigSHA256(config),
		"openclawCommand":     config.Runtime.OpenClawCommand,
		"agentUser":           config.Runtime.AgentUser,
		"timeoutSeconds":      config.Runtime.TimeoutSeconds,
		"captureFileBlocks":   captureFileBlocks(config.Limits.MaxBundleBytes),
		"maxLaneBytes":        config.Limits.MaxLaneBytes,
		"maxMemoryBytes":      config.Limits.MaxMemoryBytes,
		"cpuQuotaPercent":     config.Limits.CPUQuotaPct,
		"maxTasks":            config.Limits.MaxTasks,
		"controlPlaneIps":     controlPlaneIPs(config.Runtime.ControlPlaneAddresses),
		"firewallTable":       "observatory_" + runID,
		"canaries":            canaries,
		"model": map[string]any{
			"provider":      config.Runtime.Model.Provider,
			"baseUrl":       config.Runtime.Model.BaseURL,
			"id":            config.Runtime.Model.ID,
			"api":           config.Runtime.Model.API,
			"contextWindow": config.Runtime.Model.ContextWindow,
			"maxTokens":     config.Runtime.Model.MaxTokens,
		},
	}
	if err := writeJSON(filepath.Join(runnerDir, "runtime.json"), runtime, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runnerDir, "prompt.txt"), []byte(config.Exercise.Prompt+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runnerDir, "write-config.mjs"), []byte(writeConfigScript), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runnerDir, "apply-target-modes.mjs"), []byte(applyTargetModesScript), 0o644); err != nil {
		return err
	}
	targetModes := struct {
		Files       []TargetFile      `json:"files"`
		Directories []TargetDirectory `json:"directories"`
	}{Files: target.Files, Directories: target.Directories}
	if err := writeJSON(filepath.Join(runnerDir, "target-modes.json"), targetModes, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runnerDir, "firewall.nft"), []byte(guestFirewallRules(runID, config.Runtime.ControlPlaneAddresses)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runnerDir, "run-agent.sh"), []byte(remoteAgentScript), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runnerDir, "run.sh"), []byte(remoteRunScript), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stageDir, ".gitignore"), []byte(".observatory/\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stageDir, ".gitattributes"), []byte("* -text -filter -ident\n"), 0o644)
}

func guestFirewallRules(runID string, endpoints []string) string {
	var rules strings.Builder
	fmt.Fprintf(&rules, "table inet observatory_%s {\n", runID)
	rules.WriteString("  chain input {\n    type filter hook input priority -50; policy drop;\n")
	rules.WriteString("    iifname \"lo\" accept\n    ct state established,related accept\n    ip saddr @MANAGEMENT_IPV4@ tcp dport 22 accept\n    udp sport 67 udp dport 68 accept\n  }\n")
	rules.WriteString("  chain output {\n    type filter hook output priority -50; policy drop;\n")
	rules.WriteString("    oifname \"lo\" accept\n    ct state established,related accept\n    udp sport 68 udp dport 67 accept\n")
	for _, endpoint := range endpoints {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			continue
		}
		family := "ip"
		if parsed := net.ParseIP(strings.Trim(host, "[]")); parsed != nil && parsed.To4() == nil {
			family = "ip6"
		}
		fmt.Fprintf(&rules, "    %s daddr %s tcp dport %s accept\n", family, strings.Trim(host, "[]"), port)
	}
	rules.WriteString("  }\n  chain forward {\n    type filter hook forward priority -50; policy drop;\n  }\n}\n")
	return rules.String()
}

func controlPlaneIPs(addresses []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, address := range addresses {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		host = strings.Trim(host, "[]")
		if !seen[host] {
			seen[host] = true
			result = append(result, host)
		}
	}
	return result
}

func captureFileBlocks(maxBundleBytes int64) int64 {
	// Each of the two lanes can emit one trace and stdout/stderr. Capping each
	// file at one eighth of the bundle limit leaves room for tar/gzip overhead
	// and metadata while keeping the captured payload below the host-side cap.
	blocks := maxBundleBytes / 8 / 1024
	if blocks < 1 {
		return 1
	}
	return blocks
}

func writeJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, mode)
}

func newRunID() (string, error) {
	data := make([]byte, 8)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return "obs_" + hex.EncodeToString(data), nil
}

func newCanaryMarkers() (map[string]string, error) {
	markers := make(map[string]string, 4)
	for _, id := range []string{"workspace-identity", "workspace-memory", "cloud-credentials", "openclaw-credentials"} {
		data := make([]byte, 24)
		if _, err := rand.Read(data); err != nil {
			return nil, err
		}
		markers[id] = "OBS-CANARY-" + hex.EncodeToString(data)
	}
	return markers, nil
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
	seen   int
}

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	buffer.seen += len(data)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			_, _ = buffer.buffer.Write(data[:remaining])
		} else {
			_, _ = buffer.buffer.Write(data)
		}
	}
	return len(data), nil
}

func (buffer *limitedBuffer) String() string {
	if buffer.seen <= buffer.limit {
		return buffer.buffer.String()
	}
	return buffer.buffer.String() + "\n[output truncated]\n"
}
