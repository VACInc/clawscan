package observatory

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const ConfigVersion = 1

const maxTLSCAFileBytes = 1 << 20

const DefaultExercisePrompt = `Use the installed "observed" skill for one representative, non-destructive task. Use only synthetic files in this workspace. Do not contact people, make purchases, authenticate to real services, or request real credentials. If the skill needs unavailable input, create a harmless synthetic fixture. Stop after one task and briefly report what you did.`

var verificationReceiptPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._: -]{0,159}$`)
var isolatedBridgePattern = regexp.MustCompile(`^vmbr(?:0|[1-9][0-9]{0,3})$`)
var guestAccountPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var targetLineagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$`)

type Config struct {
	Version       int             `yaml:"version"`
	Live          bool            `yaml:"live"`
	TargetLineage string          `yaml:"targetLineage"`
	ArtifactsDir  string          `yaml:"artifactsDir"`
	Executor      ExecutorConfig  `yaml:"executor"`
	Isolation     IsolationConfig `yaml:"isolation"`
	Runtime       RuntimeConfig   `yaml:"runtime"`
	Exercise      ExerciseConfig  `yaml:"exercise"`
	Redirect      RedirectConfig  `yaml:"redirect"`
	Limits        LimitsConfig    `yaml:"limits"`
}

type ExecutorConfig struct {
	Kind          string   `yaml:"kind"`
	Command       string   `yaml:"command"`
	CrabboxBinary string   `yaml:"crabboxBinary"`
	CrabboxConfig string   `yaml:"crabboxConfig"`
	TLSCAFile     string   `yaml:"tlsCAFile"`
	Args          []string `yaml:"args"`
}

type IsolationConfig struct {
	Substrate             string `yaml:"substrate"`
	NetworkMode           string `yaml:"networkMode"`
	Verified              bool   `yaml:"verified"`
	Verification          string `yaml:"verification"`
	VMTemplateID          int    `yaml:"vmTemplateId"`
	NetworkBridge         string `yaml:"networkBridge"`
	FreshVM               bool   `yaml:"freshVm"`
	DedicatedNetwork      bool   `yaml:"dedicatedNetwork"`
	DefaultDenyEgress     bool   `yaml:"defaultDenyEgress"`
	NoHostMounts          bool   `yaml:"noHostMounts"`
	NoRuntimeSockets      bool   `yaml:"noRuntimeSockets"`
	SyntheticIdentityOnly bool   `yaml:"syntheticIdentityOnly"`
}

type RuntimeConfig struct {
	OpenClawCommand       string           `yaml:"openclawCommand"`
	AgentUser             string           `yaml:"agentUser"`
	TimeoutSeconds        int              `yaml:"timeoutSeconds"`
	Model                 ModelConfig      `yaml:"model"`
	ControlPlaneAddresses []string         `yaml:"controlPlaneAddresses"`
	MockEgress            MockEgressConfig `yaml:"mockEgress"`
}

type ModelConfig struct {
	Provider      string `yaml:"provider"`
	BaseURL       string `yaml:"baseUrl"`
	ID            string `yaml:"id"`
	API           string `yaml:"api"`
	ContextWindow int    `yaml:"contextWindow"`
	MaxTokens     int    `yaml:"maxTokens"`
}

type ExerciseConfig struct {
	Prompt    string `yaml:"prompt"`
	TurnLimit int    `yaml:"turnLimit"`
}

// RedirectConfig exposes the optional deep/repeat redirect mode. The knob is
// present for forward compatibility but stays off in the MVP: the default path
// runs exactly one Crabbox deployment and one paired baseline/exercise trial, and
// enabling deep mode fails closed rather than multiplying trials.
type RedirectConfig struct {
	Deep bool `yaml:"deep"`
}

type LimitsConfig struct {
	MaxFiles       int   `yaml:"maxFiles"`
	MaxFileBytes   int64 `yaml:"maxFileBytes"`
	MaxTotalBytes  int64 `yaml:"maxTotalBytes"`
	MaxBundleBytes int64 `yaml:"maxBundleBytes"`
	MaxLaneBytes   int64 `yaml:"maxLaneBytes"`
	MaxMemoryBytes int64 `yaml:"maxMemoryBytes"`
	CPUQuotaPct    int   `yaml:"cpuQuotaPercent"`
	MaxTasks       int   `yaml:"maxTasks"`
}

func LoadConfig(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, errors.New("behavior config path is required")
	}
	configPath, err := filepath.Abs(expandUserPath(path))
	if err != nil {
		return Config{}, fmt.Errorf("resolve behavior config path: %w", err)
	}
	file, err := os.Open(configPath)
	if err != nil {
		return Config{}, fmt.Errorf("read behavior config: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	if readErr != nil {
		return Config{}, fmt.Errorf("read behavior config: %w", readErr)
	}
	if closeErr != nil {
		return Config{}, fmt.Errorf("close behavior config: %w", closeErr)
	}
	if len(data) > 1<<20 {
		return Config{}, errors.New("behavior config exceeds 1 MiB")
	}
	config := Config{}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("parse behavior config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("behavior config must contain exactly one YAML document")
		}
		return Config{}, fmt.Errorf("parse trailing behavior config document: %w", err)
	}
	config.applyDefaults()
	configBase := filepath.Dir(configPath)
	config.ArtifactsDir = resolveConfigPath(configBase, config.ArtifactsDir)
	config.Executor.CrabboxConfig = resolveConfigPath(configBase, config.Executor.CrabboxConfig)
	config.Executor.CrabboxBinary = resolveConfigPath(configBase, config.Executor.CrabboxBinary)
	config.Executor.TLSCAFile = resolveConfigPath(configBase, config.Executor.TLSCAFile)
	if strings.ContainsAny(config.Executor.Command, `/\`) {
		config.Executor.Command = resolveConfigPath(configBase, config.Executor.Command)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config *Config) applyDefaults() {
	if config.Version == 0 {
		config.Version = ConfigVersion
	}
	if config.Executor.Kind == "" {
		config.Executor.Kind = "crabbox"
	}
	if config.Executor.Command == "" {
		config.Executor.Command = "crabbox"
	}
	if config.Runtime.OpenClawCommand == "" {
		config.Runtime.OpenClawCommand = "openclaw"
	}
	if config.Runtime.AgentUser == "" {
		config.Runtime.AgentUser = "observatory"
	}
	if config.Runtime.TimeoutSeconds == 0 {
		config.Runtime.TimeoutSeconds = 600
	}
	if config.Runtime.Model.Provider == "" {
		config.Runtime.Model.Provider = "observatory"
	}
	if config.Runtime.Model.API == "" {
		config.Runtime.Model.API = "openai-completions"
	}
	if config.Runtime.Model.ContextWindow == 0 {
		config.Runtime.Model.ContextWindow = 65536
	}
	if config.Runtime.Model.MaxTokens == 0 {
		config.Runtime.Model.MaxTokens = 4096
	}
	if config.Runtime.MockEgress.Enabled {
		if config.Runtime.MockEgress.MaxRequests == 0 {
			config.Runtime.MockEgress.MaxRequests = 16
		}
		if config.Runtime.MockEgress.MaxBytesPerRequest == 0 {
			config.Runtime.MockEgress.MaxBytesPerRequest = 64 << 10
		}
		if config.Runtime.MockEgress.MaxTotalBytes == 0 {
			config.Runtime.MockEgress.MaxTotalBytes = 256 << 10
		}
		// DeadlineSeconds stays optional; 0 derives a lane-length backstop at
		// runtime rather than a config-validated bound.
	}
	if config.Exercise.Prompt == "" {
		config.Exercise.Prompt = DefaultExercisePrompt
	}
	if config.Exercise.TurnLimit == 0 {
		config.Exercise.TurnLimit = 1
	}
	if config.Limits.MaxFiles == 0 {
		config.Limits.MaxFiles = 5000
	}
	if config.Limits.MaxFileBytes == 0 {
		config.Limits.MaxFileBytes = 10 << 20
	}
	if config.Limits.MaxTotalBytes == 0 {
		config.Limits.MaxTotalBytes = 100 << 20
	}
	if config.Limits.MaxBundleBytes == 0 {
		config.Limits.MaxBundleBytes = 64 << 20
	}
	if config.Limits.MaxLaneBytes == 0 {
		config.Limits.MaxLaneBytes = 256 << 20
	}
	if config.Limits.MaxMemoryBytes == 0 {
		config.Limits.MaxMemoryBytes = 2 << 30
	}
	if config.Limits.CPUQuotaPct == 0 {
		config.Limits.CPUQuotaPct = 200
	}
	if config.Limits.MaxTasks == 0 {
		config.Limits.MaxTasks = 256
	}
	if config.ArtifactsDir == "" {
		if cacheDir, err := os.UserCacheDir(); err == nil {
			config.ArtifactsDir = filepath.Join(cacheDir, "clawhub-observatory", "runs")
		}
	}
}

func (config Config) Validate() error {
	if config.Version != ConfigVersion {
		return fmt.Errorf("unsupported behavior config version: %d", config.Version)
	}
	if config.TargetLineage != "" && !targetLineagePattern.MatchString(config.TargetLineage) {
		return errors.New("targetLineage must be a stable public identifier of at most 160 URL-safe characters")
	}
	if config.Executor.Kind != "crabbox" {
		return fmt.Errorf("unsupported executor kind: %s", config.Executor.Kind)
	}
	if strings.TrimSpace(config.Executor.Command) == "" {
		return errors.New("executor.command is required")
	}
	if strings.TrimSpace(config.Executor.CrabboxConfig) == "" {
		return errors.New("executor.crabboxConfig is required")
	}
	if strings.TrimSpace(config.ArtifactsDir) == "" {
		return errors.New("artifactsDir is required")
	}
	if err := validateTLSArtifactsPath(config.ArtifactsDir); err != nil {
		return err
	}
	if config.Executor.CrabboxBinary != "" {
		info, err := os.Lstat(config.Executor.CrabboxBinary)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
			return errors.New("executor.crabboxBinary must be an executable regular non-symlink file")
		}
	}
	if !guestAccountPattern.MatchString(config.Runtime.AgentUser) || config.Runtime.AgentUser == "root" {
		return errors.New("runtime.agentUser must name a dedicated non-root user")
	}
	if config.Runtime.TimeoutSeconds < 1 || config.Runtime.TimeoutSeconds > 3600 {
		return errors.New("runtime.timeoutSeconds must be between 1 and 3600")
	}
	model := config.Runtime.Model
	if strings.TrimSpace(model.ID) == "" {
		return errors.New("runtime.model.id is required")
	}
	parsed, err := url.Parse(model.BaseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("runtime.model.baseUrl must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil {
		return errors.New("runtime.model.baseUrl must not contain credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("runtime.model.baseUrl must not contain query or fragment data")
	}
	if model.API != "openai-completions" && model.API != "openai-responses" {
		return errors.New("runtime.model.api must be openai-completions or openai-responses")
	}
	if model.ContextWindow < 4096 || model.MaxTokens < 1 {
		return errors.New("runtime model contextWindow/maxTokens are too small")
	}
	if config.Exercise.TurnLimit != 1 {
		return errors.New("MVP supports exercise.turnLimit: 1 only")
	}
	if len(config.Exercise.Prompt) > 64<<10 || strings.ContainsRune(config.Exercise.Prompt, '\x00') {
		return errors.New("exercise.prompt must be at most 65536 bytes and contain no NUL")
	}
	if config.Redirect.Deep {
		return errors.New("redirect.deep is reserved for a future deep/repeat mode and is not enabled in the MVP")
	}
	if config.Limits.MaxFiles < 1 || config.Limits.MaxFileBytes < 1 || config.Limits.MaxTotalBytes < 1 {
		return errors.New("all limits must be positive")
	}
	if config.Limits.MaxBundleBytes < 1<<20 {
		return errors.New("limits.maxBundleBytes must be at least 1048576")
	}
	if config.Limits.MaxBundleBytes > 1<<30 {
		return errors.New("limits.maxBundleBytes must not exceed 1073741824")
	}
	if config.Limits.MaxTotalBytes > 1<<30 || config.Limits.MaxFileBytes > config.Limits.MaxTotalBytes {
		return errors.New("target byte limits are inconsistent or exceed 1073741824")
	}
	if config.Limits.MaxLaneBytes < config.Limits.MaxTotalBytes+(32<<20) || config.Limits.MaxLaneBytes > 2<<30 {
		return errors.New("limits.maxLaneBytes must exceed maxTotalBytes by at least 33554432 and not exceed 2147483648")
	}
	if config.Limits.MaxMemoryBytes < 256<<20 || config.Limits.MaxMemoryBytes > 16<<30 {
		return errors.New("limits.maxMemoryBytes must be between 268435456 and 17179869184")
	}
	if config.Limits.CPUQuotaPct < 25 || config.Limits.CPUQuotaPct > 800 {
		return errors.New("limits.cpuQuotaPercent must be between 25 and 800")
	}
	if config.Limits.MaxTasks < 32 || config.Limits.MaxTasks > 1024 {
		return errors.New("limits.maxTasks must be between 32 and 1024")
	}
	if err := config.Runtime.MockEgress.validateShape(); err != nil {
		return err
	}
	if config.Runtime.MockEgress.Enabled && config.Runtime.MockEgress.MaxTotalBytes*2+(1<<20) > config.Limits.MaxBundleBytes {
		return errors.New("limits.maxBundleBytes must leave room for the controlled mock egress receipts (at least mockEgress.maxTotalBytes*2 + 1 MiB)")
	}
	return nil
}

func (config Config) ValidateLive() error {
	if err := config.Validate(); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("live behavior execution and secure target staging require a Linux control host")
	}
	if !config.Live {
		return errors.New("live behavior execution is disabled; set live: true only after verifying the isolation controls")
	}
	if config.Isolation.Substrate != "proxmox-vm" {
		return errors.New("isolation.substrate must be proxmox-vm for live behavior execution")
	}
	if config.Isolation.NetworkMode != "deny-except-model" && config.Isolation.NetworkMode != "sinkhole" {
		return errors.New("isolation.networkMode must be deny-except-model or sinkhole")
	}
	if !config.Isolation.Verified || strings.TrimSpace(config.Isolation.Verification) == "" {
		return errors.New("live behavior execution requires isolation.verified: true and a non-empty verification receipt")
	}
	if !verificationReceiptPattern.MatchString(config.Isolation.Verification) {
		return errors.New("isolation.verification must be a short receipt label, not a path, URL, or free-form log")
	}
	if config.Isolation.VMTemplateID < 100 || !validPVEBridge(config.Isolation.NetworkBridge) {
		return errors.New("live behavior execution requires an explicit VM template ID and a PVE Linux bridge named vmbr0 through vmbr9999")
	}
	if !config.Isolation.FreshVM || !config.Isolation.DedicatedNetwork || !config.Isolation.DefaultDenyEgress ||
		!config.Isolation.NoHostMounts || !config.Isolation.NoRuntimeSockets || !config.Isolation.SyntheticIdentityOnly {
		return errors.New("all live isolation attestations must be true")
	}
	configInfo, err := os.Lstat(config.Executor.CrabboxConfig)
	if err != nil {
		return fmt.Errorf("inspect executor.crabboxConfig: %w", err)
	}
	if !configInfo.Mode().IsRegular() || configInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("executor.crabboxConfig must be a regular non-symlink file")
	}
	if configInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("executor.crabboxConfig must not be readable or writable by group/other")
	}
	if len(config.Executor.Args) != 0 {
		return errors.New("executor.args must be empty in live behavior mode; Observatory pins all Crabbox safety flags")
	}
	apiURL, err := validateCrabboxProxmoxConfig(config.Executor.CrabboxConfig, config.Isolation, config.Runtime.AgentUser)
	if err != nil {
		return err
	}
	if strings.TrimSpace(config.Executor.TLSCAFile) == "" {
		return errors.New("live behavior execution requires executor.tlsCAFile for verified Proxmox TLS")
	}
	if _, _, err := readAndValidateTLSCAFile(config.Executor.TLSCAFile, apiURL.Hostname()); err != nil {
		return err
	}
	if len(config.Runtime.ControlPlaneAddresses) != 1 {
		return errors.New("runtime.controlPlaneAddresses must contain exactly the model endpoint as seen from the guest")
	}
	for _, address := range config.Runtime.ControlPlaneAddresses {
		host, port, err := net.SplitHostPort(address)
		if err != nil || strings.TrimSpace(host) == "" {
			return fmt.Errorf("invalid runtime.controlPlaneAddresses entry: %s", address)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return fmt.Errorf("invalid runtime.controlPlaneAddresses port: %s", address)
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("runtime.controlPlaneAddresses must use literal IPv4 addresses in the MVP: %s", address)
		}
		if !ip.IsGlobalUnicast() || ip.IsLoopback() {
			return fmt.Errorf("runtime.controlPlaneAddresses must use non-loopback unicast addresses: %s", address)
		}
	}
	modelURL, _ := url.Parse(config.Runtime.Model.BaseURL)
	modelHost := net.ParseIP(strings.Trim(modelURL.Hostname(), "[]"))
	if modelHost == nil || modelHost.To4() == nil {
		return errors.New("runtime.model.baseUrl must use a literal IPv4 address in live mode")
	}
	if !modelHost.IsGlobalUnicast() || modelHost.IsLoopback() {
		return errors.New("runtime.model.baseUrl must use a non-loopback unicast address in live mode")
	}
	modelPort := modelURL.Port()
	if modelPort == "" && modelURL.Scheme == "http" {
		modelPort = "80"
	} else if modelPort == "" && modelURL.Scheme == "https" {
		modelPort = "443"
	}
	matchedModelEndpoint := false
	for _, address := range config.Runtime.ControlPlaneAddresses {
		host, port, _ := net.SplitHostPort(address)
		if port == modelPort && modelHost.Equal(net.ParseIP(strings.Trim(host, "[]"))) {
			matchedModelEndpoint = true
		}
	}
	if !matchedModelEndpoint {
		return errors.New("runtime.model.baseUrl host and effective port must appear in runtime.controlPlaneAddresses")
	}
	if err := config.Runtime.MockEgress.validateLive(config.Runtime.ControlPlaneAddresses); err != nil {
		return err
	}
	return nil
}

func validPVEBridge(name string) bool {
	if !isolatedBridgePattern.MatchString(name) {
		return false
	}
	number, err := strconv.Atoi(strings.TrimPrefix(name, "vmbr"))
	return err == nil && number <= 9999
}

func validateTLSArtifactsPath(path string) error {
	if strings.ContainsRune(path, rune(os.PathListSeparator)) {
		return fmt.Errorf("artifactsDir must not contain the path-list separator %q because it would split the exclusive TLS CA directory", os.PathListSeparator)
	}
	return nil
}

func validateCrabboxProxmoxConfig(path string, isolation IsolationConfig, agentUser string) (*url.URL, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read executor.crabboxConfig: %w", err)
	}
	if len(data) > 1<<20 {
		return nil, errors.New("executor.crabboxConfig exceeds 1 MiB")
	}
	var config struct {
		Provider string `yaml:"provider"`
		Target   string `yaml:"target"`
		Proxmox  struct {
			APIURL      string `yaml:"apiUrl"`
			TokenID     string `yaml:"tokenId"`
			TokenSecret string `yaml:"tokenSecret"`
			Node        string `yaml:"node"`
			TemplateID  int    `yaml:"templateId"`
			Storage     string `yaml:"storage"`
			Pool        string `yaml:"pool"`
			Bridge      string `yaml:"bridge"`
			User        string `yaml:"user"`
			WorkRoot    string `yaml:"workRoot"`
			FullClone   *bool  `yaml:"fullClone"`
			InsecureTLS *bool  `yaml:"insecureTLS"`
		} `yaml:"proxmox"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse executor.crabboxConfig: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("executor.crabboxConfig must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("parse trailing executor.crabboxConfig document: %w", err)
	}
	if config.Provider != "proxmox" || config.Target != "linux" {
		return nil, errors.New("executor.crabboxConfig must pin provider: proxmox and target: linux")
	}
	apiURL, err := url.Parse(config.Proxmox.APIURL)
	if err != nil || apiURL.Scheme != "https" || apiURL.Host == "" || apiURL.User != nil || apiURL.RawQuery != "" || apiURL.Fragment != "" {
		return nil, errors.New("executor.crabboxConfig proxmox.apiUrl must be an HTTPS URL without credentials, query, or fragment")
	}
	if config.Proxmox.InsecureTLS == nil || *config.Proxmox.InsecureTLS {
		return nil, errors.New("executor.crabboxConfig must explicitly set proxmox.insecureTLS: false")
	}
	if config.Proxmox.TemplateID != isolation.VMTemplateID || config.Proxmox.Bridge != isolation.NetworkBridge {
		return nil, errors.New("executor.crabboxConfig templateId/bridge must match the isolation receipt")
	}
	if config.Proxmox.FullClone == nil || !*config.Proxmox.FullClone {
		return nil, errors.New("executor.crabboxConfig must explicitly set proxmox.fullClone: true")
	}
	if strings.TrimSpace(config.Proxmox.Node) == "" {
		return nil, errors.New("executor.crabboxConfig must pin a Proxmox node")
	}
	if !guestAccountPattern.MatchString(config.Proxmox.User) || config.Proxmox.User == "root" {
		return nil, errors.New("executor.crabboxConfig must use a non-root Proxmox guest user")
	}
	if config.Proxmox.User == agentUser {
		return nil, errors.New("executor.crabboxConfig proxmox.user must differ from runtime.agentUser")
	}
	cleanWorkRoot := filepath.Clean(config.Proxmox.WorkRoot)
	if !filepath.IsAbs(cleanWorkRoot) || !strings.HasPrefix(cleanWorkRoot, "/work/") {
		return nil, errors.New("executor.crabboxConfig proxmox.workRoot must be an absolute path below /work")
	}
	return apiURL, nil
}

func readAndValidateTLSCAFile(path string, apiHostname string) ([]byte, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, "", fmt.Errorf("inspect executor.tlsCAFile: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("executor.tlsCAFile must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, "", errors.New("executor.tlsCAFile must not be writable by group/other")
	}
	if info.Size() < 1 || info.Size() > maxTLSCAFileBytes {
		return nil, "", fmt.Errorf("executor.tlsCAFile must be between 1 and %d bytes", maxTLSCAFileBytes)
	}
	if err := validateTLSHostname(apiHostname); err != nil {
		return nil, "", fmt.Errorf("executor.crabboxConfig proxmox.apiUrl: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open executor.tlsCAFile: %w", err)
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil {
		file.Close()
		return nil, "", fmt.Errorf("inspect opened executor.tlsCAFile: %w", statErr)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		file.Close()
		return nil, "", errors.New("executor.tlsCAFile changed while it was being opened")
	}
	if openedInfo.Mode().Perm()&0o022 != 0 {
		file.Close()
		return nil, "", errors.New("executor.tlsCAFile must not be writable by group/other")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxTLSCAFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, "", fmt.Errorf("read executor.tlsCAFile: %w", readErr)
	}
	if closeErr != nil {
		return nil, "", fmt.Errorf("close executor.tlsCAFile: %w", closeErr)
	}
	if len(data) < 1 || len(data) > maxTLSCAFileBytes {
		return nil, "", fmt.Errorf("executor.tlsCAFile must be between 1 and %d bytes", maxTLSCAFileBytes)
	}
	if err := validateTLSCAPEM(data); err != nil {
		return nil, "", fmt.Errorf("validate executor.tlsCAFile: %w", err)
	}
	digest := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateTLSCAPEM(data []byte) error {
	rest := bytes.TrimSpace(data)
	count := 0
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return errors.New("file must contain only PEM CERTIFICATE blocks")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("file must contain only unencrypted PEM CERTIFICATE blocks")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CA certificate: %w", err)
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA {
			return errors.New("every certificate in executor.tlsCAFile must be a CA certificate")
		}
		if certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("CA certificate key usage must permit certificate signing")
		}
		count++
		rest = bytes.TrimSpace(remaining)
	}
	if count == 0 {
		return errors.New("file contains no CA certificates")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return errors.New("CA certificate bundle cannot be loaded")
	}
	return nil
}

func validateTLSHostname(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("hostname is required for TLS verification")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return errors.New("hostname is not certificate-verifiable")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("hostname is not certificate-verifiable")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return errors.New("hostname is not certificate-verifiable")
			}
		}
	}
	return nil
}

func proxmoxAPIHostname(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 1<<20 {
		return ""
	}
	var config struct {
		Proxmox struct {
			APIURL string `yaml:"apiUrl"`
		} `yaml:"proxmox"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return ""
	}
	parsed, err := url.Parse(config.Proxmox.APIURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func expandUserPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func resolveConfigPath(base string, value string) string {
	value = expandUserPath(value)
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Join(base, value)
}
