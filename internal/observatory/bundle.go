package observatory

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type CaptureBundle struct {
	Metadata       CaptureMetadata
	BaselineTraces []string
	ExerciseTraces []string
	BaselineOutput []byte
	ExerciseOutput []byte
}

func ReadCaptureBundle(bundlePath string, maxBytes int64) (CaptureBundle, error) {
	info, err := os.Stat(bundlePath)
	if err != nil {
		return CaptureBundle{}, fmt.Errorf("inspect capture bundle: %w", err)
	}
	if !info.Mode().IsRegular() {
		return CaptureBundle{}, errors.New("capture bundle must be a regular file")
	}
	if info.Size() > maxBytes {
		return CaptureBundle{}, fmt.Errorf("capture bundle exceeds maxBundleBytes (%d)", maxBytes)
	}
	file, err := os.Open(bundlePath)
	if err != nil {
		return CaptureBundle{}, err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return CaptureBundle{}, fmt.Errorf("open capture gzip: %w", err)
	}
	defer gzipReader.Close()

	entries := map[string][]byte{}
	decompressed := &io.LimitedReader{R: gzipReader, N: maxBytes + 1}
	reader := tar.NewReader(decompressed)
	var total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if decompressed.N <= 0 {
				return CaptureBundle{}, fmt.Errorf("capture bundle exceeds maxBundleBytes (%d)", maxBytes)
			}
			return CaptureBundle{}, fmt.Errorf("read capture tar: %w", err)
		}
		name := strings.TrimPrefix(path.Clean(strings.TrimPrefix(header.Name, "./")), "./")
		if name == "." || strings.HasPrefix(name, "../") || path.IsAbs(name) {
			return CaptureBundle{}, fmt.Errorf("capture bundle contains unsafe path: %s", header.Name)
		}
		if header.Size < 0 || header.Size > maxBytes || total+header.Size > maxBytes {
			return CaptureBundle{}, fmt.Errorf("capture bundle exceeds maxBundleBytes (%d)", maxBytes)
		}
		total += header.Size
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			if header.Size > 0 {
				if _, err := io.CopyN(io.Discard, reader, header.Size); err != nil {
					return CaptureBundle{}, fmt.Errorf("read capture entry %s: %w", name, err)
				}
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil {
			return CaptureBundle{}, err
		}
		if int64(len(data)) != header.Size {
			return CaptureBundle{}, fmt.Errorf("capture entry size mismatch: %s", name)
		}
		entries[name] = data
	}
	if _, err := io.Copy(io.Discard, decompressed); err != nil {
		return CaptureBundle{}, fmt.Errorf("finish capture gzip: %w", err)
	}
	if decompressed.N <= 0 {
		return CaptureBundle{}, fmt.Errorf("capture bundle exceeds maxBundleBytes (%d)", maxBytes)
	}

	metadata, err := captureMetadataFromEntries(entries)
	if err != nil {
		return CaptureBundle{}, err
	}
	bundle := CaptureBundle{Metadata: metadata}
	for name, data := range entries {
		switch {
		case name == "baseline/trace" || strings.HasPrefix(name, "baseline/trace."):
			bundle.BaselineTraces = append(bundle.BaselineTraces, string(data))
		case name == "exercise/trace" || strings.HasPrefix(name, "exercise/trace."):
			bundle.ExerciseTraces = append(bundle.ExerciseTraces, string(data))
		case name == "baseline/agent.stdout":
			bundle.BaselineOutput = append([]byte(nil), data...)
		case name == "exercise/agent.stdout":
			bundle.ExerciseOutput = append([]byte(nil), data...)
		}
	}
	if !traceLaneHasCompleteSyscall(bundle.BaselineTraces) {
		return CaptureBundle{}, errors.New("capture bundle baseline lane contains no complete syscall trace record")
	}
	if !traceLaneHasCompleteSyscall(bundle.ExerciseTraces) {
		return CaptureBundle{}, errors.New("capture bundle exercise lane contains no complete syscall trace record")
	}
	return bundle, nil
}

func captureMetadataFromEntries(entries map[string][]byte) (CaptureMetadata, error) {
	read := func(name string) string {
		return strings.TrimSpace(string(entries["meta/"+name]))
	}
	metadata := CaptureMetadata{
		RunID:             read("run-id"),
		TargetSHA256:      read("target-sha256"),
		CaptureConfigSHA:  read("capture-config-sha256"),
		BaselineWorkspace: read("baseline-workspace"),
		ExerciseWorkspace: read("exercise-workspace"),
		BaselineState:     read("baseline-state"),
		ExerciseState:     read("exercise-state"),
		BaselineHome:      read("baseline-home"),
		ExerciseHome:      read("exercise-home"),
		TargetKind:        read("target-kind"),
		TargetRoot:        read("target-root"),
		OpenClawVersion:   safeVersion(read("openclaw-version")),
		StraceVersion:     safeVersion(read("strace-version")),
		FirewallSHA256:    read("firewall-sha256"),
	}
	var markerMap map[string]string
	if err := json.Unmarshal(entries["meta/canaries.json"], &markerMap); err != nil {
		return CaptureMetadata{}, errors.New("capture bundle has invalid meta/canaries.json")
	}
	canaries, canaryErr := canaryDefinitions(markerMap)
	if canaryErr != nil {
		return CaptureMetadata{}, canaryErr
	}
	metadata.Canaries = canaries
	if metadata.RunID == "" {
		return CaptureMetadata{}, errors.New("capture bundle is missing meta/run-id")
	}
	if metadata.TargetSHA256 == "" {
		return CaptureMetadata{}, errors.New("capture bundle is missing meta/target-sha256")
	}
	if matched, _ := regexp.MatchString(`^sha256:[a-f0-9]{64}$`, metadata.CaptureConfigSHA); !matched {
		return CaptureMetadata{}, errors.New("capture bundle has invalid meta/capture-config-sha256")
	}
	if metadata.TargetKind != "skill" && metadata.TargetKind != "plugin" {
		return CaptureMetadata{}, errors.New("capture bundle has invalid meta/target-kind")
	}
	if metadata.TargetRoot == "" {
		return CaptureMetadata{}, errors.New("capture bundle is missing meta/target-root")
	}
	if err := validateCaptureRoots(metadata); err != nil {
		return CaptureMetadata{}, err
	}
	if strings.TrimSpace(metadata.OpenClawVersion) == "" || strings.TrimSpace(metadata.StraceVersion) == "" {
		return CaptureMetadata{}, errors.New("capture bundle is missing OpenClaw or strace version receipts")
	}
	if matched, _ := regexp.MatchString(`^[a-f0-9]{64}$`, metadata.FirewallSHA256); !matched {
		return CaptureMetadata{}, errors.New("capture bundle has invalid meta/firewall-sha256")
	}
	var err error
	metadata.BaselineExitCode, err = parseExitCode(read("baseline-exit"), "baseline")
	if err != nil {
		return CaptureMetadata{}, err
	}
	metadata.ExerciseExitCode, err = parseExitCode(read("exercise-exit"), "exercise")
	if err != nil {
		return CaptureMetadata{}, err
	}
	startedAt := read("started-at")
	if startedAt == "" {
		return CaptureMetadata{}, errors.New("capture bundle is missing meta/started-at")
	}
	metadata.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return CaptureMetadata{}, fmt.Errorf("parse capture started-at: %w", err)
	}
	completedAt := read("completed-at")
	if completedAt == "" {
		return CaptureMetadata{}, errors.New("capture bundle is missing meta/completed-at")
	}
	metadata.CompletedAt, err = time.Parse(time.RFC3339Nano, completedAt)
	if err != nil {
		return CaptureMetadata{}, fmt.Errorf("parse capture completed-at: %w", err)
	}
	if metadata.CompletedAt.Before(metadata.StartedAt) {
		return CaptureMetadata{}, errors.New("capture bundle completed-at precedes started-at")
	}
	return metadata, nil
}

func validateCaptureRoots(metadata CaptureMetadata) error {
	roots := []struct {
		name  string
		value string
	}{
		{"baseline-workspace", metadata.BaselineWorkspace},
		{"baseline-state", metadata.BaselineState},
		{"baseline-home", metadata.BaselineHome},
		{"exercise-workspace", metadata.ExerciseWorkspace},
		{"exercise-state", metadata.ExerciseState},
		{"exercise-home", metadata.ExerciseHome},
	}
	seen := map[string]bool{}
	for _, root := range roots {
		if root.value == "" {
			return fmt.Errorf("capture bundle is missing meta/%s", root.name)
		}
		if !path.IsAbs(root.value) || path.Clean(root.value) != root.value || strings.ContainsAny(root.value, "\x00\r\n") {
			return fmt.Errorf("capture bundle has invalid meta/%s", root.name)
		}
		if seen[root.value] {
			return errors.New("capture bundle lane roots must be distinct")
		}
		seen[root.value] = true
	}
	baselineLane := commonLaneRoot(metadata.BaselineWorkspace, metadata.BaselineState, metadata.BaselineHome)
	exerciseLane := commonLaneRoot(metadata.ExerciseWorkspace, metadata.ExerciseState, metadata.ExerciseHome)
	if baselineLane == "" || exerciseLane == "" || baselineLane == exerciseLane {
		return errors.New("capture bundle lane roots must form distinct baseline and exercise lanes")
	}
	if !path.IsAbs(metadata.TargetRoot) || path.Clean(metadata.TargetRoot) != metadata.TargetRoot || strings.ContainsAny(metadata.TargetRoot, "\x00\r\n") ||
		!strings.HasPrefix(metadata.TargetRoot, exerciseLane+"/") {
		return errors.New("capture bundle target root must belong to the exercise lane")
	}
	if metadata.TargetKind == "skill" && !strings.HasPrefix(metadata.TargetRoot, metadata.ExerciseWorkspace+"/") {
		return errors.New("capture bundle skill target root must belong to the exercise workspace")
	}
	return nil
}

func parseExitCode(raw string, lane string) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 || value > 255 {
		return 0, fmt.Errorf("capture bundle has invalid %s exit code", lane)
	}
	return value, nil
}

func safeVersion(value string) string {
	if line, _, ok := strings.Cut(value, "\n"); ok {
		value = line
	}
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) > 160 {
		value = value[:160]
	}
	return value
}

func BuildEvidence(target TargetEvidence, config Config, bundle CaptureBundle) (Evidence, error) {
	_, tlsCASHA256, err := readAndValidateTLSCAFile(config.Executor.TLSCAFile, proxmoxAPIHostname(config.Executor.CrabboxConfig))
	if err != nil {
		return Evidence{}, err
	}
	expectedCaptureConfig, err := captureConfigSHA256WithTLSCA(config, CaptureProtocolRevision, tlsCASHA256)
	if err != nil {
		return Evidence{}, err
	}
	if bundle.Metadata.CaptureConfigSHA != expectedCaptureConfig {
		return Evidence{}, errors.New("TLS CA changed after capture configuration verification")
	}
	target.Lineage = config.TargetLineage
	analysis := AnalyzeTraces(AnalysisInput{
		BaselineTraces:        bundle.BaselineTraces,
		ExerciseTraces:        bundle.ExerciseTraces,
		Metadata:              bundle.Metadata,
		Canaries:              bundle.Metadata.Canaries,
		ControlPlaneAddresses: config.Runtime.ControlPlaneAddresses,
	})
	started := bundle.Metadata.StartedAt
	completed := bundle.Metadata.CompletedAt
	status := "completed"
	if bundle.Metadata.BaselineExitCode != 0 || bundle.Metadata.ExerciseExitCode != 0 || !analysis.Coverage.BaselinePaired {
		status = "incomplete"
	}
	return Evidence{
		SchemaVersion:       EvidenceSchemaVersion,
		CaptureConfigSHA256: bundle.Metadata.CaptureConfigSHA,
		Target:              target,
		Run: RunEvidence{
			ID:          bundle.Metadata.RunID,
			Status:      status,
			StartedAt:   started.UTC().Format(time.RFC3339Nano),
			CompletedAt: completed.UTC().Format(time.RFC3339Nano),
			DurationMs:  completed.Sub(started).Milliseconds(),
			Executor:    config.Executor.Kind,
			Isolation: IsolationEvidence{
				Substrate:                 config.Isolation.Substrate,
				NetworkMode:               config.Isolation.NetworkMode,
				ContainmentProfile:        "proxmox-vm+nftables+systemd-cgroup",
				GuestFirewallSHA256:       "sha256:" + bundle.Metadata.FirewallSHA256,
				GuestFirewallPolicySHA256: digestBytes([]byte(guestFirewallRules("policy", config.Runtime.ControlPlaneAddresses))),
				ProxmoxTLSCASHA256:        tlsCASHA256,
				Verification:              config.Isolation.Verification,
			},
			Runtime: RuntimeEvidence{
				OpenClawVersion: bundle.Metadata.OpenClawVersion,
				StraceVersion:   bundle.Metadata.StraceVersion,
				ModelProvider:   config.Runtime.Model.Provider,
				ModelID:         config.Runtime.Model.ID,
				ModelEndpoint:   modelEndpointClass(config.Runtime.Model.BaseURL),
			},
			LaneExitCode: LaneExitCodes{
				Baseline: bundle.Metadata.BaselineExitCode,
				Exercise: bundle.Metadata.ExerciseExitCode,
			},
		},
		Exercise: ExerciseEvidence{
			PromptSHA256:      digestBytes([]byte(config.Exercise.Prompt)),
			TurnLimit:         config.Exercise.TurnLimit,
			BaselineOutputSHA: digestBytes(bundle.BaselineOutput),
			ExerciseOutputSHA: digestBytes(bundle.ExerciseOutput),
		},
		Observations: analysis.Observations,
		Canaries:     analysis.Canaries,
		Coverage:     analysis.Coverage,
	}, nil
}

func canaryDefinitions(markers map[string]string) ([]CanaryDefinition, error) {
	definitions := []CanaryDefinition{
		{ID: "workspace-identity", Surface: "workspace file", Path: "$WORKSPACE/SOUL.md"},
		{ID: "workspace-memory", Surface: "workspace file", Path: "$WORKSPACE/memory/private.md"},
		{ID: "cloud-credentials", Surface: "home file", Path: "$HOME/.aws/credentials"},
		{ID: "openclaw-credentials", Surface: "state file", Path: "$STATE/credentials.json"},
	}
	if len(markers) != len(definitions) {
		return nil, errors.New("capture bundle private canary set is incomplete")
	}
	seen := map[string]bool{}
	for i := range definitions {
		marker := markers[definitions[i].ID]
		matched, _ := regexp.MatchString(`^OBS-CANARY-[a-f0-9]{48}$`, marker)
		if !matched || seen[marker] {
			return nil, errors.New("capture bundle contains an invalid private canary marker")
		}
		seen[marker] = true
		definitions[i].Marker = marker
	}
	return definitions, nil
}

func digestBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func modelEndpointClass(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "configured"
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if isOperationallyPrivateIP(ip) {
		return "private"
	}
	if ip != nil {
		return "public"
	}
	if host == "localhost" || !strings.Contains(host, ".") {
		return "private"
	}
	return "public"
}
