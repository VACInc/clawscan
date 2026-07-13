package observatory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
)

const (
	modelRelayPolicyVersion       = "observatory.model-relay.v1"
	modelRelayReceiptMaxBytes     = 64 << 10
	defaultModelRelayAddress      = "127.0.0.8:9010"
	defaultRelayMaxRequests       = 8
	defaultRelayMaxRequestBytes   = 8 << 20
	defaultRelayMaxResponseBytes  = 16 << 20
	defaultRelayMaxTotalBytes     = 32 << 20
	defaultRelayMaxConcurrent     = 2
	defaultRelayRequestTimeoutSec = 120
)

// ModelRelayConfig defines the bounded control-plane proxy between an untrusted
// lane and the real model endpoint. The lane can reach only Address. The relay is
// the only guest process allowed to reach the upstream control-plane address.
type ModelRelayConfig struct {
	Address               string `yaml:"address"`
	MaxRequests           int    `yaml:"maxRequests"`
	MaxRequestBytes       int64  `yaml:"maxRequestBytes"`
	MaxResponseBytes      int64  `yaml:"maxResponseBytes"`
	MaxTotalBytes         int64  `yaml:"maxTotalBytes"`
	MaxConcurrentRequests int    `yaml:"maxConcurrentRequests"`
	RequestTimeoutSeconds int    `yaml:"requestTimeoutSeconds"`
}

func (config *ModelRelayConfig) applyDefaults() {
	if config.Address == "" {
		config.Address = defaultModelRelayAddress
	}
	if config.MaxRequests == 0 {
		config.MaxRequests = defaultRelayMaxRequests
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultRelayMaxRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultRelayMaxResponseBytes
	}
	if config.MaxTotalBytes == 0 {
		config.MaxTotalBytes = defaultRelayMaxTotalBytes
	}
	if config.MaxConcurrentRequests == 0 {
		config.MaxConcurrentRequests = defaultRelayMaxConcurrent
	}
	// Zero requestTimeoutSeconds is an intentional auto value derived from the
	// shorter of the lane timeout and the relay's 120 second ceiling.
}

func effectiveModelRelayConfig(config ModelRelayConfig) ModelRelayConfig {
	config.applyDefaults()
	return config
}

func (config ModelRelayConfig) validateShape(timeoutSeconds int) error {
	config = effectiveModelRelayConfig(config)
	host, port, err := splitLoopbackAddress(config.Address, "modelRelay.address")
	if err != nil {
		return err
	}
	if !net.ParseIP(host).IsLoopback() {
		return errors.New("modelRelay.address must be a guest-local IPv4 loopback address")
	}
	if port < 1024 {
		return errors.New("modelRelay.address port must be between 1024 and 65535")
	}
	if config.MaxRequests < 1 || config.MaxRequests > 64 {
		return errors.New("modelRelay.maxRequests must be between 1 and 64")
	}
	if config.MaxRequestBytes < 1 || config.MaxRequestBytes > 16<<20 {
		return errors.New("modelRelay.maxRequestBytes must be between 1 and 16777216")
	}
	if config.MaxResponseBytes < 1 || config.MaxResponseBytes > 32<<20 {
		return errors.New("modelRelay.maxResponseBytes must be between 1 and 33554432")
	}
	if config.MaxTotalBytes < config.MaxRequestBytes || config.MaxTotalBytes < config.MaxResponseBytes || config.MaxTotalBytes > 64<<20 {
		return errors.New("modelRelay.maxTotalBytes must cover each per-request cap and not exceed 67108864")
	}
	if config.MaxConcurrentRequests < 1 || config.MaxConcurrentRequests > 8 {
		return errors.New("modelRelay.maxConcurrentRequests must be between 1 and 8")
	}
	if config.RequestTimeoutSeconds < 0 || config.RequestTimeoutSeconds > timeoutSeconds {
		return errors.New("modelRelay.requestTimeoutSeconds must be 0 (auto) or no greater than runtime.timeoutSeconds")
	}
	return nil
}

func splitLoopbackAddress(address string, field string) (string, int, error) {
	host, rawPort, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", 0, fmt.Errorf("invalid %s: %s", field, address)
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	port, portErr := strconv.Atoi(rawPort)
	if ip == nil || ip.To4() == nil || portErr != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%s must use a literal IPv4 address and valid port: %s", field, address)
	}
	return ip.String(), port, nil
}

type modelRelayPolicy struct {
	Version               string `json:"version"`
	ListenAddress         string `json:"listenAddress"`
	UpstreamURL           string `json:"upstreamUrl"`
	AllowedMethod         string `json:"allowedMethod"`
	AllowedPath           string `json:"allowedPath"`
	ExpectedModel         string `json:"expectedModel"`
	MaxRequests           int    `json:"maxRequests"`
	MaxRequestBytes       int64  `json:"maxRequestBytes"`
	MaxResponseBytes      int64  `json:"maxResponseBytes"`
	MaxTotalBytes         int64  `json:"maxTotalBytes"`
	MaxConcurrentRequests int    `json:"maxConcurrentRequests"`
	RequestTimeoutSeconds int    `json:"requestTimeoutSeconds"`
	DeadlineSeconds       int    `json:"deadlineSeconds"`
}

func buildModelRelayPolicy(config ModelRelayConfig, model ModelConfig, laneTimeoutSeconds int) (modelRelayPolicy, error) {
	config = effectiveModelRelayConfig(config)
	if err := config.validateShape(laneTimeoutSeconds); err != nil {
		return modelRelayPolicy{}, err
	}
	upstream, err := url.Parse(model.BaseURL)
	if err != nil {
		return modelRelayPolicy{}, errors.New("runtime.model.baseUrl is invalid")
	}
	allowedPath, err := modelRelayAllowedPath(upstream, model.API)
	if err != nil {
		return modelRelayPolicy{}, err
	}
	upstream.Path = allowedPath
	upstream.RawPath = ""
	upstream.RawQuery = ""
	upstream.Fragment = ""
	requestTimeout := config.RequestTimeoutSeconds
	if requestTimeout == 0 {
		requestTimeout = laneTimeoutSeconds
		if requestTimeout > defaultRelayRequestTimeoutSec {
			requestTimeout = defaultRelayRequestTimeoutSec
		}
	}
	return modelRelayPolicy{
		Version:               modelRelayPolicyVersion,
		ListenAddress:         config.Address,
		UpstreamURL:           upstream.String(),
		AllowedMethod:         "POST",
		AllowedPath:           allowedPath,
		ExpectedModel:         model.ID,
		MaxRequests:           config.MaxRequests,
		MaxRequestBytes:       config.MaxRequestBytes,
		MaxResponseBytes:      config.MaxResponseBytes,
		MaxTotalBytes:         config.MaxTotalBytes,
		MaxConcurrentRequests: config.MaxConcurrentRequests,
		RequestTimeoutSeconds: requestTimeout,
		DeadlineSeconds:       laneTimeoutSeconds + 30,
	}, nil
}

func modelRelayAllowedPath(base *url.URL, api string) (string, error) {
	if base == nil || base.RawPath != "" || strings.Contains(base.EscapedPath(), "%") {
		return "", errors.New("runtime.model.baseUrl path must be unescaped")
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(base.Path, "/"))
	original := strings.TrimSuffix(base.Path, "/")
	if original == "" {
		original = "/"
	}
	if cleaned != original {
		return "", errors.New("runtime.model.baseUrl path must be canonical")
	}
	if cleaned == "/." {
		cleaned = ""
	}
	suffix := ""
	switch api {
	case "openai-completions":
		suffix = "/chat/completions"
	case "openai-responses":
		suffix = "/responses"
	default:
		return "", errors.New("runtime.model.api has no relay route")
	}
	if cleaned == "/" {
		cleaned = ""
	}
	return strings.TrimSuffix(cleaned, "/") + suffix, nil
}

func modelRelayBaseURL(config ModelRelayConfig, model ModelConfig) (string, error) {
	config = effectiveModelRelayConfig(config)
	host, port, err := splitLoopbackAddress(config.Address, "modelRelay.address")
	if err != nil {
		return "", err
	}
	base, err := url.Parse(model.BaseURL)
	if err != nil {
		return "", err
	}
	basePath := strings.TrimSuffix(path.Clean("/"+strings.TrimPrefix(base.Path, "/")), "/")
	return (&url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: basePath}).String(), nil
}

func modelRelayPolicySHA256(policy modelRelayPolicy) string {
	data, _ := json.Marshal(policy)
	return digestBytes(data)
}

func modelRelayRuntime(config ModelRelayConfig, model ModelConfig, timeoutSeconds int) (map[string]any, error) {
	policy, err := buildModelRelayPolicy(config, model, timeoutSeconds)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	var runtime map[string]any
	if err := json.Unmarshal(data, &runtime); err != nil {
		return nil, err
	}
	runtime["policySha256"] = modelRelayPolicySHA256(policy)
	runtime["receiptMaxBytes"] = modelRelayReceiptMaxBytes
	return runtime, nil
}

func modelRelayAddress(config ModelRelayConfig) string {
	config = effectiveModelRelayConfig(config)
	return config.Address
}

func modelRelayCgroupIPs(config ModelRelayConfig) []string {
	host, _, err := splitLoopbackAddress(effectiveModelRelayConfig(config).Address, "modelRelay.address")
	if err != nil {
		return nil
	}
	return []string{host}
}

// ModelRelayReceipt is the private, body-free accounting receipt produced by
// the hardened relay unit. It binds each lane to the effective relay policy.
type ModelRelayReceipt struct {
	Lane               string `json:"lane"`
	PolicySHA256       string `json:"policySha256"`
	AcceptedRequests   int    `json:"acceptedRequests"`
	RejectedRequests   int    `json:"rejectedRequests"`
	RequestBytes       int64  `json:"requestBytes"`
	ResponseBytes      int64  `json:"responseBytes"`
	PeakConcurrency    int    `json:"peakConcurrency"`
	Truncated          bool   `json:"truncated"`
	DeadlineHit        bool   `json:"deadlineHit"`
	UpstreamErrorCount int    `json:"upstreamErrorCount"`
}

func parseModelRelayReceipt(data []byte) (*ModelRelayReceipt, error) {
	if len(data) > modelRelayReceiptMaxBytes {
		return nil, errors.New("model relay receipt exceeds its bound")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("parse model relay receipt: %w", err)
	}
	required := []string{"lane", "policySha256", "acceptedRequests", "rejectedRequests", "requestBytes", "responseBytes", "peakConcurrency", "truncated", "deadlineHit", "upstreamErrorCount"}
	if len(fields) != len(required) {
		return nil, errors.New("model relay receipt field set is incomplete")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return nil, fmt.Errorf("model relay receipt is missing %s", name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt ModelRelayReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return nil, fmt.Errorf("parse model relay receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("model relay receipt must contain exactly one JSON document")
	}
	if receipt.Lane != "baseline" && receipt.Lane != "exercise" {
		return nil, errors.New("model relay receipt has an invalid lane")
	}
	if !isSHA256Digest(receipt.PolicySHA256) {
		return nil, errors.New("model relay receipt has an invalid policy digest")
	}
	if receipt.AcceptedRequests < 0 || receipt.RejectedRequests < 0 || receipt.RequestBytes < 0 || receipt.ResponseBytes < 0 || receipt.PeakConcurrency < 0 || receipt.UpstreamErrorCount < 0 {
		return nil, errors.New("model relay receipt has negative counters")
	}
	return &receipt, nil
}

func verifyModelRelayReceipts(bundle CaptureBundle, config RuntimeConfig) error {
	if bundle.ModelRelayBaseline == nil || bundle.ModelRelayExercise == nil {
		return errors.New("capture bundle is missing a per-lane model relay receipt")
	}
	policy, err := buildModelRelayPolicy(config.ModelRelay, config.Model, config.TimeoutSeconds)
	if err != nil {
		return err
	}
	wantDigest := modelRelayPolicySHA256(policy)
	limits := effectiveModelRelayConfig(config.ModelRelay)
	for lane, receipt := range map[string]*ModelRelayReceipt{"baseline": bundle.ModelRelayBaseline, "exercise": bundle.ModelRelayExercise} {
		if receipt.Lane != lane {
			return fmt.Errorf("model relay receipt lane mismatch: expected %q, receipt records %q", lane, receipt.Lane)
		}
		if receipt.PolicySHA256 != wantDigest {
			return fmt.Errorf("model relay %s receipt policy digest does not match the effective policy", lane)
		}
		if receipt.AcceptedRequests+receipt.RejectedRequests > limits.MaxRequests || receipt.RequestBytes > limits.MaxTotalBytes || receipt.ResponseBytes > limits.MaxTotalBytes || receipt.RequestBytes+receipt.ResponseBytes > limits.MaxTotalBytes {
			return fmt.Errorf("model relay %s receipt exceeds configured traffic limits", lane)
		}
		requestCount := receipt.AcceptedRequests + receipt.RejectedRequests
		if receipt.RequestBytes > int64(requestCount)*limits.MaxRequestBytes || receipt.ResponseBytes > int64(receipt.AcceptedRequests)*limits.MaxResponseBytes {
			return fmt.Errorf("model relay %s receipt exceeds configured per-request limits", lane)
		}
		if receipt.PeakConcurrency > limits.MaxConcurrentRequests || receipt.PeakConcurrency > receipt.AcceptedRequests+receipt.RejectedRequests {
			return fmt.Errorf("model relay %s receipt exceeds configured concurrency", lane)
		}
	}
	return nil
}

type ModelRelayEvidence struct {
	Route                    string `json:"route"`
	PolicySHA256             string `json:"policySha256"`
	BaselineReceiptSHA256    string `json:"baselineReceiptSha256"`
	ExerciseReceiptSHA256    string `json:"exerciseReceiptSha256"`
	BaselineRequests         int    `json:"baselineRequests"`
	ExerciseRequests         int    `json:"exerciseRequests"`
	BaselineRejectedRequests int    `json:"baselineRejectedRequests"`
	ExerciseRejectedRequests int    `json:"exerciseRejectedRequests"`
	BaselineRequestBytes     int64  `json:"baselineRequestBytes"`
	ExerciseRequestBytes     int64  `json:"exerciseRequestBytes"`
	BaselineResponseBytes    int64  `json:"baselineResponseBytes"`
	ExerciseResponseBytes    int64  `json:"exerciseResponseBytes"`
	BaselineUpstreamErrors   int    `json:"baselineUpstreamErrors"`
	ExerciseUpstreamErrors   int    `json:"exerciseUpstreamErrors"`
	Truncated                bool   `json:"truncated"`
	DeadlineHit              bool   `json:"deadlineHit"`
}

func buildModelRelayEvidence(bundle CaptureBundle) *ModelRelayEvidence {
	if bundle.ModelRelayBaseline == nil || bundle.ModelRelayExercise == nil {
		return nil
	}
	baseline, exercise := bundle.ModelRelayBaseline, bundle.ModelRelayExercise
	return &ModelRelayEvidence{
		Route:                    "bounded-control-relay",
		PolicySHA256:             exercise.PolicySHA256,
		BaselineReceiptSHA256:    modelRelayReceiptSHA256(baseline),
		ExerciseReceiptSHA256:    modelRelayReceiptSHA256(exercise),
		BaselineRequests:         baseline.AcceptedRequests,
		ExerciseRequests:         exercise.AcceptedRequests,
		BaselineRejectedRequests: baseline.RejectedRequests,
		ExerciseRejectedRequests: exercise.RejectedRequests,
		BaselineRequestBytes:     baseline.RequestBytes,
		ExerciseRequestBytes:     exercise.RequestBytes,
		BaselineResponseBytes:    baseline.ResponseBytes,
		ExerciseResponseBytes:    exercise.ResponseBytes,
		BaselineUpstreamErrors:   baseline.UpstreamErrorCount,
		ExerciseUpstreamErrors:   exercise.UpstreamErrorCount,
		Truncated:                baseline.Truncated || exercise.Truncated,
		DeadlineHit:              baseline.DeadlineHit || exercise.DeadlineHit,
	}
}

func validateModelRelayEvidence(evidence *ModelRelayEvidence) error {
	if evidence == nil {
		return errors.New("evidence model relay receipt is required")
	}
	if evidence.Route != "bounded-control-relay" || !isSHA256Digest(evidence.PolicySHA256) || !isSHA256Digest(evidence.BaselineReceiptSHA256) || !isSHA256Digest(evidence.ExerciseReceiptSHA256) {
		return errors.New("evidence model relay policy receipt is invalid")
	}
	if evidence.BaselineReceiptSHA256 == evidence.ExerciseReceiptSHA256 {
		return errors.New("evidence model relay lane receipts are not distinct")
	}
	if evidence.BaselineRequests < 0 || evidence.ExerciseRequests < 0 || evidence.BaselineRejectedRequests < 0 || evidence.ExerciseRejectedRequests < 0 || evidence.BaselineRequestBytes < 0 || evidence.ExerciseRequestBytes < 0 || evidence.BaselineResponseBytes < 0 || evidence.ExerciseResponseBytes < 0 || evidence.BaselineUpstreamErrors < 0 || evidence.ExerciseUpstreamErrors < 0 {
		return errors.New("evidence model relay counters are invalid")
	}
	return nil
}

func modelRelayReceiptSHA256(receipt *ModelRelayReceipt) string {
	data, _ := json.Marshal(receipt)
	return digestBytes(data)
}

func modelRelayCaptureComplete(bundle CaptureBundle) bool {
	for _, receipt := range []*ModelRelayReceipt{bundle.ModelRelayBaseline, bundle.ModelRelayExercise} {
		if receipt == nil || receipt.Truncated || receipt.DeadlineHit || receipt.UpstreamErrorCount != 0 {
			return false
		}
	}
	return true
}
