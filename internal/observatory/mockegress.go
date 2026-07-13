package observatory

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Controlled mock egress upgrades safe outbound-attempt evidence toward
// payload-aware evidence without permitting arbitrary real egress. When enabled,
// Observatory runs a bounded, guest-local loopback sink that the disposable
// agent lane may reach through an explicit per-lane cgroup allowlist entry that
// is distinct from the exact model control-plane allowlist. Everything else stays
// default-deny. The sink applies strict request/byte/time caps, returns a
// deterministic canned response, keeps raw captured bytes in the private bundle
// only, and publishes secret-safe counts, digests, and canary presence.

const (
	// The sink is deliberately loopback-only so captured bytes never leave the
	// disposable VM. The per-lane cgroup IPAddressAllow entry, not loopback
	// reachability, is the enforcement gate.
	mockEgressCannedResponseMaxBytes = 4096
	mockEgressReceiptRawCapBytes     = 1 << 20
	mockEgressMaxDataChunks          = 4096
	mockEgressMaxConcurrentSockets   = 64
)

var mockEgressCanaryIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// MockEgressConfig pins an Observatory-owned controlled sink. It is opt-in; when
// Enabled is false the scan behaves exactly as a pure outbound-attempt capture.
type MockEgressConfig struct {
	Enabled              bool   `yaml:"enabled"`
	Address              string `yaml:"address"`
	MaxRequests          int    `yaml:"maxRequests"`
	MaxBytesPerRequest   int64  `yaml:"maxBytesPerRequest"`
	MaxTotalBytes        int64  `yaml:"maxTotalBytes"`
	DeadlineSeconds      int    `yaml:"deadlineSeconds"`
	CannedResponseBase64 string `yaml:"cannedResponseBase64"`
}

// MockEgressEvidence is the secret-safe public projection of the controlled sink.
// It never carries raw payload bytes, the sink IP, or canary values.
type MockEgressEvidence struct {
	SinkEndpoint     string   `json:"sinkEndpoint"`
	BaselineRequests int      `json:"baselineRequests"`
	ExerciseRequests int      `json:"exerciseRequests"`
	DeltaRequests    int      `json:"deltaRequests"`
	BaselineBytes    int64    `json:"baselineBytes"`
	ExerciseBytes    int64    `json:"exerciseBytes"`
	DeltaBytes       int64    `json:"deltaBytes"`
	Truncated        bool     `json:"truncated"`
	CaptureComplete  bool     `json:"captureComplete"`
	PayloadEncoding  string   `json:"payloadEncoding"`
	PayloadSHA256    string   `json:"payloadSha256,omitempty"`
	CanariesObserved []string `json:"canariesObserved"`
}

// MockEgressReceipt is the private per-lane receipt written by the guest sink. It
// stays inside the private capture bundle; only its bounded summary is published.
type MockEgressReceipt struct {
	Sink struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"sink"`
	Lane             string `json:"lane"`
	AcceptedRequests int    `json:"acceptedRequests"`
	CapturedBytes    int64  `json:"capturedBytes"`
	Truncated        bool   `json:"truncated"`
	DeadlineHit      bool   `json:"deadlineHit"`
	ObservedChunks   int    `json:"observedChunks"`
	PeakOpenSockets  int    `json:"peakOpenSockets"`
	RejectedRequests int    `json:"rejectedRequests"`
	PayloadBase64    string `json:"payloadBase64"`
	payload          []byte
}

// mockEgressReceiptComplete is the single completeness seam used by canary
// correlation. A bounded payload is not complete if the sink truncated, timed
// out, or rejected any request.
func mockEgressReceiptComplete(receipt *MockEgressReceipt) bool {
	return receipt != nil && !receipt.Truncated && !receipt.DeadlineHit && receipt.RejectedRequests == 0
}

func mockEgressHostPort(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", "", fmt.Errorf("invalid mockEgress.address: %s", address)
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return "", "", fmt.Errorf("mockEgress.address must use a literal IPv4 loopback address: %s", address)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1024 || number > 65535 {
		return "", "", fmt.Errorf("invalid mockEgress.address port: %s", address)
	}
	return ip.String(), port, nil
}

func (config MockEgressConfig) validateShape() error {
	if !config.Enabled {
		return nil
	}
	if _, _, err := mockEgressHostPort(config.Address); err != nil {
		return err
	}
	if config.MaxRequests < 1 || config.MaxRequests > 1024 {
		return errors.New("mockEgress.maxRequests must be between 1 and 1024")
	}
	if config.MaxBytesPerRequest < 1 || config.MaxBytesPerRequest > mockEgressReceiptRawCapBytes {
		return fmt.Errorf("mockEgress.maxBytesPerRequest must be between 1 and %d", mockEgressReceiptRawCapBytes)
	}
	if config.MaxTotalBytes < config.MaxBytesPerRequest || config.MaxTotalBytes > mockEgressReceiptRawCapBytes {
		return fmt.Errorf("mockEgress.maxTotalBytes must be between maxBytesPerRequest and %d", mockEgressReceiptRawCapBytes)
	}
	if config.DeadlineSeconds < 0 || config.DeadlineSeconds > 3600 {
		return errors.New("mockEgress.deadlineSeconds must be between 0 (auto) and 3600")
	}
	if config.CannedResponseBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(config.CannedResponseBase64)
		if err != nil {
			return errors.New("mockEgress.cannedResponseBase64 must be valid base64")
		}
		if len(decoded) > mockEgressCannedResponseMaxBytes {
			return fmt.Errorf("mockEgress.cannedResponseBase64 must decode to at most %d bytes", mockEgressCannedResponseMaxBytes)
		}
	}
	return nil
}

// validateLive enforces the containment invariants for the sink. The sink must be
// a guest-local IPv4 loopback endpoint so captured bytes never traverse a LAN or
// the Internet, and it must not overlap the exact model control-plane allowlist.
func (config MockEgressConfig) validateLive(controlPlaneAddresses []string) error {
	if !config.Enabled {
		return nil
	}
	host, port, err := mockEgressHostPort(config.Address)
	if err != nil {
		return err
	}
	if !net.ParseIP(host).IsLoopback() {
		return errors.New("mockEgress.address must be a guest-local IPv4 loopback address so captured bytes never leave the VM")
	}
	sink := net.JoinHostPort(host, port)
	for _, address := range controlPlaneAddresses {
		modelHost, modelPort, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			continue
		}
		if net.JoinHostPort(strings.Trim(modelHost, "[]"), modelPort) == sink {
			return errors.New("mockEgress.address must not overlap the exact model control-plane allowlist")
		}
	}
	return nil
}

func mockEgressAddressMatches(config MockEgressConfig, host string, port int) bool {
	wantHost, wantPort, err := mockEgressHostPort(config.Address)
	if err != nil {
		return false
	}
	got := net.ParseIP(strings.Trim(host, "[]"))
	if got == nil {
		return false
	}
	return got.String() == wantHost && strconv.Itoa(port) == wantPort
}

// mockEgressClassifiedAddress reports the exact host:port the sink listens on so
// the trace analyzer can label matching connect/send subjects as controlled-sink
// traffic and redact the raw loopback address from published observations.
func mockEgressClassifiedAddress(config MockEgressConfig) string {
	if !config.Enabled {
		return ""
	}
	host, port, err := mockEgressHostPort(config.Address)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, port)
}

func mockEgressCgroupIPs(config MockEgressConfig) []string {
	if !config.Enabled {
		return []string{}
	}
	host, _, err := mockEgressHostPort(config.Address)
	if err != nil {
		return []string{}
	}
	return []string{host}
}

// mockEgressEffectiveDeadline keeps the sink alive across the whole lane; the
// runtime timeout is the backstop when the operator does not pin a shorter one.
func mockEgressEffectiveDeadline(config MockEgressConfig, timeoutSeconds int) int {
	if config.DeadlineSeconds > 0 {
		return config.DeadlineSeconds
	}
	return timeoutSeconds + 30
}

func mockEgressRuntime(config MockEgressConfig, timeoutSeconds int) map[string]any {
	if !config.Enabled {
		return map[string]any{"enabled": false}
	}
	host, port, _ := mockEgressHostPort(config.Address)
	portNumber, _ := strconv.Atoi(port)
	return map[string]any{
		"enabled":              true,
		"host":                 host,
		"port":                 portNumber,
		"maxRequests":          config.MaxRequests,
		"maxBytesPerRequest":   config.MaxBytesPerRequest,
		"maxTotalBytes":        config.MaxTotalBytes,
		"deadlineSeconds":      mockEgressEffectiveDeadline(config, timeoutSeconds),
		"cannedResponseBase64": config.CannedResponseBase64,
		"maxDataChunks":        mockEgressMaxDataChunks,
		"maxConcurrentSockets": mockEgressMaxConcurrentSockets,
		"receiptMaxBytes":      mockEgressReceiptRawCapBytes*2 + 4096,
	}
}

func parseMockEgressReceipt(data []byte) (*MockEgressReceipt, error) {
	if len(data) > mockEgressReceiptRawCapBytes*2+4096 {
		return nil, errors.New("controlled mock egress receipt exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt MockEgressReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return nil, fmt.Errorf("parse controlled mock egress receipt: %w", err)
	}
	if strings.TrimSpace(receipt.Sink.Host) == "" || receipt.Sink.Port < 1 || receipt.Sink.Port > 65535 {
		return nil, errors.New("controlled mock egress receipt has an invalid sink identity")
	}
	if net.ParseIP(strings.Trim(receipt.Sink.Host, "[]")) == nil {
		return nil, errors.New("controlled mock egress receipt sink host is not an IP literal")
	}
	if receipt.AcceptedRequests < 0 || receipt.CapturedBytes < 0 || receipt.ObservedChunks < 0 || receipt.PeakOpenSockets < 0 || receipt.RejectedRequests < 0 {
		return nil, errors.New("controlled mock egress receipt has negative counters")
	}
	payload, err := base64.StdEncoding.DecodeString(receipt.PayloadBase64)
	if err != nil {
		return nil, errors.New("controlled mock egress receipt payload is not valid base64")
	}
	if int64(len(payload)) != receipt.CapturedBytes {
		return nil, errors.New("controlled mock egress receipt payload length does not match its captured-byte count")
	}
	if len(payload) > mockEgressReceiptRawCapBytes {
		return nil, errors.New("controlled mock egress receipt payload exceeds the raw capture bound")
	}
	receipt.payload = payload
	return &receipt, nil
}

// verifyCaptureMockEgress fails closed when the sink identity, receipt, or its
// pairing disagrees with the effective configuration.
func verifyCaptureMockEgress(bundle CaptureBundle, config MockEgressConfig) error {
	if !config.Enabled {
		if bundle.MockEgressBaseline != nil || bundle.MockEgressExercise != nil {
			return errors.New("capture bundle carries a controlled mock egress receipt but the configuration disables it")
		}
		return nil
	}
	if bundle.MockEgressBaseline == nil || bundle.MockEgressExercise == nil {
		return errors.New("controlled mock egress is enabled but the capture bundle is missing a per-lane sink receipt")
	}
	if err := config.validateShape(); err != nil {
		return fmt.Errorf("validate controlled mock egress receipt limits: %w", err)
	}
	for lane, receipt := range map[string]*MockEgressReceipt{"baseline": bundle.MockEgressBaseline, "exercise": bundle.MockEgressExercise} {
		if receipt.Lane != lane {
			return fmt.Errorf("controlled mock egress receipt lane mismatch: expected %q, receipt records %q", lane, receipt.Lane)
		}
		if !mockEgressAddressMatches(config, receipt.Sink.Host, receipt.Sink.Port) {
			return errors.New("controlled mock egress sink identity does not match the configured address")
		}
		if receipt.AcceptedRequests > config.MaxRequests {
			return fmt.Errorf("controlled mock egress %s receipt exceeds configured request cap", lane)
		}
		if receipt.CapturedBytes > config.MaxTotalBytes {
			return fmt.Errorf("controlled mock egress %s receipt exceeds configured total-byte cap", lane)
		}
		requestByteCap := int64(receipt.AcceptedRequests) * config.MaxBytesPerRequest
		if receipt.CapturedBytes > requestByteCap {
			return fmt.Errorf("controlled mock egress %s receipt exceeds configured per-request byte cap", lane)
		}
		if receipt.ObservedChunks > mockEgressMaxDataChunks {
			return fmt.Errorf("controlled mock egress %s receipt exceeds the data-chunk cap", lane)
		}
		if receipt.PeakOpenSockets > mockEgressMaxConcurrentSockets || receipt.PeakOpenSockets > receipt.AcceptedRequests {
			return fmt.Errorf("controlled mock egress %s receipt exceeds the concurrent-socket cap", lane)
		}
	}
	return nil
}

func buildMockEgressEvidence(config MockEgressConfig, bundle CaptureBundle, canaries []CanaryDefinition) *MockEgressEvidence {
	if !config.Enabled || bundle.MockEgressBaseline == nil || bundle.MockEgressExercise == nil {
		return nil
	}
	_, port, _ := mockEgressHostPort(config.Address)
	baseline := bundle.MockEgressBaseline
	exercise := bundle.MockEgressExercise
	deltaRequests := exercise.AcceptedRequests - baseline.AcceptedRequests
	if deltaRequests < 0 {
		deltaRequests = 0
	}
	deltaBytes := exercise.CapturedBytes - baseline.CapturedBytes
	if deltaBytes < 0 {
		deltaBytes = 0
	}
	encoding := payloadEncoding(exercise.payload)
	evidence := &MockEgressEvidence{
		SinkEndpoint:     "controlled-sink:" + port,
		BaselineRequests: baseline.AcceptedRequests,
		ExerciseRequests: exercise.AcceptedRequests,
		DeltaRequests:    deltaRequests,
		BaselineBytes:    baseline.CapturedBytes,
		ExerciseBytes:    exercise.CapturedBytes,
		DeltaBytes:       deltaBytes,
		Truncated:        baseline.Truncated || baseline.DeadlineHit || exercise.Truncated || exercise.DeadlineHit,
		CaptureComplete:  mockEgressReceiptComplete(baseline) && mockEgressReceiptComplete(exercise),
		PayloadEncoding:  encoding,
		CanariesObserved: []string{},
	}
	if len(exercise.payload) > 0 {
		evidence.PayloadSHA256 = digestBytes(exercise.payload)
	}
	// Never scan opaque bytes: we do not pretend TLS-pinned or otherwise encrypted
	// payloads were decoded. Canary presence is a delta over the baseline lane.
	if evidence.CaptureComplete && encoding == "cleartext" {
		for _, canary := range canaries {
			if canary.Marker == "" {
				continue
			}
			if bytes.Contains(exercise.payload, []byte(canary.Marker)) && !bytes.Contains(baseline.payload, []byte(canary.Marker)) {
				evidence.CanariesObserved = append(evidence.CanariesObserved, canary.ID)
			}
		}
	}
	return evidence
}

// payloadEncoding reports whether captured bytes are cleartext or must be treated
// as opaque. It is a conservative heuristic, never a decode claim.
func payloadEncoding(data []byte) string {
	if len(data) == 0 {
		return "none"
	}
	if data[0] == 0x16 { // TLS handshake record
		return "opaque-or-encrypted"
	}
	nonPrintable := 0
	for _, b := range data {
		if b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			nonPrintable++
		}
	}
	if nonPrintable*100 > len(data)*30 {
		return "opaque-or-encrypted"
	}
	return "cleartext"
}

func validateMockEgressEvidence(evidence *MockEgressEvidence, requireCaptureComplete ...bool) error {
	if evidence == nil {
		return nil
	}
	if matched, _ := regexp.MatchString(`^controlled-sink:[0-9]{1,5}$`, evidence.SinkEndpoint); !matched {
		return errors.New("evidence controlled mock egress endpoint is invalid")
	}
	if evidence.BaselineRequests < 0 || evidence.ExerciseRequests < 0 || evidence.BaselineBytes < 0 || evidence.ExerciseBytes < 0 {
		return errors.New("evidence controlled mock egress counters are negative")
	}
	expectedRequests := evidence.ExerciseRequests - evidence.BaselineRequests
	if expectedRequests < 0 {
		expectedRequests = 0
	}
	expectedBytes := evidence.ExerciseBytes - evidence.BaselineBytes
	if expectedBytes < 0 {
		expectedBytes = 0
	}
	if evidence.DeltaRequests != expectedRequests || evidence.DeltaBytes != expectedBytes {
		return errors.New("evidence controlled mock egress deltas are inconsistent")
	}
	switch evidence.PayloadEncoding {
	case "none", "cleartext", "opaque-or-encrypted":
	default:
		return errors.New("evidence controlled mock egress payload encoding is unsupported")
	}
	if evidence.PayloadSHA256 != "" && !isSHA256Digest(evidence.PayloadSHA256) {
		return errors.New("evidence controlled mock egress payload digest is invalid")
	}
	if evidence.CaptureComplete && evidence.Truncated {
		return errors.New("evidence controlled mock egress cannot be complete and truncated")
	}
	if evidence.CanariesObserved == nil {
		return errors.New("evidence controlled mock egress canary list is required")
	}
	if len(requireCaptureComplete) > 0 && requireCaptureComplete[0] && !evidence.CaptureComplete && len(evidence.CanariesObserved) != 0 {
		return errors.New("evidence incomplete controlled mock egress must not report canaries")
	}
	if evidence.PayloadEncoding != "cleartext" && len(evidence.CanariesObserved) != 0 {
		return errors.New("evidence must not report canaries for opaque controlled mock egress payloads")
	}
	seen := map[string]bool{}
	for _, id := range evidence.CanariesObserved {
		if !mockEgressCanaryIDPattern.MatchString(id) || seen[id] {
			return errors.New("evidence controlled mock egress canary identifier is invalid")
		}
		seen[id] = true
	}
	return nil
}

// mockEgressSinkScript is the guest-side bounded loopback sink. It runs once per
// lane outside the untrusted agent cgroup, applies strict request/byte/time caps,
// returns a deterministic canned response, and writes a private per-lane receipt.
const mockEgressSinkScript = `import fs from "node:fs";
import net from "node:net";

const [runtimePath, receiptPath, lane] = process.argv.slice(2);
if (!runtimePath || !receiptPath || !lane) {
  process.stderr.write("usage: mock-egress-sink.mjs RUNTIME_JSON RECEIPT_OUT LANE\n");
  process.exit(64);
}
const runtime = JSON.parse(fs.readFileSync(runtimePath, "utf8"));
const sink = runtime.mockEgress;
if (!sink || !sink.enabled) process.exit(0);

const host = String(sink.host);
const port = Number(sink.port);
const maxRequests = Number(sink.maxRequests);
const maxBytesPerRequest = Number(sink.maxBytesPerRequest);
const maxTotalBytes = Number(sink.maxTotalBytes);
const deadlineMs = Number(sink.deadlineSeconds) * 1000;
const maxDataChunks = Number(sink.maxDataChunks);
const maxConcurrentSockets = Number(sink.maxConcurrentSockets);
const canned = sink.cannedResponseBase64 ? Buffer.from(sink.cannedResponseBase64, "base64") : Buffer.alloc(0);
if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 ||
    !Number.isSafeInteger(maxBytesPerRequest) || maxBytesPerRequest < 1 ||
    !Number.isSafeInteger(maxTotalBytes) || maxTotalBytes < maxBytesPerRequest ||
    !Number.isSafeInteger(deadlineMs) || deadlineMs < 1000 ||
    !Number.isSafeInteger(maxDataChunks) || maxDataChunks < 1 ||
    !Number.isSafeInteger(maxConcurrentSockets) || maxConcurrentSockets < 1) {
  throw new Error("invalid controlled mock egress bounds");
}

let accepted = 0;
let capturedTotal = 0;
let observedChunks = 0;
let peakOpenSockets = 0;
let rejectedRequests = 0;
let truncated = false;
let deadlineHit = false;
let finalized = false;
const capture = Buffer.allocUnsafe(maxTotalBytes);
const openSockets = new Set();

function finalize() {
  if (finalized) return;
  finalized = true;
  try { server.close(); } catch {}
  for (const socket of openSockets) { try { socket.destroy(); } catch {} }
  const payload = capture.subarray(0, capturedTotal);
  const receipt = {
    sink: { host, port },
    lane,
    acceptedRequests: accepted,
    capturedBytes: payload.length,
    truncated,
    deadlineHit,
    observedChunks,
    peakOpenSockets,
    rejectedRequests,
    payloadBase64: payload.toString("base64"),
  };
  const tmp = receiptPath + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(receipt) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, receiptPath);
  process.exit(0);
}

const server = net.createServer((socket) => {
  socket.on("error", () => {});
  if (accepted >= maxRequests || openSockets.size >= maxConcurrentSockets) {
    rejectedRequests += 1;
    truncated = true;
    socket.destroy();
    return;
  }
  accepted += 1;
  openSockets.add(socket);
  if (openSockets.size > peakOpenSockets) peakOpenSockets = openSockets.size;
  let connBytes = 0;
  let connChunks = 0;
  const respond = () => { try { socket.end(canned.length ? canned : undefined); } catch {} };
  const release = () => { openSockets.delete(socket); };
  socket.on("close", release);
  socket.on("data", (data) => {
    observedChunks += 1;
    connChunks += 1;
    if (observedChunks > maxDataChunks || connChunks > maxDataChunks) {
      observedChunks = Math.min(observedChunks, maxDataChunks);
      truncated = true;
      socket.pause();
      respond();
      return;
    }
    let slice = data;
    if (connBytes + slice.length > maxBytesPerRequest) { slice = slice.subarray(0, Math.max(0, maxBytesPerRequest - connBytes)); truncated = true; }
    if (capturedTotal + slice.length > maxTotalBytes) { slice = slice.subarray(0, Math.max(0, maxTotalBytes - capturedTotal)); truncated = true; }
    if (slice.length > 0) {
      slice.copy(capture, capturedTotal);
      connBytes += slice.length;
      capturedTotal += slice.length;
    }
    if (connBytes >= maxBytesPerRequest || capturedTotal >= maxTotalBytes) {
      socket.pause();
      respond();
    }
  });
  socket.on("end", respond);
  socket.setTimeout(750, respond);
});
server.maxConnections = maxConcurrentSockets;
server.on("drop", () => { rejectedRequests += 1; truncated = true; });

server.on("error", (err) => { process.stderr.write("mock egress sink error: " + err.message + "\n"); process.exit(21); });
server.listen({ port, host, backlog: Math.min(maxRequests, maxConcurrentSockets) }, () => {
  try { fs.writeFileSync(receiptPath + ".ready", "ok\n", { mode: 0o600 }); } catch {}
});
const timer = setTimeout(() => { deadlineHit = true; finalize(); }, deadlineMs);
if (typeof timer.unref === "function") timer.unref();
process.on("SIGTERM", finalize);
process.on("SIGINT", finalize);
`
