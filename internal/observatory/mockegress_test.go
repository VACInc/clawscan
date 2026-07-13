package observatory

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func mockEgressReceiptJSON(host string, port int, lane string, accepted int, payload []byte) string {
	receipt := map[string]any{
		"sink":             map[string]any{"host": host, "port": port},
		"lane":             lane,
		"acceptedRequests": accepted,
		"capturedBytes":    len(payload),
		"truncated":        false,
		"deadlineHit":      false,
		"observedChunks":   0,
		"peakOpenSockets":  0,
		"rejectedRequests": 0,
		"payloadBase64":    base64.StdEncoding.EncodeToString(payload),
	}
	if len(payload) > 0 {
		receipt["observedChunks"] = 1
	}
	if accepted > 0 {
		receipt["peakOpenSockets"] = 1
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		panic(err)
	}
	return string(data) + "\n"
}

func mustReceipt(t *testing.T, host string, port int, lane string, accepted int, payload []byte) *MockEgressReceipt {
	t.Helper()
	receipt, err := parseMockEgressReceipt([]byte(mockEgressReceiptJSON(host, port, lane, accepted, payload)))
	if err != nil {
		t.Fatalf("parse fixture receipt: %v", err)
	}
	return receipt
}

func TestMockEgressConfigValidation(t *testing.T) {
	base := MockEgressConfig{Enabled: true, Address: "127.0.0.9:9009", MaxRequests: 8, MaxBytesPerRequest: 4096, MaxTotalBytes: 8192, DeadlineSeconds: 5}
	if err := base.validateShape(); err != nil {
		t.Fatalf("valid shape rejected: %v", err)
	}
	if err := base.validateLive([]string{"10.0.0.2:8000"}); err != nil {
		t.Fatalf("valid live sink rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*MockEgressConfig)
		want   string
	}{
		{"missing address", func(c *MockEgressConfig) { c.Address = "" }, "mockEgress.address"},
		{"non-ipv4", func(c *MockEgressConfig) { c.Address = "example.invalid:9009" }, "literal IPv4"},
		{"privileged port", func(c *MockEgressConfig) { c.Address = "127.0.0.9:443" }, "invalid mockEgress.address port"},
		{"bad requests", func(c *MockEgressConfig) { c.MaxRequests = 0 }, "maxRequests"},
		{"total below per-request", func(c *MockEgressConfig) { c.MaxTotalBytes = 100 }, "maxTotalBytes"},
		{"bad canned", func(c *MockEgressConfig) { c.CannedResponseBase64 = "!!not-base64!!" }, "cannedResponseBase64"},
	} {
		t.Run("shape/"+test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if err := config.validateShape(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	for _, test := range []struct {
		name    string
		address string
		model   []string
		want    string
	}{
		{"non-loopback", "10.0.0.50:9009", []string{"10.0.0.2:8000"}, "loopback"},
		{"overlaps model", "127.0.0.9:9009", []string{"127.0.0.9:9009"}, "overlap the exact model"},
	} {
		t.Run("live/"+test.name, func(t *testing.T) {
			config := base
			config.Address = test.address
			if err := config.validateLive(test.model); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// A disabled sink imposes no constraints.
	if err := (MockEgressConfig{}).validateShape(); err != nil {
		t.Fatalf("disabled sink shape err = %v", err)
	}
	if err := (MockEgressConfig{}).validateLive(nil); err != nil {
		t.Fatalf("disabled sink live err = %v", err)
	}
}

func TestConfigRejectsMockEgressLargerThanBundleBudget(t *testing.T) {
	requireLinuxControlHost(t)
	config := validTestConfig(t, t.TempDir())
	config.Limits.MaxBundleBytes = 2 << 20
	config.Runtime.MockEgress = MockEgressConfig{Enabled: true, Address: "127.0.0.9:9009", MaxRequests: 8, MaxBytesPerRequest: 1 << 20, MaxTotalBytes: 1 << 20, DeadlineSeconds: 5}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "leave room for the controlled mock egress receipts") {
		t.Fatalf("err = %v", err)
	}
}

func TestGuestFirewallPinsControlledSink(t *testing.T) {
	sink := MockEgressConfig{Enabled: true, Address: "127.0.0.9:9009"}
	enabled := guestFirewallRules("obs_sink", []string{"10.0.0.2:8000"}, sink)
	if !strings.Contains(enabled, `ip daddr 127.0.0.9 tcp dport 9009 accept comment "controlled-mock-egress-sink"`) {
		t.Fatalf("firewall missing sink pin:\n%s", enabled)
	}
	if !strings.Contains(enabled, "ip daddr 10.0.0.2 tcp dport 8000 accept") {
		t.Fatalf("firewall dropped the model allowlist:\n%s", enabled)
	}
	disabled := guestFirewallRules("obs_sink", []string{"10.0.0.2:8000"}, MockEgressConfig{})
	if strings.Contains(disabled, "controlled-mock-egress-sink") || strings.Contains(disabled, "@AGENT_UID@") {
		t.Fatalf("disabled sink leaked a rule:\n%s", disabled)
	}
	if digestBytes([]byte(enabled)) == digestBytes([]byte(disabled)) {
		t.Fatal("firewall policy digest does not change when the sink is enabled")
	}
}

func TestGuestFirewallEnforcesExactSinkPortForAgentUID(t *testing.T) {
	sink := MockEgressConfig{Enabled: true, Address: "127.0.0.9:9009"}
	rules := guestFirewallRules("policy", []string{"10.0.0.2:8000"}, sink)
	allow := `meta skuid @AGENT_UID@ ip daddr 127.0.0.9 tcp dport 9009 accept comment "controlled-mock-egress-sink"`
	deny := `meta skuid @AGENT_UID@ ip daddr 127.0.0.0/8 drop comment "controlled-mock-egress-loopback-deny"`
	loopback := `oifname "lo" accept`
	model := "ip daddr 10.0.0.2 tcp dport 8000 accept"
	allowIdx := strings.Index(rules, allow)
	denyIdx := strings.Index(rules, deny)
	loopbackIdx := strings.Index(rules, loopback)
	modelIdx := strings.Index(rules, model)
	if allowIdx < 0 || denyIdx < 0 || loopbackIdx < 0 || modelIdx < 0 {
		t.Fatalf("firewall missing a required rule:\n%s", rules)
	}
	// The exact-port allow must precede the agent loopback deny, which must precede
	// the generic loopback accept, so the sink port is the enforcement boundary.
	if !(allowIdx < denyIdx && denyIdx < loopbackIdx && loopbackIdx < modelIdx) {
		t.Fatalf("firewall rule ordering is wrong (allow=%d deny=%d lo=%d model=%d):\n%s", allowIdx, denyIdx, loopbackIdx, modelIdx, rules)
	}
	if !strings.Contains(rules, "@AGENT_UID@") {
		t.Fatalf("firewall did not leave the agent-uid marker for in-guest substitution:\n%s", rules)
	}
	// Other agent loopback ports are denied: the only agent-scoped accept is the
	// exact sink host+port, and the catch-all agent loopback drop carries no port.
	if got := strings.Count(rules, "meta skuid @AGENT_UID@ ip daddr 127.0.0.9 tcp dport"); got != 1 {
		t.Fatalf("expected exactly one agent sink allow, got %d:\n%s", got, rules)
	}
	if strings.Contains(rules, "127.0.0.0/8 drop") && strings.Contains(rules[denyIdx:denyIdx+len(deny)], "dport") {
		t.Fatalf("agent loopback deny is port-scoped, so other ports would leak:\n%s", rules)
	}
	if got := strings.Count(rules, "meta skuid @AGENT_UID@"); got != 2 {
		t.Fatalf("expected exactly two agent-scoped rules (one allow, one deny), got %d:\n%s", got, rules)
	}
}

func TestRemoteRunnerSubstitutesAgentUIDAndExposesSink(t *testing.T) {
	for _, required := range []string{
		`MOCK_AGENT_UID=$(id -u "$AGENT_USER")`,
		`@AGENT_UID@`,
		"firewall agent-uid marker is missing",
		`if [ "$MOCK_EGRESS_ENABLED" = "1" ]; then`,
	} {
		if !strings.Contains(remoteRunScript, required) {
			t.Fatalf("remote runner missing agent-uid substitution %q", required)
		}
	}
	for _, required := range []string{
		"OBSERVATORY_MOCK_EGRESS_URL",
		"m && m.enabled",
		`MOCK_ENV=("OBSERVATORY_MOCK_EGRESS_URL=$MOCK_EGRESS_URL")`,
		`${MOCK_ENV[@]+"${MOCK_ENV[@]}"}`,
	} {
		if !strings.Contains(remoteAgentScript, required) {
			t.Fatalf("remote agent missing synthetic sink endpoint wiring %q", required)
		}
	}
	// The endpoint variable must be gated on the sink being enabled; a disabled run
	// never introduces it into the otherwise-empty child environment.
	if !strings.Contains(remoteAgentScript, `[ -n "$MOCK_EGRESS_URL" ] && MOCK_ENV=`) {
		t.Fatalf("synthetic sink endpoint is not gated on the sink being enabled:\n%s", remoteAgentScript)
	}
}

func TestRemoteRunnerHardensControlledSinkUnit(t *testing.T) {
	for _, required := range []string{
		`local sink_unit="observatory-$RUN_ID-$lane-mock-egress"`,
		`--property=CapabilityBoundingSet=`,
		`--property=NoNewPrivileges=yes`,
		`--property=ProtectSystem=strict`,
		`--property=MemoryMax=134217728`,
		`--property=MemorySwapMax=0`,
		`--property=TasksMax=16`,
		`--property="LimitFSIZE=$MOCK_RECEIPT_MAX_BYTES"`,
		`--property="SocketBindAllow=tcp:ipv4:$MOCK_SINK_PORT"`,
		`--property=SocketBindDeny=any`,
		`--property="ReadWritePaths=$OUT/$lane"`,
		`systemctl kill --kill-who=main --signal=SIGTERM "$sink_unit"`,
	} {
		if !strings.Contains(remoteRunScript, required) {
			t.Fatalf("remote runner missing hardened sink control %q", required)
		}
	}
	if strings.Contains(remoteRunScript, `node "$CONTROL/mock-egress-sink.mjs" "$RUNTIME_JSON" "$OUT/$lane/mock-egress.json" "$lane" &`) {
		t.Fatal("remote runner still launches the sink as an unconstrained background Node process")
	}
}

func TestClassifyControlledSinkTrafficRedactsRawAddress(t *testing.T) {
	metadata := CaptureMetadata{TargetKind: "skill", BaselineWorkspace: "/run/baseline/workspace", ExerciseWorkspace: "/run/exercise/workspace"}
	baseline := `execve("/usr/bin/node", ["node"], 0x0) = 0` + "\n"
	exercise := `execve("/usr/bin/node", ["node"], 0x0) = 0
connect(9<TCP:[127.0.0.3:40000->127.0.0.9:9009]>, {sa_family=AF_INET, sin_port=htons(9009), sin_addr=inet_addr("127.0.0.9")}, 16) = 0
write(9<TCP:[127.0.0.3:40000->127.0.0.9:9009]>, "exfil", 5) = 5
connect(4<TCP:[10.0.0.3:41000->203.0.113.1:9]>, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("203.0.113.1")}, 16) = -1 ECONNREFUSED (Connection refused)
`
	result := AnalyzeTraces(AnalysisInput{
		BaselineTraces:        []string{baseline},
		ExerciseTraces:        []string{exercise},
		Metadata:              metadata,
		ControlPlaneAddresses: []string{"10.0.0.2:8000"},
		MockEgressAddress:     "127.0.0.9:9009",
	})
	encoded, err := json.Marshal(result.Observations)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, expected := range []string{`"subject":"controlled-sink:9009"`, `"role":"controlled-sink"`, `"operation":"send"`, "203.0.113.1:9"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("observations missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "127.0.0.9") {
		t.Fatalf("raw loopback sink address leaked: %s", text)
	}
	found := false
	for _, limitation := range result.Coverage.Limitations {
		if strings.Contains(limitation, "Controlled mock egress captures raw bytes") {
			found = true
		}
	}
	if !found {
		t.Fatalf("coverage missing mock egress limitation: %#v", result.Coverage.Limitations)
	}
}

func TestParseMockEgressReceiptFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		want string
	}{
		{"bad base64", `{"sink":{"host":"127.0.0.9","port":9009},"lane":"exercise","acceptedRequests":1,"capturedBytes":3,"truncated":false,"deadlineHit":false,"payloadBase64":"@@@"}`, "not valid base64"},
		{"length mismatch", `{"sink":{"host":"127.0.0.9","port":9009},"lane":"exercise","acceptedRequests":1,"capturedBytes":9,"truncated":false,"deadlineHit":false,"payloadBase64":"YWJj"}`, "does not match"},
		{"bad port", `{"sink":{"host":"127.0.0.9","port":0},"lane":"exercise","acceptedRequests":1,"capturedBytes":0,"truncated":false,"deadlineHit":false,"payloadBase64":""}`, "invalid sink identity"},
		{"unknown field", `{"sink":{"host":"127.0.0.9","port":9009},"lane":"exercise","acceptedRequests":1,"capturedBytes":0,"truncated":false,"deadlineHit":false,"payloadBase64":"","secret":"x"}`, "parse controlled mock egress receipt"},
		{"non-ip host", `{"sink":{"host":"sink.invalid","port":9009},"lane":"exercise","acceptedRequests":1,"capturedBytes":0,"truncated":false,"deadlineHit":false,"payloadBase64":""}`, "not an IP literal"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseMockEgressReceipt([]byte(test.data)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	receipt, err := parseMockEgressReceipt([]byte(mockEgressReceiptJSON("127.0.0.9", 9009, "exercise", 2, []byte("payload"))))
	if err != nil || receipt.AcceptedRequests != 2 || string(receipt.payload) != "payload" {
		t.Fatalf("receipt = %#v err = %v", receipt, err)
	}
}

func TestVerifyCaptureMockEgressFailsClosed(t *testing.T) {
	enabled := MockEgressConfig{Enabled: true, Address: "127.0.0.9:9009", MaxRequests: 8, MaxBytesPerRequest: 4096, MaxTotalBytes: 8192, DeadlineSeconds: 5}
	good := CaptureBundle{
		MockEgressBaseline: mustReceipt(t, "127.0.0.9", 9009, "baseline", 0, nil),
		MockEgressExercise: mustReceipt(t, "127.0.0.9", 9009, "exercise", 1, []byte("x")),
	}
	if err := verifyCaptureMockEgress(good, enabled); err != nil {
		t.Fatalf("valid receipts rejected: %v", err)
	}
	if err := verifyCaptureMockEgress(CaptureBundle{}, enabled); err == nil || !strings.Contains(err.Error(), "missing a per-lane sink receipt") {
		t.Fatalf("missing receipt err = %v", err)
	}
	if err := verifyCaptureMockEgress(good, MockEgressConfig{}); err == nil || !strings.Contains(err.Error(), "disables it") {
		t.Fatalf("unexpected receipt err = %v", err)
	}
	mismatch := CaptureBundle{
		MockEgressBaseline: mustReceipt(t, "127.0.0.9", 9009, "baseline", 0, nil),
		MockEgressExercise: mustReceipt(t, "127.0.0.8", 9009, "exercise", 1, []byte("x")),
	}
	if err := verifyCaptureMockEgress(mismatch, enabled); err == nil || !strings.Contains(err.Error(), "sink identity") {
		t.Fatalf("identity err = %v", err)
	}
	laneSwap := CaptureBundle{
		MockEgressBaseline: mustReceipt(t, "127.0.0.9", 9009, "exercise", 0, nil),
		MockEgressExercise: mustReceipt(t, "127.0.0.9", 9009, "exercise", 1, []byte("x")),
	}
	if err := verifyCaptureMockEgress(laneSwap, enabled); err == nil || !strings.Contains(err.Error(), "lane mismatch") {
		t.Fatalf("lane err = %v", err)
	}
}

func TestVerifyCaptureMockEgressRejectsConfiguredCapViolations(t *testing.T) {
	config := MockEgressConfig{Enabled: true, Address: "127.0.0.9:9009", MaxRequests: 2, MaxBytesPerRequest: 4, MaxTotalBytes: 8, DeadlineSeconds: 5}
	baseline := mustReceipt(t, "127.0.0.9", 9009, "baseline", 0, nil)
	for _, test := range []struct {
		name    string
		receipt *MockEgressReceipt
		want    string
	}{
		{"request cap", mustReceipt(t, "127.0.0.9", 9009, "exercise", 3, []byte("x")), "request cap"},
		{"total-byte cap", mustReceipt(t, "127.0.0.9", 9009, "exercise", 2, []byte("123456789")), "total-byte cap"},
		{"per-request cap", mustReceipt(t, "127.0.0.9", 9009, "exercise", 1, []byte("12345")), "per-request byte cap"},
		{"chunk cap", func() *MockEgressReceipt {
			receipt := mustReceipt(t, "127.0.0.9", 9009, "exercise", 1, []byte("x"))
			receipt.ObservedChunks = mockEgressMaxDataChunks + 1
			return receipt
		}(), "data-chunk cap"},
		{"socket cap", func() *MockEgressReceipt {
			receipt := mustReceipt(t, "127.0.0.9", 9009, "exercise", 1, []byte("x"))
			receipt.PeakOpenSockets = mockEgressMaxConcurrentSockets + 1
			return receipt
		}(), "concurrent-socket cap"},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundle := CaptureBundle{MockEgressBaseline: baseline, MockEgressExercise: test.receipt}
			if err := verifyCaptureMockEgress(bundle, config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}

func TestBuildMockEgressEvidenceSubtractsAndDetectsCanaries(t *testing.T) {
	config := MockEgressConfig{Enabled: true, Address: "127.0.0.9:9009"}
	marker := testCanaryMarkers()["cloud-credentials"]
	cleartext := CaptureBundle{
		MockEgressBaseline: mustReceipt(t, "127.0.0.9", 9009, "baseline", 1, []byte("baseline noise")),
		MockEgressExercise: mustReceipt(t, "127.0.0.9", 9009, "exercise", 3, []byte("exfil "+marker)),
	}
	evidence := buildMockEgressEvidence(config, cleartext, testCanaries())
	if evidence == nil {
		t.Fatal("nil evidence for enabled sink")
	}
	if evidence.SinkEndpoint != "controlled-sink:9009" || evidence.DeltaRequests != 2 || evidence.PayloadEncoding != "cleartext" {
		t.Fatalf("evidence = %#v", evidence)
	}
	if len(evidence.CanariesObserved) != 1 || evidence.CanariesObserved[0] != "cloud-credentials" {
		t.Fatalf("canaries = %#v", evidence.CanariesObserved)
	}
	if evidence.PayloadSHA256 == "" || strings.Contains(evidence.PayloadSHA256, marker) {
		t.Fatalf("payload digest = %q", evidence.PayloadSHA256)
	}
	if strings.Contains(fmt.Sprintf("%#v", evidence), marker) {
		t.Fatalf("canary value leaked into evidence: %#v", evidence)
	}
	opaque := CaptureBundle{
		MockEgressBaseline: mustReceipt(t, "127.0.0.9", 9009, "baseline", 0, nil),
		MockEgressExercise: mustReceipt(t, "127.0.0.9", 9009, "exercise", 1, append([]byte{0x16, 0x03, 0x01}, []byte("tls "+marker)...)),
	}
	opaqueEvidence := buildMockEgressEvidence(config, opaque, testCanaries())
	if opaqueEvidence.PayloadEncoding != "opaque-or-encrypted" || len(opaqueEvidence.CanariesObserved) != 0 {
		t.Fatalf("opaque evidence = %#v", opaqueEvidence)
	}
	if buildMockEgressEvidence(MockEgressConfig{}, opaque, nil) != nil {
		t.Fatal("disabled sink produced evidence")
	}
}

func TestValidateMockEgressEvidence(t *testing.T) {
	valid := &MockEgressEvidence{SinkEndpoint: "controlled-sink:9009", ExerciseRequests: 2, DeltaRequests: 2, ExerciseBytes: 61, DeltaBytes: 61, PayloadEncoding: "cleartext", PayloadSHA256: "sha256:" + strings.Repeat("a", 64), CanariesObserved: []string{"cloud-credentials"}}
	if err := validateMockEgressEvidence(valid); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*MockEgressEvidence)
		want   string
	}{
		{"bad endpoint", func(m *MockEgressEvidence) { m.SinkEndpoint = "10.0.0.9:9009" }, "endpoint is invalid"},
		{"inconsistent delta", func(m *MockEgressEvidence) { m.DeltaRequests = 5 }, "deltas are inconsistent"},
		{"opaque canaries", func(m *MockEgressEvidence) { m.PayloadEncoding = "opaque-or-encrypted" }, "must not report canaries"},
		{"bad digest", func(m *MockEgressEvidence) { m.PayloadSHA256 = "deadbeef" }, "payload digest is invalid"},
		{"duplicate canary", func(m *MockEgressEvidence) { m.CanariesObserved = []string{"cloud-credentials", "cloud-credentials"} }, "canary identifier is invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := *valid
			evidence.CanariesObserved = append([]string(nil), valid.CanariesObserved...)
			test.mutate(&evidence)
			if err := validateMockEgressEvidence(&evidence); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if err := validateMockEgressEvidence(nil); err != nil {
		t.Fatalf("nil mock egress evidence rejected: %v", err)
	}
	full := fixtureEvidence()
	full.MockEgress = valid
	full.Coverage.CanaryStages[3].Source = "socket-send-syscall-payload+typed-sink-receipt"
	if err := ValidateEvidence(full); err != nil {
		t.Fatalf("evidence with valid mock egress rejected: %v", err)
	}
}

func TestReadCaptureBundleParsesMockEgressReceipts(t *testing.T) {
	entries := fixtureBundleEntries("obs_sink", "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "skill", "")
	entries["baseline/mock-egress.json"] = mockEgressReceiptJSON("127.0.0.9", 9009, "baseline", 0, nil)
	entries["exercise/mock-egress.json"] = mockEgressReceiptJSON("127.0.0.9", 9009, "exercise", 2, []byte("payload"))
	path := filepath.Join(t.TempDir(), "capture.tar.gz")
	if err := writeTestBundle(path, entries); err != nil {
		t.Fatal(err)
	}
	bundle, err := ReadCaptureBundle(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.MockEgressExercise == nil || bundle.MockEgressExercise.AcceptedRequests != 2 || string(bundle.MockEgressExercise.payload) != "payload" {
		t.Fatalf("exercise receipt = %#v", bundle.MockEgressExercise)
	}
	if bundle.MockEgressBaseline == nil || bundle.MockEgressBaseline.AcceptedRequests != 0 {
		t.Fatalf("baseline receipt = %#v", bundle.MockEgressBaseline)
	}
}

func TestScanCapturesControlledMockEgressEvidence(t *testing.T) {
	requireLinuxControlHost(t)
	skill := filepath.Join("..", "..", "testdata", "fixtures", "probe-skill")
	config := validTestConfig(t, t.TempDir())
	config.Runtime.MockEgress = MockEgressConfig{Enabled: true, Address: "127.0.0.9:9009", MaxRequests: 8, MaxBytesPerRequest: 4096, MaxTotalBytes: 8192, DeadlineSeconds: 5}
	result, err := Scan(context.Background(), skill, config, &fixtureExecutor{t: t})
	if err != nil {
		t.Fatal(err)
	}
	mock := result.Evidence.MockEgress
	if mock == nil || mock.SinkEndpoint != "controlled-sink:9009" || mock.DeltaRequests != 1 || mock.PayloadEncoding != "cleartext" {
		t.Fatalf("mock egress evidence = %#v", mock)
	}
	if len(mock.CanariesObserved) != 1 || mock.CanariesObserved[0] != "cloud-credentials" {
		t.Fatalf("transmitted canaries = %#v", mock.CanariesObserved)
	}
	encoded, err := json.Marshal(result.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"subject":"controlled-sink:9009"`) || !strings.Contains(text, `"role":"controlled-sink"`) {
		t.Fatalf("controlled sink observation missing: %s", text)
	}
	if strings.Contains(text, "127.0.0.9") || strings.Contains(text, "OBS-CANARY") {
		t.Fatalf("evidence leaked sink address or canary value: %s", text)
	}
	if !strings.Contains(text, "Controlled mock egress captures raw bytes") {
		t.Fatalf("coverage limitation missing: %s", text)
	}
}

func TestScanFailsClosedWhenSinkReceiptMissing(t *testing.T) {
	requireLinuxControlHost(t)
	skill := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# Fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := validTestConfig(t, t.TempDir())
	// Enable the sink but use an executor whose fabricated bundle omits receipts.
	config.Runtime.MockEgress = MockEgressConfig{Enabled: true, Address: "127.0.0.9:9009", MaxRequests: 8, MaxBytesPerRequest: 4096, MaxTotalBytes: 8192, DeadlineSeconds: 5}
	if _, err := Scan(context.Background(), skill, config, &noReceiptExecutor{t: t}); err == nil || !strings.Contains(err.Error(), "missing a per-lane sink receipt") {
		t.Fatalf("err = %v", err)
	}
}

// noReceiptExecutor fabricates a valid bundle that omits controlled mock egress
// receipts even though the configuration enables the sink.
type noReceiptExecutor struct {
	t *testing.T
}

func (executor *noReceiptExecutor) Run(_ context.Context, _ string, args []string, cwd string, _ map[string]string, _ time.Duration) (CommandResult, error) {
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
	if err := writeTestBundle(bundlePath, entries); err != nil {
		executor.t.Fatal(err)
	}
	return CommandResult{Stdout: "no-receipt run\n"}, nil
}

func TestRenderSiteShowsControlledMockEgress(t *testing.T) {
	requireLinuxControlHost(t)
	evidence := fixtureEvidence()
	evidence.MockEgress = &MockEgressEvidence{
		SinkEndpoint: "controlled-sink:9009", ExerciseRequests: 1, DeltaRequests: 1, ExerciseBytes: 61, DeltaBytes: 61,
		PayloadEncoding: "cleartext", PayloadSHA256: "sha256:" + strings.Repeat("a", 64), CanariesObserved: []string{"cloud-credentials"},
	}
	evidence.Coverage.CanaryStages[3].Source = "socket-send-syscall-payload+typed-sink-receipt"
	output := t.TempDir()
	if err := RenderSite(output, evidence, nil); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(output, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	for _, expected := range []string{"Controlled mock egress", "controlled-sink:9009", "cloud-credentials", "never decoded"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("HTML missing %q", expected)
		}
	}
}

type controlledSink struct {
	host    string
	port    int
	url     string
	collect func() *MockEgressReceipt
}

// runControlledSink starts the real embedded sink script on loopback and returns
// its synthetic endpoint plus a collector that terminates it and reads the
// private receipt. It contacts no external service.
func runControlledSink(t *testing.T, maxBytesPerRequest int64, maxTotalBytes int64) controlledSink {
	t.Helper()
	requireLinuxControlHost(t)
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for controlled mock egress sink validation")
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "mock-egress-sink.mjs")
	if err := os.WriteFile(scriptPath, []byte(mockEgressSinkScript), 0o644); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	runtime := map[string]any{
		"mockEgress": map[string]any{
			"enabled": true, "host": "127.0.0.1", "port": port,
			"maxRequests": 8, "maxBytesPerRequest": maxBytesPerRequest, "maxTotalBytes": maxTotalBytes, "deadlineSeconds": 20,
			"maxDataChunks": mockEgressMaxDataChunks, "maxConcurrentSockets": mockEgressMaxConcurrentSockets,
			"cannedResponseBase64": base64.StdEncoding.EncodeToString([]byte("OK\n")),
		},
	}
	runtimePath := filepath.Join(dir, "runtime.json")
	if err := writeJSON(runtimePath, runtime, 0o600); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(dir, "mock-egress.json")
	command := exec.Command(node, scriptPath, runtimePath, receiptPath, "exercise")
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	})
	readyDeadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(receiptPath + ".ready"); err == nil {
			break
		}
		if time.Now().After(readyDeadline) {
			t.Fatal("controlled mock egress sink did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	collect := func() *MockEgressReceipt {
		if !stopped {
			stopped = true
			_ = command.Process.Signal(syscall.SIGTERM)
			if _, err := command.Process.Wait(); err != nil {
				t.Fatalf("controlled mock egress sink exited with error: %v", err)
			}
		}
		data, err := os.ReadFile(receiptPath)
		if err != nil {
			t.Fatalf("read receipt: %v", err)
		}
		receipt, err := parseMockEgressReceipt(data)
		if err != nil {
			t.Fatalf("parse receipt: %v", err)
		}
		return receipt
	}
	return controlledSink{host: "127.0.0.1", port: port, url: fmt.Sprintf("http://127.0.0.1:%d/observatory-mock-egress", port), collect: collect}
}

func assertCanaryExfiltrated(t *testing.T, receipt *MockEgressReceipt, marker string) {
	t.Helper()
	if receipt.AcceptedRequests < 1 || !bytes.Contains(receipt.payload, []byte(marker)) {
		t.Fatalf("sink receipt did not capture the transmitted canary: %#v", receipt)
	}
	config := MockEgressConfig{Enabled: true, Address: fmt.Sprintf("%s:%d", receipt.Sink.Host, receipt.Sink.Port)}
	canaries := []CanaryDefinition{{ID: "cloud-credentials", Surface: "home file", Path: "$HOME/.aws/credentials", Marker: marker}}
	bundle := CaptureBundle{
		MockEgressBaseline: mustReceipt(t, receipt.Sink.Host, receipt.Sink.Port, "baseline", 0, nil),
		MockEgressExercise: receipt,
	}
	evidence := buildMockEgressEvidence(config, bundle, canaries)
	if evidence == nil || len(evidence.CanariesObserved) != 1 || evidence.CanariesObserved[0] != "cloud-credentials" {
		t.Fatalf("evidence did not correlate the transmitted canary: %#v", evidence)
	}
	if evidence.PayloadEncoding != "cleartext" || evidence.DeltaRequests != 1 {
		t.Fatalf("mock egress evidence = %#v", evidence)
	}
	if strings.Contains(fmt.Sprintf("%#v", evidence), marker) {
		t.Fatalf("canary value leaked into public evidence: %#v", evidence)
	}
}

func TestMockEgressSinkScriptCapturesBoundedPayload(t *testing.T) {
	sink := runControlledSink(t, 8, 32) // 8-byte per-request cap
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sink.port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("0123456789")); err != nil { // exceeds the per-request cap
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 16)
	n, _ := conn.Read(response)
	if string(response[:n]) != "OK\n" {
		t.Fatalf("canned response = %q", response[:n])
	}
	_ = conn.Close()
	receipt := sink.collect()
	if receipt.AcceptedRequests != 1 || receipt.CapturedBytes != 8 || !receipt.Truncated {
		t.Fatalf("receipt = %#v", receipt)
	}
	if string(receipt.payload) != "01234567" || receipt.Sink.Port != sink.port {
		t.Fatalf("captured payload = %q port = %d", receipt.payload, receipt.Sink.Port)
	}
}

func TestMockEgressSinkBoundsRequestAndObjectOverhead(t *testing.T) {
	sink := runControlledSink(t, 32, 256)
	for index := 0; index < 24; index++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", sink.port), time.Second)
		if err != nil {
			continue
		}
		_, _ = conn.Write([]byte{byte(index)})
		_ = conn.Close()
	}
	time.Sleep(200 * time.Millisecond)
	receipt := sink.collect()
	if receipt.AcceptedRequests > 8 || receipt.CapturedBytes > 256 {
		t.Fatalf("sink exceeded request/byte bounds: %#v", receipt)
	}
	if receipt.ObservedChunks > mockEgressMaxDataChunks || receipt.PeakOpenSockets > mockEgressMaxConcurrentSockets {
		t.Fatalf("sink exceeded object-overhead bounds: %#v", receipt)
	}
	if !receipt.Truncated || receipt.RejectedRequests < 1 {
		t.Fatalf("sink did not record rejected excess requests: %#v", receipt)
	}
}

func TestProbeSkillFixtureExfiltratesCanaryToControlledSink(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for owned-fixture controlled mock egress correlation")
	}
	sink := runControlledSink(t, 1024, 8192)
	home := t.TempDir()
	workspace := t.TempDir()
	marker := "OBS-CANARY-" + strings.Repeat("c", 48)
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aws", "credentials"), []byte("[default]\naws_access_key_id="+marker+"\nregion=us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "probe-skill", "scripts", "probe.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(node, probe)
	command.Env = []string{"HOME=" + home, "OBSERVATORY_WORKSPACE=" + workspace, "OBSERVATORY_MOCK_EGRESS_URL=" + sink.url, "PATH=" + os.Getenv("PATH")}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run probe skill fixture: %v: %s", err, output)
	}
	assertCanaryExfiltrated(t, sink.collect(), marker)
}

func TestProbePluginFixtureExfiltratesCanaryToControlledSink(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for owned-fixture controlled mock egress correlation")
	}
	sink := runControlledSink(t, 1024, 8192)
	dir := t.TempDir()
	// Run the owned fixture standalone against a stubbed plugin SDK so we execute
	// the real fixture source without the full OpenClaw CLI.
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "probe-plugin", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	sdkDir := filepath.Join(dir, "node_modules", "openclaw", "plugin-sdk")
	if err := os.MkdirAll(sdkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"type":"module"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_modules", "openclaw", "package.json"), []byte(`{"name":"openclaw","version":"0.0.0","exports":{"./plugin-sdk/plugin-entry":"./plugin-sdk/plugin-entry.mjs"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdkDir, "plugin-entry.mjs"), []byte("export function definePluginEntry(entry) { return entry; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	harness := "import entry from \"./index.js\";\nconst tools = [];\nentry.register({ registerTool: (tool) => tools.push(tool) });\nawait tools[0].execute();\n"
	if err := os.WriteFile(filepath.Join(dir, "harness.mjs"), []byte(harness), 0o644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	workspace := t.TempDir()
	marker := "OBS-CANARY-" + strings.Repeat("d", 48)
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aws", "credentials"), []byte("[default]\naws_access_key_id="+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(node, filepath.Join(dir, "harness.mjs"))
	command.Dir = dir
	command.Env = []string{"HOME=" + home, "OBSERVATORY_WORKSPACE=" + workspace, "OBSERVATORY_MOCK_EGRESS_URL=" + sink.url, "PATH=" + os.Getenv("PATH")}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run probe plugin fixture: %v: %s", err, output)
	}
	assertCanaryExfiltrated(t, sink.collect(), marker)
}
