package observatory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigPinsDedicatedObservatoryUser(t *testing.T) {
	config := validTestConfig(t, t.TempDir())
	config.Runtime.AgentUser = "daemon"
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "exactly the pinned dedicated account observatory") {
		t.Fatalf("err = %v", err)
	}
}

func TestHostileLaneHasNoUnixSocketsOrDirectModelRoute(t *testing.T) {
	start := strings.Index(remoteRunScript, "run_lane() {")
	end := strings.Index(remoteRunScript[start:], "# run_lane_and_capture")
	if start < 0 || end < 0 {
		t.Fatal("hostile lane unit not found")
	}
	lane := remoteRunScript[start : start+end]
	for _, required := range []string{
		`RestrictAddressFamilies=AF_INET`,
		`MemorySwapMax=0`,
		`LimitNOFILE=1024`,
		`PrivateIPC=yes`,
		`SystemCallFilter=~bind listen accept accept4 io_uring_setup io_uring_register io_uring_enter`,
		`for (const value of r.modelRelayIps)`,
	} {
		if !strings.Contains(lane, required) {
			t.Fatalf("hostile lane missing %q", required)
		}
	}
	for _, forbidden := range []string{"AF_UNIX", "AF_INET6", `for (const value of r.controlPlaneIps)`} {
		if strings.Contains(lane, forbidden) {
			t.Fatalf("hostile lane retains forbidden capability %q", forbidden)
		}
	}
	for _, required := range []string{
		`[ "$AGENT_USER" = "observatory" ]`,
		`pgrep -u "$AGENT_USER"`,
		`Observatory agent UID has preexisting processes`,
	} {
		if !strings.Contains(remoteRunScript, required) {
			t.Fatalf("runtime account guard missing %q", required)
		}
	}
}

func TestTrustedRelayAndSinkKeepOnlyTheirExactListenerPolicy(t *testing.T) {
	listenerDeny := `SystemCallFilter=~bind listen accept accept4`
	relayStart := strings.Index(remoteRunScript, `local relay_unit="observatory-$RUN_ID-$lane-model-relay"`)
	sinkStart := strings.Index(remoteRunScript, `local sink_unit="observatory-$RUN_ID-$lane-mock-egress"`)
	laneStart := strings.Index(remoteRunScript, `  run_lane "$lane" "$root"`)
	if relayStart < 0 || sinkStart <= relayStart || laneStart <= sinkStart {
		t.Fatal("trusted listener unit boundaries not found")
	}
	if strings.Contains(remoteRunScript[relayStart:sinkStart], listenerDeny) {
		t.Fatal("trusted model relay cannot bind its exact allowlisted port")
	}
	if strings.Contains(remoteRunScript[sinkStart:laneStart], listenerDeny) {
		t.Fatal("trusted mock sink cannot bind its exact allowlisted port")
	}
	if !strings.Contains(remoteRunScript[relayStart:sinkStart], `SocketBindAllow=ipv4:tcp:$MODEL_RELAY_PORT`) {
		t.Fatal("trusted model relay does not use systemd's address-family:protocol:port syntax")
	}
	if !strings.Contains(remoteRunScript[relayStart:sinkStart], `--property=IPAddressAllow=127.0.0.1`) {
		t.Fatal("trusted model relay does not admit the hostile lane's kernel-selected loopback source")
	}
	if !strings.Contains(remoteRunScript[sinkStart:laneStart], `SocketBindAllow=ipv4:tcp:$MOCK_SINK_PORT`) {
		t.Fatal("trusted mock sink does not use systemd's address-family:protocol:port syntax")
	}
}

func TestFirewallGivesUpstreamOnlyToRelayControlUID(t *testing.T) {
	rules := guestFirewallRules("policy", []string{"10.0.0.2:8000"}, ModelRelayConfig{}, MockEgressConfig{})
	relayAllow := `meta skuid @AGENT_UID@ ip daddr 127.0.0.8 tcp dport 9010 accept comment "bounded-model-relay"`
	loopbackDeny := `meta skuid @AGENT_UID@ ip daddr 127.0.0.0/8 drop comment "agent-adjacent-loopback-deny"`
	upstreamAllow := `meta skuid @CONTROL_UID@ ip daddr 10.0.0.2 tcp dport 8000 accept comment "model-upstream-relay-only"`
	for _, required := range []string{relayAllow, loopbackDeny, upstreamAllow} {
		if !strings.Contains(rules, required) {
			t.Fatalf("firewall missing %q:\n%s", required, rules)
		}
	}
	if strings.Contains(rules, "\n    ip daddr 10.0.0.2 tcp dport 8000 accept") || strings.Contains(rules, "@AGENT_UID@ ip daddr 10.0.0.2") {
		t.Fatalf("hostile UID retained direct upstream access:\n%s", rules)
	}
	if !(strings.Index(rules, relayAllow) < strings.Index(rules, loopbackDeny)) {
		t.Fatalf("relay allow must precede adjacent-loopback deny:\n%s", rules)
	}
}

func TestModelRelayPolicyPinsOnlyExpectedAPIRoute(t *testing.T) {
	completion := ModelConfig{BaseURL: "https://10.0.0.2:8443/v1", ID: "fixture", API: "openai-completions"}
	policy, err := buildModelRelayPolicy(ModelRelayConfig{}, completion, 600)
	if err != nil {
		t.Fatal(err)
	}
	if policy.AllowedMethod != "POST" || policy.AllowedPath != "/v1/chat/completions" || policy.UpstreamURL != "https://10.0.0.2:8443/v1/chat/completions" || policy.RequestTimeoutSeconds != 120 {
		t.Fatalf("completion relay policy = %#v", policy)
	}
	responses := completion
	responses.API = "openai-responses"
	responsePolicy, err := buildModelRelayPolicy(ModelRelayConfig{}, responses, 30)
	if err != nil {
		t.Fatal(err)
	}
	if responsePolicy.AllowedPath != "/v1/responses" || responsePolicy.RequestTimeoutSeconds != 30 {
		t.Fatalf("responses relay policy = %#v", responsePolicy)
	}
	modified := effectiveModelRelayConfig(ModelRelayConfig{})
	modified.MaxRequests++
	modifiedPolicy, err := buildModelRelayPolicy(modified, completion, 600)
	if err != nil {
		t.Fatal(err)
	}
	if modelRelayPolicySHA256(policy) == modelRelayPolicySHA256(modifiedPolicy) {
		t.Fatal("relay policy digest ignored a traffic cap")
	}
	nonCanonical := completion
	nonCanonical.BaseURL = "https://10.0.0.2:8443/v1/../admin"
	if _, err := buildModelRelayPolicy(ModelRelayConfig{}, nonCanonical, 600); err == nil || !strings.Contains(err.Error(), "must be canonical") {
		t.Fatalf("non-canonical model path err = %v", err)
	}
}

func TestModelRelayReceiptsFailClosedAndMockCompletenessIsExplicit(t *testing.T) {
	runtimeConfig := RuntimeConfig{
		TimeoutSeconds: 10,
		Model:          ModelConfig{BaseURL: "http://10.0.0.2:8000/v1", ID: "fixture", API: "openai-completions"},
	}
	policy, err := buildModelRelayPolicy(runtimeConfig.ModelRelay, runtimeConfig.Model, runtimeConfig.TimeoutSeconds)
	if err != nil {
		t.Fatal(err)
	}
	digest := modelRelayPolicySHA256(policy)
	bundle := CaptureBundle{
		ModelRelayBaseline: &ModelRelayReceipt{Lane: "baseline", PolicySHA256: digest, AcceptedRequests: 1, RequestBytes: 100, ResponseBytes: 200, PeakConcurrency: 1},
		ModelRelayExercise: &ModelRelayReceipt{Lane: "exercise", PolicySHA256: digest, AcceptedRequests: 1, RequestBytes: 100, ResponseBytes: 200, PeakConcurrency: 1},
	}
	if err := verifyModelRelayReceipts(bundle, runtimeConfig); err != nil {
		t.Fatalf("valid receipts rejected: %v", err)
	}
	bundle.ModelRelayBaseline.AcceptedRequests = 0
	bundle.ModelRelayBaseline.RejectedRequests = 1
	bundle.ModelRelayBaseline.RequestBytes = 100
	bundle.ModelRelayBaseline.ResponseBytes = 0
	if err := verifyModelRelayReceipts(bundle, runtimeConfig); err != nil {
		t.Fatalf("bounded rejected request bytes rejected: %v", err)
	}
	bundle.ModelRelayExercise.PolicySHA256 = "sha256:" + strings.Repeat("f", 64)
	if err := verifyModelRelayReceipts(bundle, runtimeConfig); err == nil || !strings.Contains(err.Error(), "policy digest") {
		t.Fatalf("digest mismatch err = %v", err)
	}
	if _, err := parseModelRelayReceipt([]byte(`{"lane":"baseline","policySha256":"` + digest + `"}`)); err == nil || !strings.Contains(err.Error(), "field set is incomplete") {
		t.Fatalf("partial relay receipt err = %v", err)
	}

	if !mockEgressReceiptComplete(&MockEgressReceipt{}) {
		t.Fatal("clean sink receipt was not complete")
	}
	for _, receipt := range []*MockEgressReceipt{{Truncated: true}, {DeadlineHit: true}, {RejectedRequests: 1}, nil} {
		if mockEgressReceiptComplete(receipt) {
			t.Fatalf("incomplete sink receipt accepted: %#v", receipt)
		}
	}
}

func TestRenderSitePublishesOnlySafeModelRelayAccounting(t *testing.T) {
	evidence := fixtureEvidence()
	evidence.ModelRelay = &ModelRelayEvidence{
		Route:                    "bounded-control-relay",
		PolicySHA256:             "sha256:" + strings.Repeat("7", 64),
		BaselineReceiptSHA256:    "sha256:" + strings.Repeat("6", 64),
		ExerciseReceiptSHA256:    "sha256:" + strings.Repeat("5", 64),
		BaselineRequests:         1,
		ExerciseRequests:         2,
		ExerciseRejectedRequests: 1,
		BaselineRequestBytes:     100,
		ExerciseRequestBytes:     200,
		BaselineResponseBytes:    300,
		ExerciseResponseBytes:    400,
	}
	output := t.TempDir()
	if err := RenderSite(output, evidence, nil); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(filepath.Join(output, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, required := range []string{"Bounded model relay", "bounded-control-relay", "Rejected requests", "The hostile lane reached only this bounded control relay"} {
		if !strings.Contains(text, required) {
			t.Fatalf("rendered relay panel missing %q", required)
		}
	}
	if strings.Contains(text, "10.0.0.2") || strings.Contains(text, "/v1/chat/completions") {
		t.Fatal("rendered relay panel leaked the private upstream endpoint")
	}
}

func TestValidateEvidenceBindsRelayCompletenessToRunStatus(t *testing.T) {
	evidence := fixtureEvidence()
	evidence.Run.Isolation.ContainmentProfile = "proxmox-vm+nftables+systemd-cgroup+bounded-model-relay"
	evidence.ModelRelay.Truncated = true
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "run status") {
		t.Fatalf("completed truncated relay err = %v", err)
	}
	evidence.Run.Status = "incomplete"
	if err := ValidateEvidence(evidence); err != nil {
		t.Fatalf("incomplete truncated relay rejected: %v", err)
	}
	evidence.ModelRelay = nil
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "model relay receipt is required") {
		t.Fatalf("missing bounded relay err = %v", err)
	}
}

func TestModelRelayScriptRejectsAdjacentRoutesAndCapsRequests(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("loopback alias fixture requires Linux")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	upstreamListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var upstreamCalls atomic.Int32
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/v1/chat/completions" {
			t.Errorf("upstream request = %s %s", request.Method, request.URL.Path)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	})}
	go func() { _ = upstream.Serve(upstreamListener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = upstream.Shutdown(ctx)
	}()

	probe, err := net.Listen("tcp4", "127.0.0.8:0")
	if err != nil {
		t.Skipf("loopback alias unavailable: %v", err)
	}
	relayAddress := probe.Addr().String()
	_ = probe.Close()
	upstreamAddress := upstreamListener.Addr().String()
	model := ModelConfig{BaseURL: "http://" + upstreamAddress + "/v1", ID: "fixture-model", API: "openai-completions"}
	relayConfig := ModelRelayConfig{Address: relayAddress, MaxRequests: 7, MaxRequestBytes: 1024, MaxResponseBytes: 2048, MaxTotalBytes: 2048, MaxConcurrentRequests: 1, RequestTimeoutSeconds: 1}
	policy, err := buildModelRelayPolicy(relayConfig, model, 5)
	if err != nil {
		t.Fatal(err)
	}
	runtimePolicy, err := modelRelayRuntime(relayConfig, model, 5)
	if err != nil {
		t.Fatal(err)
	}
	runtimePolicy["deadlineSeconds"] = 2
	temp := t.TempDir()
	runtimePath := filepath.Join(temp, "runtime.json")
	scriptPath := filepath.Join(temp, "model-relay.mjs")
	receiptPath := filepath.Join(temp, "receipt.json")
	runtimeData, _ := json.Marshal(map[string]any{"modelRelay": runtimePolicy})
	if err := os.WriteFile(runtimePath, runtimeData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, []byte(modelRelayScript), 0o500); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command := exec.Command(node, scriptPath, runtimePath, receiptPath, "exercise")
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := receiptPath + ".ready"
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(ready); err != nil {
		t.Fatalf("relay did not become ready: %v, stderr=%s", err, stderr.String())
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Second}
	baseURL := "http://" + relayAddress
	do := func(method, route, body string) int {
		t.Helper()
		request, err := http.NewRequest(method, baseURL+route, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("content-type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return response.StatusCode
	}
	validBody := `{"model":"fixture-model","messages":[]}`
	if got := do(http.MethodPost, policy.AllowedPath, validBody); got != http.StatusOK {
		t.Fatalf("valid request status = %d", got)
	}
	if got := do(http.MethodGet, policy.AllowedPath, ""); got != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d", got)
	}
	if got := do(http.MethodPost, policy.AllowedPath+"?next=/admin", `{"model":"fixture-model"}`); got != http.StatusNotFound {
		t.Fatalf("query route status = %d", got)
	}
	wrongModelBody := `{"model":"other","padding":"` + strings.Repeat("x", 900) + `"}`
	for attempt := 0; attempt < 2; attempt++ {
		if got := do(http.MethodPost, policy.AllowedPath, wrongModelBody); got != http.StatusBadRequest {
			t.Fatalf("wrong model attempt %d status = %d", attempt+1, got)
		}
	}
	if got := do(http.MethodPost, policy.AllowedPath, wrongModelBody); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("cumulative rejected-body status = %d", got)
	}
	if got := do(http.MethodPost, policy.AllowedPath, `{"model":"fixture-model","padding":"`+strings.Repeat("x", 2048)+`"}`); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d", got)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		if err != nil {
			t.Fatalf("relay exited with %v: %s", err, stderr.String())
		}
	case <-time.After(4 * time.Second):
		t.Fatal("relay did not exit at its bounded deadline")
	}
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := parseModelRelayReceipt(data)
	if err != nil {
		t.Fatal(err)
	}
	expectedRequestBytes := int64(len(validBody) + 2*len(wrongModelBody))
	if receipt.AcceptedRequests != 1 || receipt.RejectedRequests != 6 || receipt.RequestBytes != expectedRequestBytes || receipt.ResponseBytes == 0 || upstreamCalls.Load() != 1 || receipt.DeadlineHit {
		t.Fatalf("receipt=%#v upstreamCalls=%d", receipt, upstreamCalls.Load())
	}
}
