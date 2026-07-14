package proxmox

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMiniMaxSecretRelayLifecycleIsCompletionOrScanDeadlineBound(t *testing.T) {
	script, err := os.ReadFile("minimax-secret-relay.mjs")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, forbidden := range []string{"idleTimeout", "armIdleTimer", "startupTimeoutMs"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("relay retains premature lifecycle trigger %q", forbidden)
		}
	}
	for _, required := range []string{"OBSERVATORY_RELAY_DEADLINE_SECONDS", "fs.existsSync(donePath)", "shutdown(true)"} {
		if !strings.Contains(text, required) {
			t.Fatalf("relay missing lifecycle control %q", required)
		}
	}
}

func TestGatedPipelineBindsAndRejectsRelayDeadline(t *testing.T) {
	script, err := os.ReadFile("run-gated-observatory.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, required := range []string{
		"--print-scan-budget-seconds",
		"OBSERVATORY_RELAY_DEADLINE_SECONDS=\"$relay_deadline_seconds\"",
		".deadlineHit | booleans",
		"$relay_deadline_hit\" != \"false",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("gated pipeline missing relay deadline guard %q", required)
		}
	}
}

func TestMiniMaxSecretRelayRejectsMissingDerivedDeadline(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	dir := t.TempDir()
	command := exec.Command(node, "minimax-secret-relay.mjs")
	command.Env = []string{
		"OBSERVATORY_RELAY_LISTEN=127.0.0.1:19091",
		"OBSERVATORY_MINIMAX_API_KEY=fixture",
		"OBSERVATORY_RELAY_RECEIPT=" + filepath.Join(dir, "receipt.json"),
		"OBSERVATORY_RELAY_DONE_FILE=" + filepath.Join(dir, "done"),
	}
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "scan-derived deadline") {
		t.Fatalf("missing deadline err = %v output = %q", err, output)
	}
	if _, err := os.Stat(filepath.Join(dir, "receipt.json")); !os.IsNotExist(err) {
		t.Fatalf("missing-deadline relay wrote a receipt: %v", err)
	}
}

func TestMiniMaxSecretRelayReservesRequestCapBeforeReadingBodies(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	receiptPath := filepath.Join(dir, "receipt.json")
	readyPath := receiptPath + ".ready"
	command := exec.Command(node, "minimax-secret-relay.mjs")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	command.Env = []string{
		"OBSERVATORY_RELAY_LISTEN=127.0.0.1:" + strconv.Itoa(port),
		"OBSERVATORY_MINIMAX_API_KEY=fixture",
		"OBSERVATORY_RELAY_RECEIPT=" + receiptPath,
		"OBSERVATORY_RELAY_DONE_FILE=" + filepath.Join(dir, "done"),
		"OBSERVATORY_RELAY_MAX_REQUESTS=1",
		"OBSERVATORY_RELAY_DEADLINE_SECONDS=3",
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = command.Wait()
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			if waitErr := command.Wait(); waitErr != nil {
				t.Fatalf("relay did not become ready: %v", waitErr)
			}
			t.Fatal("relay exited without becoming ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	address := "127.0.0.1:" + strconv.Itoa(port)
	first, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(first, "POST /v1/chat/completions HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer local\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)

	second, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(second, "GET /v1/chat/completions HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(response), " 429 ") || !strings.Contains(string(response), "request cap reached") {
		t.Fatalf("second concurrent request bypassed the cap: %q", response)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("relay exit: %v output=%q", err, output.String())
	}
	waited = true
	receiptJSON, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		AcceptedRequests int  `json:"acceptedRequests"`
		DeadlineHit      bool `json:"deadlineHit"`
	}
	if err := json.Unmarshal(receiptJSON, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.AcceptedRequests != 0 || receipt.DeadlineHit {
		t.Fatalf("relay forwarded or timed out after enforcing its cap: %s", receiptJSON)
	}
}
