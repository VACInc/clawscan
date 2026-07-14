package proxmox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	command.Env = append(os.Environ(),
		"OBSERVATORY_RELAY_LISTEN=127.0.0.1:19091",
		"OBSERVATORY_MINIMAX_API_KEY=fixture",
		"OBSERVATORY_RELAY_RECEIPT="+filepath.Join(dir, "receipt.json"),
		"OBSERVATORY_RELAY_DONE_FILE="+filepath.Join(dir, "done"),
	)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "scan-derived deadline") {
		t.Fatalf("missing deadline err = %v output = %q", err, output)
	}
	if _, err := os.Stat(filepath.Join(dir, "receipt.json")); !os.IsNotExist(err) {
		t.Fatalf("missing-deadline relay wrote a receipt: %v", err)
	}
}
