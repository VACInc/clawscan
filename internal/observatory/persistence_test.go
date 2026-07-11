package observatory

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyPersistenceSurfaceCoversAgentAndUserSurfaces(t *testing.T) {
	cases := []struct {
		subject  string
		surface  string
		category string
	}{
		{"$STATE/openclaw.json", "openclaw-config", "agent-config"},
		{"$STATE/hooks/on-start.json", "openclaw-hooks", "agent-hooks"},
		{"$STATE/mcp.json", "openclaw-mcp", "agent-mcp"},
		{"$STATE/plugins/registry.json", "openclaw-plugins", "agent-plugins"},
		{"$STATE/skills/index.json", "openclaw-skills", "agent-skills"},
		{"$STATE/schedules/daily.json", "openclaw-schedules", "agent-scheduled"},
		{"$STATE/sessions/latest.json", "openclaw-state", "agent-state"},
		{"$HOME/.config/openclaw/config.json", "openclaw-home-config", "agent-config"},
		{"$WORKSPACE/SOUL.md", "agent-startup-instructions", "startup-instruction"},
		{"$WORKSPACE/memory/private.md", "agent-startup-instructions", "startup-instruction"},
		{"$HOME/.bashrc", "shell-init", "shell-init"},
		{"$HOME/.config/autostart/agent.desktop", "xdg-autostart", "login-autostart"},
		{"$HOME/.config/systemd/user/agent.service", "systemd-user-unit", "login-autostart"},
		{"$HOME/.ssh/authorized_keys", "ssh-trust", "ssh-trust"},
		{"$HOME/.local/bin/helper", "user-path-binary", "search-path"},
		{"/etc/cron.d/agent", "system-cron", "scheduled-task"},
		{"/etc/systemd/system/agent.service", "system-systemd-unit", "login-autostart"},
		{"/etc/profile.d/agent.sh", "system-shell-init", "shell-init"},
		{"/etc/ld.so.preload", "loader-preload", "loader-preload"},
		{"/etc/rc.local", "system-init", "system-init"},
	}
	for _, test := range cases {
		surface, ok := classifyPersistenceSurface(test.subject)
		if !ok || surface.ID != test.surface || surface.Category != test.category {
			t.Fatalf("classify %q = %+v (ok=%v), want surface %q category %q", test.subject, surface, ok, test.surface, test.category)
		}
	}
	for _, subject := range []string{
		"$SKILL/scripts/run.sh", "$PLUGIN/index.js", "$WORKSPACE/probe.json",
		"$HOME/.aws/credentials", "$HOME/notes.txt", "/tmp/scratch", "/usr/bin/node", "",
	} {
		if surface, ok := classifyPersistenceSurface(subject); ok {
			t.Fatalf("classify %q unexpectedly matched surface %q", subject, surface.ID)
		}
	}
}

func TestPersistenceCatalogIsSelfConsistentAndSorted(t *testing.T) {
	catalog := persistenceSurfaceCatalog()
	if len(catalog) != len(persistenceSurfaces) {
		t.Fatalf("catalog has %d surfaces, definitions have %d", len(catalog), len(persistenceSurfaces))
	}
	for index := 1; index < len(catalog); index++ {
		if catalog[index-1].ID >= catalog[index].ID {
			t.Fatalf("catalog is not sorted by ID at %d: %q >= %q", index, catalog[index-1].ID, catalog[index].ID)
		}
	}
	// The published catalog must satisfy the same validation the evidence uses.
	evidence := PersistenceEvidence{Scope: persistenceScope, Surfaces: catalog, Findings: []PersistenceFinding{}, Limitations: []string{"limit"}}
	if err := validatePersistenceEvidence(evidence); err != nil {
		t.Fatalf("canonical catalog failed validation: %v", err)
	}
}

func TestAnalyzePersistenceDistinguishesAttemptedAndResidual(t *testing.T) {
	observations := []Observation{
		{Kind: "file", Operation: "open-for-write", Subject: "$HOME/.bashrc", Outcome: "succeeded", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1},
		{Kind: "file", Operation: "open-for-write", Subject: "/etc/cron.d/agent", Outcome: "attempted", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1},
		{Kind: "file", Operation: "open-for-write", Subject: "$STATE/openclaw.json", Outcome: "succeeded", BaselineCount: 0, ExerciseCount: 2, DeltaCount: 2},
		// Reads and non-persistence writes must not become persistence findings.
		{Kind: "file", Operation: "open-for-read", Subject: "$HOME/.bashrc", Outcome: "succeeded", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1},
		{Kind: "file", Operation: "open-for-write", Subject: "$WORKSPACE/probe.json", Outcome: "succeeded", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1},
		{Kind: "process", Operation: "execute", Subject: "node", Outcome: "succeeded", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1},
	}
	diff := inventoryDiff{Paired: true, Residues: []inventoryResidue{
		{Subject: "$HOME/.bashrc", Change: "added"},
		// A residual with no matching syscall (mutation via an untraced mechanism).
		{Subject: "$HOME/.config/systemd/user/agent.service", Change: "added"},
	}}
	persistence := analyzePersistence(observations, diff)
	if persistence.Scope != persistenceScope || !persistence.InventoryPaired {
		t.Fatalf("persistence scope/paired = %#v", persistence)
	}
	bashrc := findPersistenceFinding(persistence.Findings, "shell-init", "$HOME/.bashrc")
	if bashrc.Outcome != "succeeded" || bashrc.Residual != "confirmed" || bashrc.Evidence != "syscall+inventory" || bashrc.DeltaCount != 1 {
		t.Fatalf("bashrc finding = %#v", bashrc)
	}
	cron := findPersistenceFinding(persistence.Findings, "system-cron", "/etc/cron.d/agent")
	if cron.Outcome != "attempted" || cron.Residual != "unavailable" || cron.Evidence != "syscall" {
		t.Fatalf("cron finding = %#v", cron)
	}
	state := findPersistenceFinding(persistence.Findings, "openclaw-config", "$STATE/openclaw.json")
	if state.Outcome != "succeeded" || state.Residual != "not-observed" || state.Evidence != "syscall" {
		t.Fatalf("state finding (succeeded write, no residue) = %#v", state)
	}
	systemd := findPersistenceFinding(persistence.Findings, "systemd-user-unit", "$HOME/.config/systemd/user/agent.service")
	if systemd.Outcome != "succeeded" || systemd.Residual != "confirmed" || systemd.Evidence != "inventory" || systemd.Operation != "create" {
		t.Fatalf("inventory-only finding = %#v", systemd)
	}
	for _, finding := range persistence.Findings {
		if finding.Subject == "$WORKSPACE/probe.json" || finding.Subject == "node" {
			t.Fatalf("non-persistence subject leaked into findings: %#v", finding)
		}
		if finding.Operation == "open-for-read" {
			t.Fatalf("read operation became a persistence finding: %#v", finding)
		}
	}
	if err := validatePersistenceEvidence(persistence); err != nil {
		t.Fatalf("analyzed persistence failed validation: %v", err)
	}
}

func TestAnalyzePersistenceWithoutInventoryMarksResidualUnavailable(t *testing.T) {
	observations := []Observation{
		{Kind: "file", Operation: "open-for-write", Subject: "$HOME/.bashrc", Outcome: "succeeded", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1},
	}
	persistence := analyzePersistence(observations, inventoryDiff{Paired: false})
	if persistence.InventoryPaired {
		t.Fatalf("inventory should be unpaired: %#v", persistence)
	}
	finding := findPersistenceFinding(persistence.Findings, "shell-init", "$HOME/.bashrc")
	if finding.Residual != "unavailable" || finding.Evidence != "syscall" {
		t.Fatalf("finding without inventory = %#v", finding)
	}
}

func TestDiffLaneInventoriesSubtractsBaselineNoise(t *testing.T) {
	baseline := laneInventory{
		Present: true,
		Before:  map[string]inventoryEntry{"state/openclaw.json": {Mode: "0600", SHA256: "aaa"}},
		After:   map[string]inventoryEntry{"state/openclaw.json": {Mode: "0600", SHA256: "bbb"}},
	}
	exercise := laneInventory{
		Present: true,
		Before:  map[string]inventoryEntry{"state/openclaw.json": {Mode: "0600", SHA256: "ccc"}},
		After: map[string]inventoryEntry{
			"state/openclaw.json": {Mode: "0600", SHA256: "ddd"},
			"home/.bashrc":        {Mode: "0600", SHA256: "eee"},
		},
	}
	diff := diffLaneInventories(baseline, exercise)
	if !diff.Paired {
		t.Fatal("diff should be paired")
	}
	// openclaw.json is modified in both lanes (runtime noise) and must cancel;
	// only the exercise-only .bashrc addition survives.
	if len(diff.Residues) != 1 || diff.Residues[0].Subject != "$HOME/.bashrc" || diff.Residues[0].Change != "added" {
		t.Fatalf("residues = %#v", diff.Residues)
	}
}

func TestDiffLaneInventoriesExcludesTargetDirectory(t *testing.T) {
	exercise := laneInventory{
		Present: true,
		Before:  map[string]inventoryEntry{},
		After: map[string]inventoryEntry{
			"workspace/skills/observed/extra.txt": {Mode: "0600", SHA256: "aaa"},
			"home/.profile":                       {Mode: "0600", SHA256: "bbb"},
		},
	}
	baseline := laneInventory{Present: true, Before: map[string]inventoryEntry{}, After: map[string]inventoryEntry{}}
	diff := diffLaneInventories(baseline, exercise)
	if len(diff.Residues) != 1 || diff.Residues[0].Subject != "$HOME/.profile" {
		t.Fatalf("target-directory residue leaked: %#v", diff.Residues)
	}
}

func TestValidatePersistenceEvidenceRejectsInconsistentResidual(t *testing.T) {
	base := func() PersistenceEvidence {
		return PersistenceEvidence{
			Scope:       persistenceScope,
			Surfaces:    persistenceSurfaceCatalog(),
			Findings:    []PersistenceFinding{},
			Limitations: []string{"limit"},
		}
	}
	tests := []struct {
		name    string
		finding PersistenceFinding
		want    string
	}{
		{
			name:    "confirmed without inventory",
			finding: PersistenceFinding{Surface: "shell-init", Category: "shell-init", Operation: "write", Subject: "$HOME/.bashrc", Outcome: "succeeded", Evidence: "syscall", Residual: "confirmed", ExerciseCount: 1, DeltaCount: 1},
			want:    "residual state is inconsistent",
		},
		{
			name:    "inventory-backed but attempted",
			finding: PersistenceFinding{Surface: "shell-init", Category: "shell-init", Operation: "write", Subject: "$HOME/.bashrc", Outcome: "attempted", Evidence: "syscall+inventory", Residual: "confirmed", ExerciseCount: 1, DeltaCount: 1},
			want:    "must record a succeeded outcome",
		},
		{
			name:    "unknown surface",
			finding: PersistenceFinding{Surface: "not-a-surface", Category: "shell-init", Operation: "write", Subject: "$HOME/.bashrc", Outcome: "succeeded", Evidence: "syscall", Residual: "unavailable", ExerciseCount: 1, DeltaCount: 1},
			want:    "unknown surface",
		},
		{
			name:    "bad delta",
			finding: PersistenceFinding{Surface: "shell-init", Category: "shell-init", Operation: "write", Subject: "$HOME/.bashrc", Outcome: "succeeded", Evidence: "syscall", Residual: "unavailable", BaselineCount: 1, ExerciseCount: 1, DeltaCount: 0},
			want:    "invalid persistence finding count",
		},
		{
			name:    "leaked canary subject",
			finding: PersistenceFinding{Surface: "shell-init", Category: "shell-init", Operation: "write", Subject: "$HOME/OBS-CANARY-abc", Outcome: "succeeded", Evidence: "syscall", Residual: "unavailable", ExerciseCount: 1, DeltaCount: 1},
			want:    "invalid persistence finding subject",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := base()
			evidence.Findings = []PersistenceFinding{test.finding}
			if err := validatePersistenceEvidence(evidence); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseLaneInventoryRejectsMalformedSnapshots(t *testing.T) {
	good := "0600\t" + strings.Repeat("a", 64) + "\tstate/openclaw.json\n"
	if inventory := parseLaneInventory([]byte(good), []byte(good)); !inventory.Present || len(inventory.Before) != 1 {
		t.Fatalf("valid inventory not parsed: %#v", inventory)
	}
	if inventory := parseLaneInventory([]byte(good), nil); inventory.Present {
		t.Fatal("missing after-snapshot should be unpaired")
	}
	for _, bad := range []string{
		"7778\tdigest\tstate/openclaw.json\n",           // invalid mode
		"0600\t\tstate/openclaw.json\n",                 // empty digest
		"0600\tdigest\t../escape\n",                     // traversal
		"0600\tdigest\t/etc/passwd\n",                   // absolute
		"0600\tdigest\tstate/x\n0600\tother\tstate/x\n", // duplicate path
		"only-one-field\n",                              // too few fields
	} {
		if inventory := parseLaneInventory([]byte(bad), []byte(good)); inventory.Present {
			t.Fatalf("malformed snapshot accepted: %q", bad)
		}
	}
	// Informational markers and blank lines are skipped, not rejected.
	withMarker := good + "# truncated\n\n"
	if inventory := parseLaneInventory([]byte(withMarker), []byte(good)); !inventory.Present || len(inventory.Before) != 1 {
		t.Fatalf("marker/blank handling failed: %#v", inventory)
	}
}

func TestRemoteRunScriptCapturesBeforeAndAfterInventory(t *testing.T) {
	for _, required := range []string{
		`as_root install -m 0600 "$STAGED_RUNNER/inventory.mjs" "$CONTROL/inventory.mjs"`,
		`as_root node "$CONTROL/inventory.mjs" "$root" "$trace_dir/inventory.before"`,
		`as_root node "$CONTROL/inventory.mjs" "$root" "$trace_dir/inventory.after"`,
	} {
		if !strings.Contains(remoteRunScript, required) {
			t.Fatalf("remote runner missing inventory wiring %q", required)
		}
	}
	path := filepath.Join(t.TempDir(), "run.sh")
	if err := os.WriteFile(path, []byte(remoteRunScript), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("run.sh syntax: %v: %s", err, output)
	}
}

func TestInventoryScriptSnapshotsPersistenceSurfaces(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for inventory snapshot validation")
	}
	lane := t.TempDir()
	mustWrite := func(rel string, data string) {
		full := filepath.Join(lane, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("state/openclaw.json", "{}\n")
	mustWrite("home/.bashrc", "export PATH=$PATH\n")
	mustWrite("home/.config/systemd/user/agent.service", "[Service]\n")
	mustWrite("workspace/SOUL.md", "identity\n")
	// A file under the staged skill directory must be excluded from the snapshot.
	mustWrite("workspace/skills/observed/run.sh", "#!/bin/sh\n")
	// A target-controlled filename with an embedded newline must not forge or split
	// an inventory line; the control-character guard skips it entirely.
	injectedName := "home/.config/x\n0600\t" + strings.Repeat("f", 64) + "\t/etc/cron.d/forged"
	mustWrite(injectedName, "boom\n")

	scriptPath := filepath.Join(t.TempDir(), "inventory.mjs")
	if err := os.WriteFile(scriptPath, []byte(inventoryScript), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "inventory.before")
	if output, err := exec.Command(node, scriptPath, lane, outputPath).CombinedOutput(); err != nil {
		t.Fatalf("inventory.mjs: %v: %s", err, output)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	entries, ok := parseInventorySnapshot(data)
	if !ok {
		t.Fatalf("inventory snapshot did not parse: %q", data)
	}
	if strings.Contains(string(data), "/etc/cron.d/forged") {
		t.Fatalf("control-character filename forged an inventory line: %q", data)
	}
	for _, expected := range []string{"state/openclaw.json", "home/.bashrc", "home/.config/systemd/user/agent.service", "workspace/SOUL.md"} {
		if _, present := entries[expected]; !present {
			t.Fatalf("inventory missing %q: %q", expected, data)
		}
	}
	for path := range entries {
		if strings.HasPrefix(path, "workspace/skills/") {
			t.Fatalf("inventory included staged target path %q", path)
		}
	}
	// The snapshot must classify against the same normalized subjects the
	// analyzer uses, and must not embed file contents.
	if strings.Contains(string(data), "export PATH") {
		t.Fatalf("inventory leaked file contents: %q", data)
	}
	if subject := normalizeInventoryPath("home/.bashrc"); subject != "$HOME/.bashrc" {
		t.Fatalf("normalizeInventoryPath = %q", subject)
	}
}

func TestRenderSiteShowsPersistenceFindings(t *testing.T) {
	requireLinuxControlHost(t)
	evidence := fixtureEvidence()
	evidence.Persistence.InventoryPaired = true
	evidence.Persistence.Findings = []PersistenceFinding{
		{Surface: "shell-init", Category: "shell-init", Operation: "write", Subject: "$HOME/.bashrc", Outcome: "succeeded", Evidence: "syscall+inventory", Residual: "confirmed", ExerciseCount: 1, DeltaCount: 1},
		{Surface: "system-cron", Category: "scheduled-task", Operation: "write", Subject: "/etc/cron.d/agent", Outcome: "attempted", Evidence: "syscall", Residual: "unavailable", ExerciseCount: 1, DeltaCount: 1},
	}
	output := t.TempDir()
	if err := RenderSite(output, evidence, nil); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(output, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	for _, expected := range []string{"Persistence and lifecycle", "$HOME/.bashrc", "/etc/cron.d/agent", "confirmed", "attempted", "Persistence deltas"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("HTML missing %q", expected)
		}
	}
}

func TestBuildEvidencePersistenceSurvivesJSONRoundTrip(t *testing.T) {
	evidence := fixtureEvidence()
	evidence.Persistence.Findings = []PersistenceFinding{
		{Surface: "openclaw-hooks", Category: "agent-hooks", Operation: "write", Subject: "$STATE/hooks/on-start.json", Outcome: "succeeded", Evidence: "inventory", Residual: "confirmed", ExerciseCount: 1, DeltaCount: 1},
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Evidence
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEvidence(decoded); err != nil {
		t.Fatalf("round-tripped evidence failed validation: %v", err)
	}
	if len(decoded.Persistence.Findings) != 1 || decoded.Persistence.Findings[0].Surface != "openclaw-hooks" {
		t.Fatalf("decoded persistence = %#v", decoded.Persistence)
	}
}
