package observatory

import (
	"bytes"
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

// sharedPathNoiseInventories models baseline and exercise both modifying the
// same OpenClaw state path (runtime noise) while the exercise lane also adds a
// user shell-init file. Content digests differ per lane, as they do for the
// seeded, timestamped config.
func sharedPathNoiseInventories() (laneInventory, laneInventory) {
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
	return baseline, exercise
}

func TestDiffLaneInventoriesRetainsFullExerciseResiduesAndBaselineNoise(t *testing.T) {
	baseline, exercise := sharedPathNoiseInventories()
	diff := diffLaneInventories(baseline, exercise)
	if !diff.Paired {
		t.Fatal("diff should be paired")
	}
	// The full exercise residue set is retained (not pre-subtracted) so syscall
	// correlation can still confirm target changes to shared paths.
	if len(diff.Residues) != 2 {
		t.Fatalf("residues = %#v", diff.Residues)
	}
	if _, noise := diff.baselineNoise[inventoryNoiseKey(inventoryResidue{Subject: "$STATE/openclaw.json", Change: "modified", beforeMode: "0600", afterMode: "0600"})]; !noise {
		t.Fatalf("baseline noise key missing: %#v", diff.baselineNoise)
	}
}

func TestAnalyzePersistenceSubtractsEquivalentBaselineNoise(t *testing.T) {
	baseline, exercise := sharedPathNoiseInventories()
	// No syscall observations: openclaw.json changed only via runtime in both
	// lanes and must be suppressed; the exercise-only .bashrc addition survives.
	persistence := analyzePersistence(nil, diffLaneInventories(baseline, exercise))
	if state := findPersistenceFinding(persistence.Findings, "openclaw-config", "$STATE/openclaw.json"); state.Surface != "" {
		t.Fatalf("equivalent baseline noise was not subtracted: %#v", state)
	}
	if bashrc := findPersistenceFinding(persistence.Findings, "shell-init", "$HOME/.bashrc"); bashrc.Evidence != "inventory" || bashrc.Residual != "confirmed" || bashrc.Operation != "create" {
		t.Fatalf("exercise-only residue = %#v", bashrc)
	}
}

func TestAnalyzePersistenceConfirmsTargetChangeToSharedPath(t *testing.T) {
	baseline, exercise := sharedPathNoiseInventories()
	// The target writes openclaw.json in the exercise lane (a baseline-subtracted
	// succeeded syscall delta). Even though the baseline runtime also modified the
	// same path, the exercise inventory residue must still confirm the change.
	observations := []Observation{
		{Kind: "file", Operation: "open-for-write", Subject: "$STATE/openclaw.json", Outcome: "succeeded", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1},
	}
	persistence := analyzePersistence(observations, diffLaneInventories(baseline, exercise))
	state := findPersistenceFinding(persistence.Findings, "openclaw-config", "$STATE/openclaw.json")
	if state.Outcome != "succeeded" || state.Residual != "confirmed" || state.Evidence != "syscall+inventory" {
		t.Fatalf("target change to shared path was hidden: %#v", state)
	}
	// The residue is consumed by the syscall finding; no duplicate inventory-only
	// finding is emitted for the same path.
	occurrences := 0
	for _, finding := range persistence.Findings {
		if finding.Subject == "$STATE/openclaw.json" {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Fatalf("expected a single openclaw.json finding, got %d: %#v", occurrences, persistence.Findings)
	}
}

func TestAnalyzePersistenceReportsModeOnlyResidualDifference(t *testing.T) {
	// Baseline leaves .bashrc mode unchanged; the exercise target makes it
	// world-executable. The mode transition differs, so it is not equivalent
	// baseline noise and must surface even without a correlated syscall.
	baseline := laneInventory{
		Present: true,
		Before:  map[string]inventoryEntry{"home/.bashrc": {Mode: "0600", SHA256: "aaa"}},
		After:   map[string]inventoryEntry{"home/.bashrc": {Mode: "0600", SHA256: "bbb"}},
	}
	exercise := laneInventory{
		Present: true,
		Before:  map[string]inventoryEntry{"home/.bashrc": {Mode: "0600", SHA256: "aaa"}},
		After:   map[string]inventoryEntry{"home/.bashrc": {Mode: "0755", SHA256: "ccc"}},
	}
	persistence := analyzePersistence(nil, diffLaneInventories(baseline, exercise))
	if bashrc := findPersistenceFinding(persistence.Findings, "shell-init", "$HOME/.bashrc"); bashrc.Residual != "confirmed" || bashrc.Evidence != "inventory" {
		t.Fatalf("mode-only residual difference was hidden: %#v", bashrc)
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

func TestPersistenceEvidenceNeverPublishesPrivateDigests(t *testing.T) {
	secret := strings.Repeat("f", 64)
	baseline := laneInventory{Present: true, Before: map[string]inventoryEntry{}, After: map[string]inventoryEntry{}}
	exercise := laneInventory{
		Present: true,
		Before:  map[string]inventoryEntry{},
		After:   map[string]inventoryEntry{"home/.bashrc": {Mode: "0600", SHA256: secret}},
	}
	persistence := analyzePersistence(nil, diffLaneInventories(baseline, exercise))
	data, err := json.Marshal(persistence)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("published persistence evidence leaked a private inventory digest: %s", data)
	}
}

func TestReadLaneInventoryFailsClosedOnIncompleteReceipts(t *testing.T) {
	good := "0600\t" + strings.Repeat("a", 64) + "\tstate/openclaw.json\n"
	entries := func(before string, after string) map[string][]byte {
		m := map[string][]byte{}
		if before != "" {
			m["exercise/inventory.before"] = []byte(before)
		}
		if after != "" {
			m["exercise/inventory.after"] = []byte(after)
		}
		return m
	}
	inventory, err := readLaneInventory(entries(good, good), "exercise")
	if err != nil || !inventory.Present || len(inventory.Before) != 1 {
		t.Fatalf("valid inventory not parsed: %#v err=%v", inventory, err)
	}
	// A present-but-empty snapshot is complete (no monitored surfaces exist yet).
	if empty, err := readLaneInventory(map[string][]byte{"exercise/inventory.before": {}, "exercise/inventory.after": {}}, "exercise"); err != nil || !empty.Present {
		t.Fatalf("empty snapshot rejected: %#v err=%v", empty, err)
	}
	if _, err := readLaneInventory(entries(good, ""), "exercise"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing after-snapshot err = %v", err)
	}
	badCases := map[string]string{
		"invalid mode":     "7778\tdigest\tstate/openclaw.json\n",
		"empty digest":     "0600\t\tstate/openclaw.json\n",
		"traversal":        "0600\tdigest\t../escape\n",
		"absolute":         "0600\tdigest\t/etc/passwd\n",
		"duplicate path":   "0600\tdigest\tstate/x\n0600\tother\tstate/x\n",
		"too few fields":   "only-one-field\n",
		"truncated marker": good + "# truncated\n",
		"unknown marker":   good + "# note something\n",
	}
	for name, bad := range badCases {
		t.Run(name, func(t *testing.T) {
			if _, err := readLaneInventory(entries(bad, good), "exercise"); err == nil {
				t.Fatalf("incomplete snapshot accepted: %q", bad)
			}
		})
	}
}

func TestReadCaptureBundleRejectsIncompleteInventory(t *testing.T) {
	base := func() map[string]string {
		return fixtureBundleEntries("obs_inventory", "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "skill", "")
	}
	tests := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{name: "missing", mutate: func(m map[string]string) { delete(m, "exercise/inventory.after") }, want: "missing the exercise persistence inventory"},
		{name: "truncated", mutate: func(m map[string]string) { m["baseline/inventory.before"] += "# truncated\n" }, want: "baseline before-inventory is invalid: incomplete inventory marker"},
		{name: "malformed", mutate: func(m map[string]string) { m["exercise/inventory.before"] = "not-a-valid-line\n" }, want: "exercise before-inventory is invalid: malformed inventory line"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := base()
			test.mutate(entries)
			path := filepath.Join(t.TempDir(), "capture.tar.gz")
			if err := writeTestBundle(path, entries); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadCaptureBundle(path, 1<<20); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRemoteRunScriptCapturesBeforeAndAfterInventory(t *testing.T) {
	for _, required := range []string{
		`as_root install -m 0555 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/inventory.mjs" "$CONTROL/inventory.mjs"`,
		`run_inventory "$lane" "$root" before`,
		`run_inventory "$lane" "$root" after`,
		`--property="User=$AGENT_USER"`,
		`--property=CapabilityBoundingSet=`,
		`--property=PrivateNetwork=yes`,
		`--property=ProtectSystem=strict`,
		`--property=MemoryMax=134217728`,
		`--property=MemorySwapMax=0`,
		`--property=TasksMax=16`,
		`--property=LimitFSIZE=8388608`,
		`--property="ReadOnlyPaths=$root $CONTROL/inventory.mjs"`,
		`node "$CONTROL/inventory.mjs" "$root" -`,
	} {
		if !strings.Contains(remoteRunScript, required) {
			t.Fatalf("remote runner missing inventory wiring %q", required)
		}
	}
	if strings.Contains(remoteRunScript, `as_root node "$CONTROL/inventory.mjs"`) {
		t.Fatal("remote runner still launches persistence inventory as unconstrained root Node")
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
	entries, err := parseInventorySnapshot(data)
	if err != nil {
		t.Fatalf("inventory snapshot did not parse: %v: %q", err, data)
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

func TestInventoryScriptFailsClosedOnUnrepresentableTraversal(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for inventory traversal validation")
	}
	lane := t.TempDir()
	configDir := filepath.Join(lane, "home", ".config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	injectedName := "x\n0600\t" + strings.Repeat("f", 64) + "\tetc-cron-forged"
	if err := os.WriteFile(filepath.Join(configDir, injectedName), []byte("boom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(t.TempDir(), "inventory.mjs")
	if err := os.WriteFile(scriptPath, []byte(inventoryScript), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(node, scriptPath, lane, "-").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte("# truncated\n")) {
		t.Fatalf("unrepresentable path did not mark inventory incomplete: %q", output)
	}
	if _, err := parseInventorySnapshot(output); err == nil || !strings.Contains(err.Error(), "incomplete inventory marker") {
		t.Fatalf("inventory did not fail closed: %v", err)
	}
	if bytes.Contains(output, []byte("etc-cron-forged")) {
		t.Fatalf("unrepresentable filename leaked into inventory output: %q", output)
	}
}

func TestInventoryScriptFailsClosedOnUnreadableSurface(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for inventory permission validation")
	}
	lane := t.TempDir()
	stateDir := filepath.Join(lane, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(stateDir, "openclaw.json")
	if err := os.WriteFile(protected, []byte("{}\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(protected, 0o600) })
	scriptPath := filepath.Join(t.TempDir(), "inventory.mjs")
	if err := os.WriteFile(scriptPath, []byte(inventoryScript), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(node, scriptPath, lane, "-").Output()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseInventorySnapshot(output); err == nil || !strings.Contains(err.Error(), "incomplete inventory marker") {
		t.Fatalf("unreadable persistence surface did not fail closed: %v, output=%q", err, output)
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
