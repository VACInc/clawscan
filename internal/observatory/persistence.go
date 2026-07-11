package observatory

import (
	"regexp"
	"sort"
	"strings"
)

var persistenceSurfaceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// PersistenceProtocolRevision versions the persistence surface catalog and the
// inventory-diff semantics. It is folded into CaptureProtocolRevision so that a
// change to what counts as a persistence surface cannot silently mix evidence
// across protocol revisions.
const PersistenceProtocolRevision = "observatory.persistence.v1"

const persistenceScope = "selected-persistence-surfaces"

// persistenceSurfaceDefinition describes one monitored persistence surface. The
// match predicate runs against a normalized, redacted observation or inventory
// subject (for example "$STATE/openclaw.json" or "/etc/cron.d/agent"). Order is
// significant: classification returns the first surface whose match succeeds, so
// more specific agent surfaces precede broader agent-state and system fallbacks.
type persistenceSurfaceDefinition struct {
	ID          string
	Category    string
	Scope       string
	Description string
	match       func(subject string) bool
}

// persistenceSurfaces is the curated, deterministic catalog. It intentionally
// covers agent-specific OpenClaw surfaces (config, hooks, MCP, plugin/skill
// registrations, startup instructions, scheduled work) and a bounded set of
// conventional user and system persistence locations. It is not an exhaustive
// host persistence audit; the coverage limitations record that explicitly.
var persistenceSurfaces = []persistenceSurfaceDefinition{
	{
		ID: "openclaw-config", Category: "agent-config", Scope: "agent",
		Description: "OpenClaw agent configuration file in the state directory.",
		match:       func(s string) bool { return under(s, "$STATE/openclaw.json") },
	},
	{
		ID: "openclaw-hooks", Category: "agent-hooks", Scope: "agent",
		Description: "OpenClaw lifecycle hook registrations under the state directory.",
		match:       func(s string) bool { return under(s, "$STATE/hooks") },
	},
	{
		ID: "openclaw-mcp", Category: "agent-mcp", Scope: "agent",
		Description: "OpenClaw MCP server registrations under the state directory.",
		match: func(s string) bool {
			return under(s, "$STATE/mcp") || under(s, "$STATE/mcp.json")
		},
	},
	{
		ID: "openclaw-plugins", Category: "agent-plugins", Scope: "agent",
		Description: "OpenClaw plugin registrations under the state directory.",
		match:       func(s string) bool { return under(s, "$STATE/plugins") },
	},
	{
		ID: "openclaw-skills", Category: "agent-skills", Scope: "agent",
		Description: "OpenClaw skill registrations under the state directory.",
		match:       func(s string) bool { return under(s, "$STATE/skills") },
	},
	{
		ID: "openclaw-schedules", Category: "agent-scheduled", Scope: "agent",
		Description: "OpenClaw scheduled-work definitions under the state directory.",
		match: func(s string) bool {
			return under(s, "$STATE/schedules") || under(s, "$STATE/cron") || under(s, "$STATE/tasks")
		},
	},
	{
		ID: "openclaw-state", Category: "agent-state", Scope: "agent",
		Description: "Other OpenClaw state files that survive between sessions.",
		match:       func(s string) bool { return under(s, "$STATE") },
	},
	{
		ID: "openclaw-home-config", Category: "agent-config", Scope: "agent",
		Description: "OpenClaw agent configuration stored under the user home directory.",
		match: func(s string) bool {
			return under(s, "$HOME/.openclaw") || under(s, "$HOME/.config/openclaw") || under(s, "$HOME/.local/share/openclaw")
		},
	},
	{
		ID: "agent-startup-instructions", Category: "startup-instruction", Scope: "agent",
		Description: "Workspace startup-instruction files the agent reads at launch.",
		match: func(s string) bool {
			return under(s, "$WORKSPACE/SOUL.md") || under(s, "$WORKSPACE/AGENTS.md") ||
				under(s, "$WORKSPACE/CLAUDE.md") || under(s, "$WORKSPACE/memory") || under(s, "$WORKSPACE/.openclaw")
		},
	},
	{
		ID: "shell-init", Category: "shell-init", Scope: "user",
		Description: "User shell initialization files sourced on login or interactive shells.",
		match:       matchShellInit,
	},
	{
		ID: "xdg-autostart", Category: "login-autostart", Scope: "user",
		Description: "XDG desktop autostart entries in the user configuration directory.",
		match:       func(s string) bool { return under(s, "$HOME/.config/autostart") },
	},
	{
		ID: "systemd-user-unit", Category: "login-autostart", Scope: "user",
		Description: "systemd user units and timers that start work for the login user.",
		match:       func(s string) bool { return under(s, "$HOME/.config/systemd/user") },
	},
	{
		ID: "user-cron", Category: "scheduled-task", Scope: "user",
		Description: "User cron definitions in the home directory.",
		match: func(s string) bool {
			return under(s, "$HOME/.config/cron") || under(s, "$HOME/.crontab") || under(s, "$HOME/.cron")
		},
	},
	{
		ID: "ssh-trust", Category: "ssh-trust", Scope: "user",
		Description: "SSH trust and command surfaces such as authorized_keys and config.",
		match:       func(s string) bool { return under(s, "$HOME/.ssh") },
	},
	{
		ID: "user-path-binary", Category: "search-path", Scope: "user",
		Description: "Executables on the user PATH that later commands may resolve.",
		match:       func(s string) bool { return under(s, "$HOME/.local/bin") || under(s, "$HOME/bin") },
	},
	{
		ID: "system-cron", Category: "scheduled-task", Scope: "system",
		Description: "System cron locations (read-only in a contained scan).",
		match: func(s string) bool {
			return strings.HasPrefix(s, "/etc/cron") || under(s, "/var/spool/cron") || under(s, "/etc/anacrontab")
		},
	},
	{
		ID: "system-systemd-unit", Category: "login-autostart", Scope: "system",
		Description: "System-wide systemd units and timers (read-only in a contained scan).",
		match: func(s string) bool {
			return under(s, "/etc/systemd/system") || under(s, "/etc/systemd/user") ||
				under(s, "/usr/lib/systemd/system") || under(s, "/lib/systemd/system") || under(s, "/run/systemd/system")
		},
	},
	{
		ID: "system-shell-init", Category: "shell-init", Scope: "system",
		Description: "System-wide shell initialization files (read-only in a contained scan).",
		match: func(s string) bool {
			return under(s, "/etc/profile") || under(s, "/etc/profile.d") || under(s, "/etc/bash.bashrc") ||
				under(s, "/etc/bashrc") || under(s, "/etc/zsh") || under(s, "/etc/zprofile") || under(s, "/etc/zshrc")
		},
	},
	{
		ID: "system-xdg-autostart", Category: "login-autostart", Scope: "system",
		Description: "System-wide XDG autostart entries (read-only in a contained scan).",
		match:       func(s string) bool { return under(s, "/etc/xdg/autostart") },
	},
	{
		ID: "loader-preload", Category: "loader-preload", Scope: "system",
		Description: "Dynamic loader preload and search configuration (read-only in a contained scan).",
		match: func(s string) bool {
			return under(s, "/etc/ld.so.preload") || under(s, "/etc/ld.so.conf")
		},
	},
	{
		ID: "system-init", Category: "system-init", Scope: "system",
		Description: "Legacy init and rc startup locations (read-only in a contained scan).",
		match: func(s string) bool {
			return strings.HasPrefix(s, "/etc/rc") || under(s, "/etc/init.d") || under(s, "/etc/inittab")
		},
	},
}

var persistenceSurfaceByID = func() map[string]persistenceSurfaceDefinition {
	index := make(map[string]persistenceSurfaceDefinition, len(persistenceSurfaces))
	for _, surface := range persistenceSurfaces {
		index[surface.ID] = surface
	}
	return index
}()

// persistenceMutationOps maps mutating file operations to the persistence
// operation label published in evidence. Read-only operations (open-for-read,
// open-path) are intentionally absent: reading a persistence surface is not a
// persistence attempt.
var persistenceMutationOps = map[string]string{
	"open-for-write":      "write",
	"open-for-read-write": "write",
	"truncate":            "truncate",
	"create-directory":    "create-directory",
	"rename-to":           "rename-to",
	"link-to":             "link-to",
	"create-symlink":      "create-symlink",
	"delete":              "delete",
}

var persistenceOperationClass = map[string]string{
	"write":            "write",
	"truncate":         "write",
	"create-directory": "write",
	"rename-to":        "write",
	"link-to":          "write",
	"create-symlink":   "write",
	"delete":           "remove",
	"create":           "write",
}

func under(subject string, base string) bool {
	return subject == base || strings.HasPrefix(subject, base+"/")
}

func matchShellInit(subject string) bool {
	switch subject {
	case "$HOME/.bashrc", "$HOME/.bash_profile", "$HOME/.bash_login", "$HOME/.bash_logout",
		"$HOME/.profile", "$HOME/.zshrc", "$HOME/.zprofile", "$HOME/.zshenv", "$HOME/.zlogin", "$HOME/.kshrc":
		return true
	}
	return under(subject, "$HOME/.bashrc.d") || under(subject, "$HOME/.zshrc.d")
}

// classifyPersistenceSurface returns the catalog surface for a normalized
// subject, or the zero definition when the subject is not a monitored
// persistence surface. Target-owned paths ($SKILL, $PLUGIN) are never persistence
// surfaces; writes there are the target's own directory, not a residual mutation.
func classifyPersistenceSurface(subject string) (persistenceSurfaceDefinition, bool) {
	if subject == "" || strings.HasPrefix(subject, "$SKILL") || strings.HasPrefix(subject, "$PLUGIN") {
		return persistenceSurfaceDefinition{}, false
	}
	for _, surface := range persistenceSurfaces {
		if surface.match(subject) {
			return surface, true
		}
	}
	return persistenceSurfaceDefinition{}, false
}

func isInventoryScopedSubject(subject string) bool {
	return under(subject, "$HOME") || under(subject, "$STATE") || under(subject, "$WORKSPACE")
}

// persistenceSurfaceCatalog returns the published, sorted coverage catalog.
func persistenceSurfaceCatalog() []PersistenceSurface {
	catalog := make([]PersistenceSurface, 0, len(persistenceSurfaces))
	for _, surface := range persistenceSurfaces {
		catalog = append(catalog, PersistenceSurface{
			ID:          surface.ID,
			Category:    surface.Category,
			Scope:       surface.Scope,
			Description: surface.Description,
		})
	}
	sort.Slice(catalog, func(i, j int) bool { return catalog[i].ID < catalog[j].ID })
	return catalog
}

type inventoryResidue struct {
	Subject string
	Change  string // added | modified | removed
}

type inventoryDiff struct {
	Paired   bool
	Residues []inventoryResidue
}

// analyzePersistence correlates baseline-subtracted trace observations with a
// before/after lane inventory diff. Trace observations distinguish attempted
// (denied) from succeeded persistence operations; the inventory diff confirms
// which succeeded operations left a residual on-disk change. Inventory-only
// residues (surface changes with no matching traced syscall) are also reported.
func analyzePersistence(observations []Observation, diff inventoryDiff) PersistenceEvidence {
	residueByKey := map[string]inventoryResidue{}
	for _, residue := range diff.Residues {
		if _, ok := classifyPersistenceSurface(residue.Subject); !ok {
			continue
		}
		residueByKey[residueKey(residue.Subject, residue.Change)] = residue
	}
	consumed := map[string]bool{}

	findings := []PersistenceFinding{}
	for _, observation := range observations {
		if observation.Kind != "file" {
			continue
		}
		operation, mutating := persistenceMutationOps[observation.Operation]
		if !mutating {
			continue
		}
		surface, ok := classifyPersistenceSurface(observation.Subject)
		if !ok {
			continue
		}
		class := persistenceOperationClass[operation]
		key := observation.Subject + "\x00" + class
		evidenceKind := "syscall"
		residual := "unavailable"
		if observation.Outcome == "succeeded" {
			if _, matched := residueByKey[key]; matched {
				evidenceKind = "syscall+inventory"
				residual = "confirmed"
				consumed[key] = true
			} else if diff.Paired && isInventoryScopedSubject(observation.Subject) {
				residual = "not-observed"
			}
		} else if diff.Paired && isInventoryScopedSubject(observation.Subject) {
			residual = "not-observed"
		}
		findings = append(findings, PersistenceFinding{
			Surface:       surface.ID,
			Category:      surface.Category,
			Operation:     operation,
			Subject:       observation.Subject,
			Outcome:       observation.Outcome,
			Evidence:      evidenceKind,
			Residual:      residual,
			BaselineCount: observation.BaselineCount,
			ExerciseCount: observation.ExerciseCount,
			DeltaCount:    observation.DeltaCount,
		})
	}

	for key, residue := range residueByKey {
		if consumed[key] {
			continue
		}
		surface, _ := classifyPersistenceSurface(residue.Subject)
		findings = append(findings, PersistenceFinding{
			Surface:       surface.ID,
			Category:      surface.Category,
			Operation:     residueOperation(residue.Change),
			Subject:       residue.Subject,
			Outcome:       "succeeded",
			Evidence:      "inventory",
			Residual:      "confirmed",
			BaselineCount: 0,
			ExerciseCount: 1,
			DeltaCount:    1,
		})
	}

	sort.Slice(findings, func(i, j int) bool { return persistenceFindingKey(findings[i]) < persistenceFindingKey(findings[j]) })

	return PersistenceEvidence{
		Scope:           persistenceScope,
		InventoryPaired: diff.Paired,
		Surfaces:        persistenceSurfaceCatalog(),
		Findings:        findings,
		Limitations: []string{
			"Persistence coverage is a curated selection of agent and conventional user surfaces; it is not an exhaustive host persistence audit.",
			"Residual confirmation requires a paired before/after lane inventory; without it only traced syscall attempts are reported and residual is unavailable.",
			"Operations denied by the read-only OS or containment are labeled attempted; only inventory-confirmed changes are labeled residual: confirmed.",
			"A write to a persistence surface is a behavioral observation, not proof of author intent or a safety verdict.",
		},
	}
}

func residueKey(subject string, change string) string {
	return subject + "\x00" + residueClass(change)
}

func residueClass(change string) string {
	if change == "removed" {
		return "remove"
	}
	return "write"
}

func residueOperation(change string) string {
	switch change {
	case "added":
		return "create"
	case "removed":
		return "delete"
	default:
		return "write"
	}
}

func persistenceFindingKey(finding PersistenceFinding) string {
	return strings.Join([]string{finding.Surface, finding.Subject, finding.Operation, finding.Outcome, finding.Residual, finding.Evidence}, "\x00")
}

// diffLaneInventories subtracts baseline-lane residual changes from exercise-lane
// residual changes so that runtime noise (state the OpenClaw runtime itself
// rewrites in both lanes) does not surface as a target-attributed residue.
func diffLaneInventories(baseline laneInventory, exercise laneInventory) inventoryDiff {
	if !baseline.Present || !exercise.Present {
		return inventoryDiff{Paired: false}
	}
	baselineChanges := laneInventoryChanges(baseline)
	residues := []inventoryResidue{}
	for key, residue := range laneInventoryChanges(exercise) {
		if _, noise := baselineChanges[key]; noise {
			continue
		}
		residues = append(residues, residue)
	}
	sort.Slice(residues, func(i, j int) bool {
		if residues[i].Subject != residues[j].Subject {
			return residues[i].Subject < residues[j].Subject
		}
		return residues[i].Change < residues[j].Change
	})
	return inventoryDiff{Paired: true, Residues: residues}
}

// laneInventoryChanges maps a "subject\x00change" key to its residue for one
// lane. Keying by both subject and change kind lets diffLaneInventories subtract
// baseline-lane noise without losing the change type.
func laneInventoryChanges(inventory laneInventory) map[string]inventoryResidue {
	changes := map[string]inventoryResidue{}
	record := func(subject string, change string) {
		if subject == "" {
			return
		}
		changes[subject+"\x00"+change] = inventoryResidue{Subject: subject, Change: change}
	}
	for path, after := range inventory.After {
		subject := normalizeInventoryPath(path)
		if subject == "" {
			continue
		}
		before, existed := inventory.Before[path]
		if !existed {
			record(subject, "added")
			continue
		}
		if before.SHA256 != after.SHA256 || before.Mode != after.Mode {
			record(subject, "modified")
		}
	}
	for path := range inventory.Before {
		if _, ok := inventory.After[path]; ok {
			continue
		}
		record(normalizeInventoryPath(path), "removed")
	}
	return changes
}

// normalizeInventoryPath maps a lane-relative inventory path to the same
// normalized label space the trace parser uses ($HOME, $STATE, $WORKSPACE), so
// inventory residues and syscall observations share one subject vocabulary.
// Target-owned staging paths return "" and are excluded from persistence diffs.
func normalizeInventoryPath(relative string) string {
	relative = strings.TrimLeft(relative, "/")
	component, rest, found := strings.Cut(relative, "/")
	label := ""
	switch component {
	case "home":
		label = "$HOME"
	case "state":
		label = "$STATE"
	case "workspace":
		label = "$WORKSPACE"
	default:
		return ""
	}
	if !found || rest == "" {
		return label
	}
	if component == "workspace" && (rest == "skills" || strings.HasPrefix(rest, "skills/") || rest == "plugins" || strings.HasPrefix(rest, "plugins/")) {
		return ""
	}
	return label + "/" + rest
}
