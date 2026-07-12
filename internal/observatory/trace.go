package observatory

import (
	"math"
	"net"
	"net/netip"
	pathpkg "path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type AnalysisInput struct {
	BaselineTraces        []string
	ExerciseTraces        []string
	Metadata              CaptureMetadata
	Canaries              []CanaryDefinition
	ControlPlaneAddresses []string
}

type analysisResult struct {
	Observations []Observation
	Canaries     []CanaryObservation
	Coverage     CoverageEvidence
}

type traceObservation struct {
	Kind      string
	Operation string
	Subject   string
	Outcome   string
	Role      string
}

type observationCounts struct {
	Baseline int
	Exercise int
}

type traceString struct {
	Value string
	Start int
	End   int
}

type traceRecord struct {
	PID          string
	Line         string
	Timestamp    float64
	HasTimestamp bool
}

type processCWD struct {
	path string
}

type traceProcessState struct {
	defaultCWD string
	byPID      map[string]*processCWD
}

var (
	quotedStringPattern        = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	dirFDPattern               = regexp.MustCompile(`(?:AT_FDCWD|[0-9]+)<([^>]+)>`)
	ipv4Pattern                = regexp.MustCompile(`sin_addr=inet_addr\("([^"]+)"\)`)
	ipv6Pattern                = regexp.MustCompile(`inet_pton\(AF_INET6, "([^"]+)"`)
	portPattern                = regexp.MustCompile(`sin6?_port=htons\(([0-9]+)\)`)
	unixPathPattern            = regexp.MustCompile(`sun_path=(@)?("(?:\\.|[^"\\])*")`)
	pidPrefixPattern           = regexp.MustCompile(`^(?:\[pid\s+([0-9]+)\]\s+|([0-9]+)\s+)(.*)$`)
	traceTimestampPattern      = regexp.MustCompile(`^([0-9]+\.[0-9]+)\s+`)
	resumedCallPattern         = regexp.MustCompile(`^<\.\.\.\s+([A-Za-z0-9_]+)\s+resumed>(.*)$`)
	ipv4LiteralPattern         = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
	ipv6LiteralPattern         = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*`)
	socketFDPattern            = regexp.MustCompile(`^[0-9]+<(?:TCP|UDP):\[[^>]*->([^>]+)\]>$`)
	procPIDPattern             = regexp.MustCompile(`^/proc/[0-9]+`)
	traceSyscallRecordPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\(.*\)\s+=\s+.+$`)
	operationalPrivatePrefixes = []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("198.18.0.0/15"),
	}
)

func AnalyzeTraces(input AnalysisInput) analysisResult {
	counts := map[string]*observationCounts{}
	observationsByKey := map[string]traceObservation{}
	baselineCanaries := make(map[string]int, len(input.Canaries))
	exerciseCanaries := make(map[string]int, len(input.Canaries))

	consume := func(traces []string, exercise bool) {
		for _, trace := range traces {
			initialCWD := input.Metadata.BaselineWorkspace
			if exercise {
				initialCWD = input.Metadata.ExerciseWorkspace
			}
			processes := newTraceProcessState(initialCWD)
			for _, record := range completeTraceRecords(trace) {
				line := record.Line
				if line == "" {
					continue
				}
				cwd := processes.cwd(record.PID)
				for _, canary := range input.Canaries {
					if lineTouchesCanaryAtCWD(line, canary, input.Metadata, cwd) {
						if exercise {
							exerciseCanaries[canary.ID]++
						} else {
							baselineCanaries[canary.ID]++
						}
					}
				}
				for _, observation := range parseTraceLineAtCWD(line, input.Metadata, input.ControlPlaneAddresses, exercise, cwd) {
					key := observationKey(observation)
					entry := counts[key]
					if entry == nil {
						entry = &observationCounts{}
						counts[key] = entry
						observationsByKey[key] = observation
					}
					if exercise {
						entry.Exercise++
					} else {
						entry.Baseline++
					}
				}
				processes.apply(record)
			}
		}
	}
	consume(input.BaselineTraces, false)
	consume(input.ExerciseTraces, true)

	result := analysisResult{Observations: []Observation{}, Canaries: []CanaryObservation{}}
	publicObservations := map[string]*Observation{}
	for key, count := range counts {
		delta := count.Exercise - count.Baseline
		if delta <= 0 {
			continue
		}
		parsed := observationsByKey[key]
		if parsed.Kind == "process" {
			parsed.Subject = pathpkg.Base(sanitizeObservationSubject(parsed.Subject, input.Canaries, input.ControlPlaneAddresses))
		} else {
			parsed.Subject = publicObservationSubject(parsed, input.Canaries, input.ControlPlaneAddresses)
		}
		publicKey := observationKey(parsed)
		published := publicObservations[publicKey]
		if published == nil {
			published = &Observation{Kind: parsed.Kind, Operation: parsed.Operation, Subject: parsed.Subject, Outcome: parsed.Outcome, Role: parsed.Role}
			publicObservations[publicKey] = published
		}
		published.BaselineCount += count.Baseline
		published.ExerciseCount += count.Exercise
		published.DeltaCount += delta
	}
	for _, observation := range publicObservations {
		result.Observations = append(result.Observations, *observation)
	}
	sort.Slice(result.Observations, func(i, j int) bool {
		a, b := result.Observations[i], result.Observations[j]
		return a.Kind+"\x00"+a.Operation+"\x00"+a.Subject+"\x00"+a.Outcome < b.Kind+"\x00"+b.Operation+"\x00"+b.Subject+"\x00"+b.Outcome
	})

	for _, canary := range input.Canaries {
		baseline := baselineCanaries[canary.ID]
		exercise := exerciseCanaries[canary.ID]
		delta := exercise - baseline
		if delta < 0 {
			delta = 0
		}
		result.Canaries = append(result.Canaries, CanaryObservation{
			ID:                   canary.ID,
			Surface:              canary.Surface,
			BaselineInteractions: baseline,
			ExerciseInteractions: exercise,
			DeltaInteractions:    delta,
		})
	}
	sort.Slice(result.Canaries, func(i, j int) bool { return result.Canaries[i].ID < result.Canaries[j].ID })

	pairedTraceReceipts := traceLaneHasCompleteSyscall(input.BaselineTraces) && traceLaneHasCompleteSyscall(input.ExerciseTraces)
	result.Coverage = CoverageEvidence{
		SyscallScope:    "selected-mvp-syscalls",
		FileSyscalls:    pairedTraceReceipts,
		ProcessSyscalls: pairedTraceReceipts,
		NetworkSyscalls: pairedTraceReceipts,
		BaselinePaired:  pairedTraceReceipts,
		Limitations: []string{
			"Coverage booleans confirm paired trace receipts for selected MVP syscall families; they do not claim an exhaustive Linux syscall audit.",
			"Observed behavior is input- and model-dependent; unexercised branches remain invisible.",
			"System-call tracing records endpoint addresses but does not provide complete DNS-name or payload attribution.",
			"A behavioral delta shows correlation with the exercise lane, not author intent or a safety verdict.",
			"MVP coverage is limited to one bounded OpenClaw " + input.Metadata.TargetKind + " exercise; browser automation is not exercised.",
			"The per-lane runtime syscall timeline is a bounded, ordered projection of the selected MVP syscalls with normalized, secret-safe subjects; it records file/process/network syscalls, not OpenClaw tool calls or arguments, and is capped per lane.",
			"Runtime timeline timing offsets are relative to each lane's first event and are published only when the capture provides monotonic per-event timestamps.",
		},
	}
	return result
}

// BuildRuntimeTimeline extracts an ordered, per-lane runtime syscall timeline from
// the same records AnalyzeTraces aggregates. It records file/process/network
// syscalls, not OpenClaw tool calls. Both lanes are published in full (bounded by
// MaxRuntimeTimelineEventsPerLane) rather than baseline-subtracted, because the
// timeline's job is to expose sequence and timing to downstream grading. Every
// subject reuses AnalyzeTraces' normalization and redaction so the timeline is
// exactly as secret-safe as the delta observations.
func BuildRuntimeTimeline(input AnalysisInput) RuntimeTimeline {
	return RuntimeTimeline{
		MaxEventsPerLane: MaxRuntimeTimelineEventsPerLane,
		Baseline:         buildLaneRuntimeTimeline(input.BaselineTraces, input.Metadata.BaselineWorkspace, input.Metadata, input.Canaries, input.ControlPlaneAddresses, false),
		Exercise:         buildLaneRuntimeTimeline(input.ExerciseTraces, input.Metadata.ExerciseWorkspace, input.Metadata, input.Canaries, input.ControlPlaneAddresses, true),
	}
}

type runtimeTimelineGroup struct {
	events       []RuntimeTimelineEvent
	timestamp    float64
	hasTimestamp bool
}

func buildLaneRuntimeTimeline(traces []string, initialCWD string, metadata CaptureMetadata, canaries []CanaryDefinition, controlPlaneAddresses []string, exercise bool) RuntimeTimelineLane {
	groups := []runtimeTimelineGroup{}
	timed := true
	monotonic := true
	seen := false
	var previous float64
	for _, trace := range traces {
		processes := newTraceProcessState(initialCWD)
		for _, record := range completeTraceRecords(trace) {
			if line := record.Line; line != "" {
				cwd := processes.cwd(record.PID)
				parsed := parseTraceLineAtCWD(line, metadata, controlPlaneAddresses, exercise, cwd)
				if len(parsed) > 0 {
					events := make([]RuntimeTimelineEvent, 0, len(parsed))
					for _, observation := range parsed {
						events = append(events, RuntimeTimelineEvent{
							Kind:      observation.Kind,
							Operation: observation.Operation,
							Subject:   runtimeTimelinePublicSubject(observation, canaries, controlPlaneAddresses),
							Outcome:   runtimeTimelineOutcome(observation.Outcome, line),
							Role:      observation.Role,
							Canary:    runtimeTimelineCanaryID(observation, canaries),
						})
					}
					groups = append(groups, runtimeTimelineGroup{events: events, timestamp: record.Timestamp, hasTimestamp: record.HasTimestamp})
					if !record.HasTimestamp {
						timed = false
					}
					if seen && record.Timestamp < previous {
						monotonic = false
					}
					previous = record.Timestamp
					seen = true
				}
			}
			processes.apply(record)
		}
	}

	lane := RuntimeTimelineLane{Events: []RuntimeTimelineEvent{}}
	if len(groups) == 0 {
		return lane
	}
	// Timing is trustworthy only when every timeline record carries a stamp and
	// the stamps never move backwards; otherwise offsets are withheld entirely.
	timed = timed && monotonic
	base := groups[0].timestamp
	var duration int64
	events := make([]RuntimeTimelineEvent, 0, len(groups))
	for _, group := range groups {
		var offset int64
		if timed {
			offset = relativeOffsetMs(group.timestamp, base)
			if offset > duration {
				duration = offset
			}
		}
		for _, event := range group.events {
			if timed {
				value := offset
				event.OffsetMs = &value
			}
			events = append(events, event)
		}
	}
	lane.TotalEvents = len(events)
	if len(events) > MaxRuntimeTimelineEventsPerLane {
		events = events[:MaxRuntimeTimelineEventsPerLane]
		lane.Truncated = true
	}
	for index := range events {
		events[index].Sequence = index + 1
	}
	lane.Events = events
	lane.EventCount = len(events)
	if timed {
		lane.Timed = true
		total := duration
		lane.DurationMs = &total
	}
	return lane
}

func relativeOffsetMs(timestamp float64, base float64) int64 {
	offset := int64(math.Round((timestamp - base) * 1000))
	if offset < 0 {
		return 0
	}
	return offset
}

func runtimeTimelinePublicSubject(observation traceObservation, canaries []CanaryDefinition, controlPlaneAddresses []string) string {
	if observation.Kind == "process" {
		return pathpkg.Base(sanitizeObservationSubject(observation.Subject, canaries, controlPlaneAddresses))
	}
	return publicObservationSubject(observation, canaries, controlPlaneAddresses)
}

// runtimeTimelineCanaryID attributes a file event to a synthetic canary by exact
// normalized path. It is intentionally path-only: marker-in-argument
// interactions are still counted in the aggregate canary section but are never
// reconstructed into a timeline subject that could leak the marker value.
func runtimeTimelineCanaryID(observation traceObservation, canaries []CanaryDefinition) string {
	if observation.Kind != "file" {
		return ""
	}
	for _, canary := range canaries {
		if canary.Path != "" && observation.Subject == canary.Path {
			return canary.ID
		}
	}
	return ""
}

// runtimeTimelineOutcome maps the parser's succeeded/attempted verdict onto the
// timeline's completion/denial/error vocabulary. A permission error is reported
// as a distinct denial so downstream grading can separate blocked attempts from
// other failures.
func runtimeTimelineOutcome(observationOutcome string, line string) string {
	if observationOutcome == "succeeded" {
		return "completed"
	}
	result := syscallResult(line)
	if strings.Contains(result, "EACCES") || strings.Contains(result, "EPERM") {
		return "denied"
	}
	return "error"
}

func traceLaneHasCompleteSyscall(traces []string) bool {
	for _, trace := range traces {
		for _, record := range completeTraceRecords(trace) {
			line := record.Line
			if strings.Contains(line, "trace ended before syscall resumed") {
				continue
			}
			if traceSyscallRecordPattern.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func publicObservationSubject(observation traceObservation, canaries []CanaryDefinition, controlPlaneAddresses []string) string {
	if observation.Role == "private-network" {
		if _, port, err := net.SplitHostPort(observation.Subject); err == nil {
			return "private-endpoint:" + port
		}
	}
	return sanitizeObservationSubject(observation.Subject, canaries, controlPlaneAddresses)
}

func completeTraceRecords(trace string) []traceRecord {
	type pendingCall struct {
		prefix       string
		index        int
		timestamp    float64
		hasTimestamp bool
	}
	pending := map[string]pendingCall{}
	completed := []traceRecord{}
	for _, raw := range strings.Split(trace, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		pid := "single"
		if match := pidPrefixPattern.FindStringSubmatch(line); len(match) == 4 {
			if match[1] != "" {
				pid = match[1]
			} else {
				pid = match[2]
			}
			line = match[3]
		}
		// A trailing `-ttt` timestamp is stripped here so every downstream
		// consumer (parsing, resumed-call stitching, cwd tracking) sees the same
		// bare syscall text it did before timing capture existed. The start-time
		// stamp of a split syscall stays with its <unfinished ...> record.
		timestamp, hasTimestamp, line := splitTraceTimestamp(line)
		if strings.HasSuffix(line, "<unfinished ...>") {
			prefix := strings.TrimSpace(strings.TrimSuffix(line, "<unfinished ...>"))
			pending[pid] = pendingCall{prefix: prefix, index: len(completed), timestamp: timestamp, hasTimestamp: hasTimestamp}
			completed = append(completed, traceRecord{PID: pid})
			continue
		}
		if match := resumedCallPattern.FindStringSubmatch(line); len(match) == 3 {
			if call, ok := pending[pid]; ok && strings.HasPrefix(call.prefix, match[1]+"(") {
				completed[call.index] = traceRecord{PID: pid, Line: call.prefix + match[2], Timestamp: call.timestamp, HasTimestamp: call.hasTimestamp}
				delete(pending, pid)
			}
			continue
		}
		completed = append(completed, traceRecord{PID: pid, Line: line, Timestamp: timestamp, HasTimestamp: hasTimestamp})
	}
	for pid, call := range pending {
		completed[call.index] = traceRecord{PID: pid, Line: call.prefix + " = -1 EINTR (trace ended before syscall resumed)", Timestamp: call.timestamp, HasTimestamp: call.hasTimestamp}
	}
	return completed
}

func splitTraceTimestamp(line string) (float64, bool, string) {
	match := traceTimestampPattern.FindStringSubmatch(line)
	if match == nil {
		return 0, false, line
	}
	value, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0, false, line
	}
	return value, true, strings.TrimSpace(line[len(match[0]):])
}

func newTraceProcessState(defaultCWD string) *traceProcessState {
	return &traceProcessState{defaultCWD: pathpkg.Clean(defaultCWD), byPID: map[string]*processCWD{}}
}

func (state *traceProcessState) cwd(pid string) string {
	entry := state.byPID[pid]
	if entry == nil {
		entry = &processCWD{path: state.defaultCWD}
		state.byPID[pid] = entry
	}
	return entry.path
}

func (state *traceProcessState) apply(record traceRecord) {
	line := record.Line
	open := strings.IndexByte(line, '(')
	if open <= 0 || !syscallSucceeded(syscallResult(line)) {
		return
	}
	syscall := strings.TrimSpace(line[:open])
	current := state.cwd(record.PID)
	switch syscall {
	case "chdir":
		quoted := quotedTraceStrings(line)
		if len(quoted) > 0 {
			state.byPID[record.PID].path = resolveTracePath(quoted[0], line, current)
		}
	case "fchdir":
		if path := annotatedFDPathBefore(line, strings.IndexByte(line, ')')); path != "" {
			state.byPID[record.PID].path = pathpkg.Clean(path)
		}
	case "clone", "clone3", "fork", "vfork":
		childPID := successfulResultPID(line)
		if childPID == "" {
			return
		}
		if strings.Contains(line, "CLONE_FS") {
			state.byPID[childPID] = state.byPID[record.PID]
		} else {
			state.byPID[childPID] = &processCWD{path: current}
		}
	case "unshare":
		if strings.Contains(line, "CLONE_FS") {
			state.byPID[record.PID] = &processCWD{path: current}
		}
	case "execve", "execveat":
		// exec unshares an fs_struct previously shared through CLONE_FS.
		state.byPID[record.PID] = &processCWD{path: current}
	}
}

func successfulResultPID(line string) string {
	fields := strings.Fields(syscallResult(line))
	if len(fields) == 0 {
		return ""
	}
	value := fields[0]
	if annotation := strings.IndexByte(value, '<'); annotation > 0 {
		value = value[:annotation]
	}
	pid, err := strconv.ParseInt(value, 10, 64)
	if err != nil || pid <= 0 {
		return ""
	}
	return strconv.FormatInt(pid, 10)
}

func sanitizeObservationSubject(subject string, canaries []CanaryDefinition, controlPlaneAddresses []string) string {
	for _, canary := range canaries {
		if canary.Marker != "" {
			subject = strings.ReplaceAll(subject, canary.Marker, "[canary:"+canary.ID+"]")
		}
	}
	controlPlaneHosts := map[string]struct{}{}
	for _, address := range controlPlaneAddresses {
		host, _, err := net.SplitHostPort(address)
		if err == nil {
			if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
				controlPlaneHosts[ip.String()] = struct{}{}
			}
		}
	}
	redactAddress := func(candidate string) string {
		return redactAddressLiteral(candidate, controlPlaneHosts)
	}
	subject = ipv4LiteralPattern.ReplaceAllStringFunc(subject, redactAddress)
	subject = ipv6LiteralPattern.ReplaceAllStringFunc(subject, redactAddress)
	return subject
}

func redactAddressLiteral(candidate string, controlPlaneHosts map[string]struct{}) string {
	trimmed := strings.Trim(candidate, "[]")
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return candidate
	}
	if _, controlPlane := controlPlaneHosts[ip.String()]; controlPlane || isOperationallyPrivateIP(ip) {
		return "[private-address]"
	}
	return candidate
}

func isOperationallyPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range operationalPrivatePrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseTraceLine(line string, metadata CaptureMetadata, controlPlaneAddresses []string, exercise bool) []traceObservation {
	return parseTraceLineAtCWD(line, metadata, controlPlaneAddresses, exercise, "")
}

func parseTraceLineAtCWD(line string, metadata CaptureMetadata, controlPlaneAddresses []string, exercise bool, cwd string) []traceObservation {
	open := strings.IndexByte(line, '(')
	if open <= 0 {
		return nil
	}
	syscall := strings.TrimSpace(line[:open])
	outcome := "attempted"
	if syscallSucceeded(syscallResult(line)) {
		outcome = "succeeded"
	}
	quoted := quotedTraceStrings(line)
	switch syscall {
	case "execve", "execveat":
		if len(quoted) == 0 {
			return nil
		}
		resolved := resolveTracePath(quoted[0], line, cwd)
		if syscall == "execveat" && quoted[0].Value == "" && strings.Contains(line, "AT_EMPTY_PATH") {
			resolved = annotatedFDPathBefore(line, quoted[0].Start)
		}
		if resolved == "" {
			return nil
		}
		path := normalizePath(resolved, metadata, exercise)
		if path == "" {
			return nil
		}
		return []traceObservation{{Kind: "process", Operation: "execute", Subject: path, Outcome: outcome}}
	case "open", "openat", "openat2", "creat":
		if len(quoted) == 0 {
			return nil
		}
		path := normalizePath(resolveTracePath(quoted[0], line, cwd), metadata, exercise)
		if path == "" {
			return nil
		}
		operation := openOperation(line, syscall, quoted[0])
		if (operation == "open-for-read" || operation == "open-path") && outcome == "succeeded" && isKnownRuntimeReadNoise(path) {
			return nil
		}
		return []traceObservation{{Kind: "file", Operation: operation, Subject: path, Outcome: outcome}}
	case "unlink", "unlinkat", "rmdir":
		if len(quoted) == 0 {
			return nil
		}
		path := normalizePath(resolveTracePath(quoted[0], line, cwd), metadata, exercise)
		if path == "" {
			return nil
		}
		return []traceObservation{{Kind: "file", Operation: "delete", Subject: path, Outcome: outcome}}
	case "mkdir", "mkdirat":
		if len(quoted) == 0 {
			return nil
		}
		path := normalizePath(resolveTracePath(quoted[0], line, cwd), metadata, exercise)
		if path == "" {
			return nil
		}
		return []traceObservation{{Kind: "file", Operation: "create-directory", Subject: path, Outcome: outcome}}
	case "truncate", "ftruncate":
		path := ""
		if syscall == "truncate" && len(quoted) > 0 {
			path = normalizePath(resolveTracePath(quoted[0], line, cwd), metadata, exercise)
		} else if syscall == "ftruncate" {
			if annotated := annotatedFDPathBefore(line, strings.IndexByte(line, ',')); annotated != "" {
				path = normalizePath(annotated, metadata, exercise)
			}
		}
		if path == "" {
			return nil
		}
		return []traceObservation{{Kind: "file", Operation: "truncate", Subject: path, Outcome: outcome}}
	case "rename", "renameat", "renameat2":
		if len(quoted) < 2 {
			return nil
		}
		from := normalizePath(resolveTracePath(quoted[0], line, cwd), metadata, exercise)
		to := normalizePath(resolveTracePath(quoted[1], line, cwd), metadata, exercise)
		result := []traceObservation{}
		if from != "" {
			result = append(result, traceObservation{Kind: "file", Operation: "rename-from", Subject: from, Outcome: outcome})
		}
		if to != "" {
			result = append(result, traceObservation{Kind: "file", Operation: "rename-to", Subject: to, Outcome: outcome})
		}
		return result
	case "link", "linkat":
		if len(quoted) < 2 {
			return nil
		}
		fromPath := resolveTracePath(quoted[0], line, cwd)
		if syscall == "linkat" && quoted[0].Value == "" && strings.Contains(line, "AT_EMPTY_PATH") {
			fromPath = annotatedFDPathBefore(line, quoted[0].Start)
		}
		from := ""
		if fromPath != "" {
			from = normalizePath(fromPath, metadata, exercise)
		}
		to := normalizePath(resolveTracePath(quoted[1], line, cwd), metadata, exercise)
		result := []traceObservation{}
		if from != "" {
			result = append(result, traceObservation{Kind: "file", Operation: "link-from", Subject: from, Outcome: outcome})
		}
		if to != "" {
			result = append(result, traceObservation{Kind: "file", Operation: "link-to", Subject: to, Outcome: outcome})
		}
		return result
	case "symlink", "symlinkat":
		if len(quoted) < 2 {
			return nil
		}
		path := normalizePath(resolveTracePath(quoted[len(quoted)-1], line, cwd), metadata, exercise)
		if path == "" {
			return nil
		}
		return []traceObservation{{Kind: "file", Operation: "create-symlink", Subject: path, Outcome: outcome}}
	case "connect", "sendto", "sendmsg", "sendmmsg":
		if syscall == "sendmmsg" {
			sent, known := successfulResultCount(line)
			endpoints := repeatedNetworkSubjects(line, metadata, controlPlaneAddresses, exercise, cwd)
			if len(endpoints) == 0 {
				if subject, role := networkFDSubject(line, controlPlaneAddresses); subject != "" {
					count := 1
					if known && sent > count {
						count = sent
					}
					for index := 0; index < count; index++ {
						endpoints = append(endpoints, networkEndpoint{Subject: subject, Role: role})
					}
				}
			}
			limit := len(endpoints)
			if known && sent < limit {
				limit = sent + 1
			} else if !known && limit > 1 {
				limit = 1
			}
			observations := make([]traceObservation, 0, limit)
			for index := 0; index < limit; index++ {
				messageOutcome := "attempted"
				if known && index < sent {
					messageOutcome = "succeeded"
				}
				endpoint := endpoints[index]
				observations = append(observations, traceObservation{Kind: "network", Operation: "send", Subject: endpoint.Subject, Outcome: messageOutcome, Role: endpoint.Role})
			}
			return observations
		}
		subject, role := networkSubject(line, metadata, controlPlaneAddresses, exercise, cwd)
		if subject == "" && syscall != "connect" {
			subject, role = networkFDSubject(line, controlPlaneAddresses)
		}
		if subject == "" {
			return nil
		}
		operation := "connect"
		if syscall != "connect" {
			operation = "send"
		}
		return []traceObservation{{Kind: "network", Operation: operation, Subject: subject, Outcome: outcome, Role: role}}
	case "write", "writev":
		subject, role := networkFDSubject(line, controlPlaneAddresses)
		if subject == "" {
			return nil
		}
		return []traceObservation{{Kind: "network", Operation: "send", Subject: subject, Outcome: outcome, Role: role}}
	default:
		return nil
	}
}

func successfulResultCount(line string) (int, bool) {
	fields := strings.Fields(syscallResult(line))
	if len(fields) == 0 {
		return 0, false
	}
	count, err := strconv.ParseInt(fields[0], 0, 32)
	if err != nil || count < 0 {
		return 0, false
	}
	return int(count), true
}

func annotatedFDPathBefore(line string, end int) string {
	if end < 0 || end > len(line) {
		return ""
	}
	matches := dirFDPattern.FindAllStringSubmatch(line[:end], -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1][1]
}

func quotedTraceStrings(line string) []traceString {
	indices := quotedStringPattern.FindAllStringIndex(line, -1)
	values := make([]traceString, 0, len(indices))
	for _, index := range indices {
		value, err := strconv.Unquote(line[index[0]:index[1]])
		if err == nil {
			values = append(values, traceString{Value: value, Start: index[0], End: index[1]})
		}
	}
	return values
}

func syscallResult(line string) string {
	index := strings.LastIndex(line, " = ")
	if index < 0 {
		return ""
	}
	return strings.TrimSpace(line[index+3:])
}

func syscallSucceeded(result string) bool {
	fields := strings.Fields(result)
	if len(fields) == 0 {
		return false
	}
	value := fields[0]
	if annotation := strings.IndexByte(value, '<'); annotation > 0 {
		value = value[:annotation]
	}
	number, err := strconv.ParseInt(value, 0, 64)
	return err == nil && number >= 0
}

func resolveTracePath(path traceString, line string, cwd string) string {
	if path.Value == "" || pathpkg.IsAbs(path.Value) {
		return path.Value
	}
	prefix := line
	if path.Start >= 0 && path.Start <= len(line) {
		prefix = line[:path.Start]
	}
	matches := dirFDPattern.FindAllStringSubmatch(prefix, -1)
	if len(matches) > 0 {
		match := matches[len(matches)-1]
		return pathpkg.Clean(pathpkg.Join(match[1], path.Value))
	}
	if cwd != "" {
		return pathpkg.Clean(pathpkg.Join(cwd, path.Value))
	}
	return path.Value
}

func normalizePath(path string, metadata CaptureMetadata, exercise bool) string {
	path = pathpkg.Clean(path)
	path = procPIDPattern.ReplaceAllString(path, "/proc/$PID")
	type root struct {
		path  string
		label string
	}
	targetLabel := "$SKILL"
	if metadata.TargetKind == "plugin" {
		targetLabel = "$PLUGIN"
	}
	roots := []root{{metadata.TargetRoot, targetLabel}}
	if exercise {
		roots = append(roots,
			root{metadata.ExerciseWorkspace, "$WORKSPACE"},
			root{metadata.ExerciseState, "$STATE"},
			root{metadata.ExerciseHome, "$HOME"},
			root{commonLaneRoot(metadata.ExerciseWorkspace, metadata.ExerciseState, metadata.ExerciseHome), "$LANE"},
		)
	} else {
		roots = append(roots,
			root{metadata.BaselineWorkspace, "$WORKSPACE"},
			root{metadata.BaselineState, "$STATE"},
			root{metadata.BaselineHome, "$HOME"},
			root{commonLaneRoot(metadata.BaselineWorkspace, metadata.BaselineState, metadata.BaselineHome), "$LANE"},
		)
	}
	sort.SliceStable(roots, func(i, j int) bool { return len(roots[i].path) > len(roots[j].path) })
	for _, candidate := range roots {
		if candidate.path == "" {
			continue
		}
		cleanRoot := pathpkg.Clean(candidate.path)
		if path == cleanRoot {
			return candidate.label
		}
		if strings.HasPrefix(path, cleanRoot+"/") {
			return candidate.label + "/" + strings.TrimPrefix(path, cleanRoot+"/")
		}
	}
	if strings.HasPrefix(path, "/home/") {
		parts := strings.SplitN(strings.TrimPrefix(path, "/home/"), "/", 2)
		if len(parts) == 1 {
			return "$GUEST_HOME"
		}
		return "$GUEST_HOME/" + parts[1]
	}
	return path
}

func commonLaneRoot(workspace string, state string, home string) string {
	if workspace == "" || state == "" || home == "" {
		return ""
	}
	root := pathpkg.Dir(workspace)
	if root == "." || root == "/" || pathpkg.Dir(state) != root || pathpkg.Dir(home) != root {
		return ""
	}
	return root
}

func openOperation(line string, syscall string, path traceString) string {
	if syscall == "creat" {
		return "open-for-write"
	}
	flags := ""
	if path.End >= 0 && path.End <= len(line) {
		flags = line[path.End:]
		if result := strings.LastIndex(flags, " = "); result >= 0 {
			flags = flags[:result]
		}
	}
	if strings.Contains(flags, "O_PATH") {
		return "open-path"
	}
	if strings.Contains(flags, "O_RDWR") {
		return "open-for-read-write"
	}
	if strings.Contains(flags, "O_WRONLY") || strings.Contains(flags, "O_TRUNC") || strings.Contains(flags, "O_APPEND") || strings.Contains(flags, "O_CREAT") {
		return "open-for-write"
	}
	return "open-for-read"
}

func isKnownRuntimeReadNoise(path string) bool {
	if path == "/etc/ld.so.cache" || path == "/usr/lib/locale/locale-archive" {
		return true
	}
	if strings.HasPrefix(path, "/usr/share/locale/") && strings.HasSuffix(path, ".mo") {
		return true
	}
	if !strings.HasPrefix(path, "/lib/") && !strings.HasPrefix(path, "/lib64/") && !strings.HasPrefix(path, "/usr/lib/") {
		return false
	}
	base := pathpkg.Base(path)
	return strings.Contains(base, ".so") && (strings.HasPrefix(base, "lib") || strings.HasPrefix(base, "ld-") || strings.HasPrefix(base, "ld-linux"))
}

func networkSubject(line string, metadata CaptureMetadata, controlPlaneAddresses []string, exercise bool, cwd string) (string, string) {
	endpoints := networkSubjects(line, metadata, controlPlaneAddresses, exercise, cwd)
	if len(endpoints) == 0 {
		return "", ""
	}
	return endpoints[0].Subject, endpoints[0].Role
}

type networkEndpoint struct {
	Subject string
	Role    string
}

func networkSubjects(line string, metadata CaptureMetadata, controlPlaneAddresses []string, exercise bool, cwd string) []networkEndpoint {
	return collectNetworkSubjects(line, metadata, controlPlaneAddresses, exercise, cwd, true)
}

func repeatedNetworkSubjects(line string, metadata CaptureMetadata, controlPlaneAddresses []string, exercise bool, cwd string) []networkEndpoint {
	return collectNetworkSubjects(line, metadata, controlPlaneAddresses, exercise, cwd, false)
}

func collectNetworkSubjects(line string, metadata CaptureMetadata, controlPlaneAddresses []string, exercise bool, cwd string, deduplicate bool) []networkEndpoint {
	endpoints := []networkEndpoint{}
	seen := map[string]bool{}
	quotedSpans := quotedTraceStrings(line)
	add := func(subject, role string) {
		key := subject + "\x00" + role
		if subject != "" && (!deduplicate || !seen[key]) {
			seen[key] = true
			endpoints = append(endpoints, networkEndpoint{Subject: subject, Role: role})
		}
	}
	for _, match := range unixPathPattern.FindAllStringSubmatchIndex(line, -1) {
		if len(match) != 6 || tracePositionInsideString(match[0], quotedSpans) {
			continue
		}
		path, err := strconv.Unquote(line[match[4]:match[5]])
		if err == nil {
			if match[2] >= 0 {
				add("unix-abstract:"+path, "local")
				continue
			}
			if !pathpkg.IsAbs(path) && cwd != "" {
				path = pathpkg.Join(cwd, path)
			}
			add("unix:"+normalizePath(path, metadata, exercise), "local")
		}
	}
	for _, pattern := range []*regexp.Regexp{ipv4Pattern, ipv6Pattern} {
		for _, match := range pattern.FindAllStringSubmatchIndex(line, -1) {
			if len(match) != 4 || tracePositionInsideString(match[0], quotedSpans) {
				continue
			}
			host := line[match[2]:match[3]]
			sockaddr := sockaddrContaining(line, match[0])
			if sockaddr == "" {
				continue
			}
			port := "unknown"
			if portMatch := portPattern.FindStringSubmatch(sockaddr); len(portMatch) == 2 {
				port = portMatch[1]
			}
			subject, role := classifyNetworkHost(host, port, controlPlaneAddresses)
			add(subject, role)
		}
	}
	return endpoints
}

func tracePositionInsideString(position int, values []traceString) bool {
	for _, value := range values {
		if position >= value.Start && position < value.End {
			return true
		}
	}
	return false
}

func sockaddrContaining(line string, position int) string {
	if position < 0 || position > len(line) {
		return ""
	}
	start := strings.LastIndexByte(line[:position], '{')
	if start < 0 {
		return ""
	}
	end := strings.IndexByte(line[position:], '}')
	if end < 0 {
		return ""
	}
	return line[start : position+end+1]
}

func networkFDSubject(line string, controlPlaneAddresses []string) (string, string) {
	open := strings.IndexByte(line, '(')
	if open < 0 {
		return "", ""
	}
	firstArg := line[open+1:]
	if comma := strings.IndexByte(firstArg, ','); comma >= 0 {
		firstArg = firstArg[:comma]
	}
	match := socketFDPattern.FindStringSubmatch(strings.TrimSpace(firstArg))
	if len(match) != 2 {
		return "", ""
	}
	host, port, err := net.SplitHostPort(match[1])
	if err != nil {
		return "", ""
	}
	return classifyNetworkHost(strings.Trim(host, "[]"), port, controlPlaneAddresses)
}

func classifyNetworkHost(host string, port string, controlPlaneAddresses []string) (string, string) {
	for _, allowed := range controlPlaneAddresses {
		allowedHost, allowedPort, err := net.SplitHostPort(allowed)
		if err == nil && strings.EqualFold(strings.Trim(allowedHost, "[]"), host) && allowedPort == port {
			return "model-endpoint:" + port, "model-control-plane"
		}
	}
	ip := net.ParseIP(host)
	if isOperationallyPrivateIP(ip) {
		return net.JoinHostPort(host, port), "private-network"
	}
	return net.JoinHostPort(host, port), "external"
}

func lineTouchesCanary(line string, canary CanaryDefinition, metadata CaptureMetadata) bool {
	return lineTouchesCanaryAtCWD(line, canary, metadata, "")
}

func lineTouchesCanaryAtCWD(line string, canary CanaryDefinition, metadata CaptureMetadata, cwd string) bool {
	if canary.Marker != "" && strings.Contains(line, canary.Marker) {
		return true
	}
	if canary.Path == "" {
		return false
	}
	open := strings.IndexByte(line, '(')
	if open <= 0 {
		return false
	}
	syscall := strings.TrimSpace(line[:open])
	quoted := quotedTraceStrings(line)
	pathOperands := []traceString{}
	switch syscall {
	case "open", "openat", "openat2", "creat", "unlink", "unlinkat", "rmdir", "mkdir", "mkdirat", "truncate":
		if len(quoted) > 0 {
			pathOperands = quoted[:1]
		}
	case "rename", "renameat", "renameat2", "link", "linkat":
		if len(quoted) > 2 {
			quoted = quoted[:2]
		}
		pathOperands = quoted
		if syscall == "linkat" && len(pathOperands) > 0 && pathOperands[0].Value == "" && strings.Contains(line, "AT_EMPTY_PATH") {
			pathOperands[0] = traceString{Value: annotatedFDPathBefore(line, pathOperands[0].Start), Start: -1, End: -1}
		}
	case "symlink", "symlinkat":
		if len(quoted) >= 2 {
			pathOperands = quoted[len(quoted)-1:]
		}
	case "ftruncate":
		path := annotatedFDPathBefore(line, strings.IndexByte(line, ','))
		for _, exercise := range []bool{false, true} {
			if normalizePath(path, metadata, exercise) == canary.Path {
				return true
			}
		}
		return false
	default:
		return false
	}
	for _, exercise := range []bool{false, true} {
		for _, operand := range pathOperands {
			if normalizePath(resolveTracePath(operand, line, cwd), metadata, exercise) == canary.Path {
				return true
			}
		}
	}
	return false
}

func observationKey(observation traceObservation) string {
	return strings.Join([]string{observation.Kind, observation.Operation, observation.Subject, observation.Outcome, observation.Role}, "\x00")
}
