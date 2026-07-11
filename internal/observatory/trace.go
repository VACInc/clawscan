package observatory

import (
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
	// BaselineOutputs and ExerciseOutputs are optional captured tool/output
	// value channels (the agent tool/output stream today). They are scanned for
	// canary values to derive the tool interaction stage and are never
	// published. Enhancements that capture a richer structured tool-event stream
	// can supply it here without changing the evidence schema.
	BaselineOutputs [][]byte
	ExerciseOutputs [][]byte
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
	PID  string
	Line string
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
	baselineCanaries := make(map[string]*canaryLaneCounts, len(input.Canaries))
	exerciseCanaries := make(map[string]*canaryLaneCounts, len(input.Canaries))
	for _, canary := range input.Canaries {
		baselineCanaries[canary.ID] = newCanaryLaneCounts()
		exerciseCanaries[canary.ID] = newCanaryLaneCounts()
	}

	consume := func(traces []string, exercise bool) {
		laneCanaries := baselineCanaries
		if exercise {
			laneCanaries = exerciseCanaries
		}
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
					stages := canaryLineStages(line, canary, input.Metadata, cwd)
					if len(stages) == 0 {
						continue
					}
					lane := laneCanaries[canary.ID]
					lane.total++
					for _, stage := range stages {
						lane.stages[stage]++
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
		// The tool stage is not tied to a syscall trace line: it counts canary
		// values surfacing in the captured agent tool/output stream. Scanning is
		// bounded and only counts are published.
		baselineTool := clampCanaryCount(countCanaryInStreams(input.BaselineOutputs, canary.Marker))
		exerciseTool := clampCanaryCount(countCanaryInStreams(input.ExerciseOutputs, canary.Marker))
		stages := []CanaryStageInteraction{}
		for _, stage := range canaryStageSequence {
			baselineStage := clampCanaryCount(baseline.stages[stage])
			exerciseStage := clampCanaryCount(exercise.stages[stage])
			if stage == CanaryStageTool {
				baselineStage, exerciseStage = baselineTool, exerciseTool
			}
			if baselineStage == 0 && exerciseStage == 0 {
				continue
			}
			stages = append(stages, CanaryStageInteraction{
				Stage:                stage,
				BaselineInteractions: baselineStage,
				ExerciseInteractions: exerciseStage,
				DeltaInteractions:    positiveDelta(exerciseStage, baselineStage),
			})
		}
		baselineTotal := clampCanaryCount(baseline.total)
		exerciseTotal := clampCanaryCount(exercise.total)
		result.Canaries = append(result.Canaries, CanaryObservation{
			ID:                   canary.ID,
			Surface:              canary.Surface,
			Class:                canary.Class,
			BaselineInteractions: baselineTotal,
			ExerciseInteractions: exerciseTotal,
			DeltaInteractions:    positiveDelta(exerciseTotal, baselineTotal),
			Stages:               stages,
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
		CanaryStages:    canaryStageCoverage(pairedTraceReceipts),
		Limitations: []string{
			"Coverage booleans confirm paired trace receipts for selected MVP syscall families; they do not claim an exhaustive Linux syscall audit.",
			"Observed behavior is input- and model-dependent; unexercised branches remain invisible.",
			"System-call tracing records endpoint addresses but does not provide complete DNS-name or payload attribution.",
			"A behavioral delta shows correlation with the exercise lane, not author intent or a safety verdict.",
			"MVP coverage is limited to one bounded OpenClaw " + input.Metadata.TargetKind + " exercise; browser automation is not exercised.",
			"Canary correlation classifies interactions into read, write, execute, outbound, and tool stages; the read stage reflects read-intent file opens, not individual read() syscalls, which are outside the selected scope.",
			"Outbound and tool are value-correlation stages: the capture strips network payloads, so a zero outbound count is limited coverage, not proof the token was not exfiltrated. Any nonzero stage interaction remains a real observation.",
		},
	}
	return result
}

type canaryLaneCounts struct {
	total  int
	stages map[string]int
}

func newCanaryLaneCounts() *canaryLaneCounts {
	return &canaryLaneCounts{stages: map[string]int{}}
}

// canaryStageCoverage reports, per interaction stage, whether the capture
// protocol can positively confirm it. The value is a stable function of the
// protocol and capture completeness, so two runs of the same protocol compare
// as equal. read/write/execute are confirmed by paired file/process traces;
// outbound is limited because the -s 0 capture strips send payloads; the agent
// tool/output stream is always captured, so the tool stage is confirmed.
func canaryStageCoverage(pairedTraceReceipts bool) []CanaryStageCoverage {
	traceState := "limited"
	if pairedTraceReceipts {
		traceState = "observed"
	}
	return []CanaryStageCoverage{
		{Stage: CanaryStageRead, Coverage: traceState, Source: "file-open-and-descriptor-syscall-trace"},
		{Stage: CanaryStageWrite, Coverage: traceState, Source: "file-mutation-syscall-trace"},
		{Stage: CanaryStageExecute, Coverage: traceState, Source: "exec-syscall-trace"},
		{Stage: CanaryStageOutbound, Coverage: "limited", Source: "socket-send-payload"},
		{Stage: CanaryStageTool, Coverage: "observed", Source: "agent-tool-output-stream"},
	}
}

func countCanaryInStreams(streams [][]byte, marker string) int {
	if marker == "" {
		return 0
	}
	total := 0
	for _, stream := range streams {
		if len(stream) == 0 {
			continue
		}
		total += strings.Count(string(stream), marker)
		if total >= maxCanaryInteractionCount {
			return maxCanaryInteractionCount
		}
	}
	return total
}

func clampCanaryCount(count int) int {
	if count > maxCanaryInteractionCount {
		return maxCanaryInteractionCount
	}
	if count < 0 {
		return 0
	}
	return count
}

func positiveDelta(exercise int, baseline int) int {
	if exercise > baseline {
		return exercise - baseline
	}
	return 0
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
		prefix string
		index  int
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
		if strings.HasSuffix(line, "<unfinished ...>") {
			prefix := strings.TrimSpace(strings.TrimSuffix(line, "<unfinished ...>"))
			pending[pid] = pendingCall{prefix: prefix, index: len(completed)}
			completed = append(completed, traceRecord{PID: pid})
			continue
		}
		if match := resumedCallPattern.FindStringSubmatch(line); len(match) == 3 {
			if call, ok := pending[pid]; ok && strings.HasPrefix(call.prefix, match[1]+"(") {
				completed[call.index].Line = call.prefix + match[2]
				delete(pending, pid)
			}
			continue
		}
		completed = append(completed, traceRecord{PID: pid, Line: line})
	}
	for pid, call := range pending {
		completed[call.index] = traceRecord{PID: pid, Line: call.prefix + " = -1 EINTR (trace ended before syscall resumed)"}
	}
	return completed
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
	return len(canaryLineStages(line, canary, metadata, cwd)) > 0
}

// canaryLineStages returns the deduplicated, canonically ordered interaction
// stages a single trace line represents for one canary. A line is counted as a
// canary interaction exactly when this returns a non-empty set. Two triggers
// contribute: value correlation (the canary's secret marker literally appears in
// the line) and path/descriptor correlation (a path operand resolves to the
// canary path). Neither ever inspects argv or payload bytes for a bare path
// string, so spoofing the canary path in an unrelated argument cannot forge an
// interaction.
func canaryLineStages(line string, canary CanaryDefinition, metadata CaptureMetadata, cwd string) []string {
	present := map[string]bool{}
	if canary.Marker != "" && strings.Contains(line, canary.Marker) {
		for _, stage := range canaryValueStages(line) {
			present[stage] = true
		}
	}
	for _, stage := range canaryPathStages(line, canary, metadata, cwd) {
		present[stage] = true
	}
	ordered := make([]string, 0, len(present))
	for _, stage := range canaryStageSequence {
		if present[stage] {
			ordered = append(ordered, stage)
		}
	}
	return ordered
}

// canaryValueStages classifies a line whose canary marker value is present by
// the syscall that carried it. Under the -s 0 capture protocol argv and payload
// strings are stripped, so this only fires for enriched re-analysis or for
// values that surface through filenames; the value is never republished.
func canaryValueStages(line string) []string {
	open := strings.IndexByte(line, '(')
	if open <= 0 {
		return []string{CanaryStageRead}
	}
	syscall := strings.TrimSpace(line[:open])
	switch syscall {
	case "open", "openat", "openat2":
		quoted := quotedTraceStrings(line)
		if len(quoted) == 0 {
			return []string{CanaryStageRead}
		}
		return openStages(openOperation(line, syscall, quoted[0]))
	case "creat":
		return []string{CanaryStageWrite}
	case "execve", "execveat":
		return []string{CanaryStageExecute}
	case "connect", "sendto", "sendmsg", "sendmmsg":
		return []string{CanaryStageOutbound}
	case "write", "writev":
		if subject, _ := networkFDSubject(line, nil); subject != "" {
			return []string{CanaryStageOutbound}
		}
		return []string{CanaryStageWrite}
	case "link", "linkat", "symlink", "symlinkat", "unlink", "unlinkat",
		"rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir",
		"truncate", "ftruncate":
		return []string{CanaryStageWrite}
	default:
		return []string{CanaryStageRead}
	}
}

// canaryPathStages classifies a line whose path operand (or annotated
// descriptor) resolves to the canary path. Path resolution mirrors the
// observation parser: relative operands are resolved against the PID-aware cwd,
// and both lane labelings are considered before comparing to the canary path.
func canaryPathStages(line string, canary CanaryDefinition, metadata CaptureMetadata, cwd string) []string {
	if canary.Path == "" {
		return nil
	}
	open := strings.IndexByte(line, '(')
	if open <= 0 {
		return nil
	}
	syscall := strings.TrimSpace(line[:open])
	quoted := quotedTraceStrings(line)
	matches := func(operand traceString) bool {
		for _, exercise := range []bool{false, true} {
			if normalizePath(resolveTracePath(operand, line, cwd), metadata, exercise) == canary.Path {
				return true
			}
		}
		return false
	}
	switch syscall {
	case "open", "openat", "openat2":
		if len(quoted) > 0 && matches(quoted[0]) {
			return openStages(openOperation(line, syscall, quoted[0]))
		}
	case "creat":
		if len(quoted) > 0 && matches(quoted[0]) {
			return []string{CanaryStageWrite}
		}
	case "unlink", "unlinkat", "rmdir", "mkdir", "mkdirat", "truncate":
		if len(quoted) > 0 && matches(quoted[0]) {
			return []string{CanaryStageWrite}
		}
	case "ftruncate":
		path := annotatedFDPathBefore(line, strings.IndexByte(line, ','))
		for _, exercise := range []bool{false, true} {
			if normalizePath(path, metadata, exercise) == canary.Path {
				return []string{CanaryStageWrite}
			}
		}
	case "rename", "renameat", "renameat2":
		operands := quoted
		if len(operands) > 2 {
			operands = operands[:2]
		}
		for _, operand := range operands {
			if matches(operand) {
				return []string{CanaryStageWrite}
			}
		}
	case "link", "linkat":
		operands := append([]traceString{}, quoted...)
		if len(operands) > 2 {
			operands = operands[:2]
		}
		if syscall == "linkat" && len(operands) > 0 && operands[0].Value == "" && strings.Contains(line, "AT_EMPTY_PATH") {
			operands[0] = traceString{Value: annotatedFDPathBefore(line, operands[0].Start), Start: -1, End: -1}
		}
		for _, operand := range operands {
			if matches(operand) {
				return []string{CanaryStageWrite}
			}
		}
	case "symlink", "symlinkat":
		if len(quoted) >= 2 && matches(quoted[len(quoted)-1]) {
			return []string{CanaryStageWrite}
		}
	case "execve", "execveat":
		if len(quoted) > 0 {
			program := quoted[0]
			if syscall == "execveat" && program.Value == "" && strings.Contains(line, "AT_EMPTY_PATH") {
				program = traceString{Value: annotatedFDPathBefore(line, program.Start), Start: -1, End: -1}
			}
			if matches(program) {
				return []string{CanaryStageExecute}
			}
		}
	}
	return nil
}

func openStages(operation string) []string {
	switch operation {
	case "open-for-write":
		return []string{CanaryStageWrite}
	case "open-for-read-write":
		return []string{CanaryStageRead, CanaryStageWrite}
	default:
		return []string{CanaryStageRead}
	}
}

func observationKey(observation traceObservation) string {
	return strings.Join([]string{observation.Kind, observation.Operation, observation.Subject, observation.Outcome, observation.Role}, "\x00")
}
