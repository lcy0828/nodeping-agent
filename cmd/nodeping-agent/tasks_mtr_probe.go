package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type mtrRunConfig struct {
	Target       string
	Path         string
	ReportCycles int
	MaxHops      int
	Protocol     string
}

const (
	defaultMTRReportCycles   = 100
	maxMTRReportCycles       = 100
	mtrSampleIntervalSeconds = 1
	maxMTRRawDiagnosticBytes = 64 * 1024
)

func runMTR(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	cfg, err := newMTRRunConfig(ctx, target, options)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	result, raw, cmdErr, err := runMTRReport(ctx, cfg, cfg.ReportCycles)
	if err != nil {
		return nil, err
	}
	return finalizeMTRResult(ctx, cfg, started, result, raw, cmdErr), nil
}

func runMTRWithProgress(ctx context.Context, cfg config, task taskRequest, target string) (map[string]any, error) {
	mtrCfg, err := newMTRRunConfig(ctx, target, task.Options)
	if err != nil {
		return nil, err
	}
	emitter := newMTRProgressEmitter(ctx, cfg, task)
	defer emitter.Close()

	result, raw, rawErr := runMTRRaw(ctx, mtrCfg, emitter.Emit)
	if rawErr == nil {
		result["raw_output"] = strings.TrimSpace(string(raw))
		return result, nil
	}
	if result != nil {
		result["raw_output"] = strings.TrimSpace(string(raw))
		return result, rawErr
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	started := time.Now()
	report, reportRaw, cmdErr, reportErr := runMTRReport(ctx, mtrCfg, mtrCfg.ReportCycles)
	if reportErr != nil {
		return nil, fmt.Errorf("mtr raw mode failed: %v; report fallback failed: %w", rawErr, reportErr)
	}
	result = finalizeMTRResult(ctx, mtrCfg, started, report, reportRaw, cmdErr)
	result["stream_mode"] = "report_fallback"
	return result, nil
}

func newMTRRunConfig(ctx context.Context, target string, options map[string]any) (*mtrRunConfig, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("mtr target is required")
	}
	resolver := newProbeTargetResolver(options)
	resolved, err := resolver.resolveHost(ctx, target)
	if err != nil {
		return nil, err
	}
	path, err := exec.LookPath("mtr")
	if err != nil {
		return nil, errors.New("mtr command not found")
	}
	reportCycles := intOption(options, "report_cycles", defaultMTRReportCycles)
	if reportCycles < 1 {
		reportCycles = 1
	}
	if reportCycles > maxMTRReportCycles {
		reportCycles = maxMTRReportCycles
	}
	maxHops := intOption(options, "max_hops", 30)
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > 64 {
		maxHops = 64
	}
	protocol := strings.ToLower(strings.TrimSpace(stringOptionAny(options, "protocol")))
	switch protocol {
	case "icmp", "":
		protocol = "icmp"
	case "udp":
	case "tcp":
	default:
		return nil, fmt.Errorf("unsupported mtr protocol: %s", protocol)
	}
	return &mtrRunConfig{
		Target:       resolved.String(),
		Path:         path,
		ReportCycles: reportCycles,
		MaxHops:      maxHops,
		Protocol:     protocol,
	}, nil
}

func runMTRRaw(ctx context.Context, cfg *mtrRunConfig, emit func(map[string]any)) (map[string]any, []byte, error) {
	if cfg == nil {
		return nil, nil, errors.New("mtr config is required")
	}
	args := []string{"-l", "-c", strconv.Itoa(cfg.ReportCycles), "-i", strconv.Itoa(mtrSampleIntervalSeconds), "-m", strconv.Itoa(cfg.MaxHops), "-n"}
	switch cfg.Protocol {
	case "udp":
		args = append(args, "-u")
	case "tcp":
		args = append(args, "-T")
	}
	args = append(args, cfg.Target)

	cmd := mtrCommandContext(ctx, cfg.Path, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("open mtr raw output: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start mtr raw mode: %w", err)
	}

	started := time.Now()
	aggregate := newMTRAggregate(cfg, started, cfg.Target)
	var raw bytes.Buffer
	lastEmitted := 0
	rawTransmits := 0
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		appendMTRDiagnosticString(&raw, line)
		appendMTRDiagnosticString(&raw, "\n")
		event, ok := parseMTRRawEvent(line)
		if !ok {
			continue
		}
		switch event.kind {
		case 'x':
			if aggregate.hasTransmit(event.hop, event.sequence, event.hasSequence) {
				continue
			}
			if event.hop == 1 {
				completed := aggregate.sentCount(1)
				if completed > lastEmitted {
					aggregate.completedCount = min(completed, cfg.ReportCycles)
					if emit != nil {
						emit(aggregate.summary())
					}
					lastEmitted = aggregate.completedCount
				}
			}
			if aggregate.addTransmit(event.hop, event.sequence, event.hasSequence) {
				rawTransmits++
			}
		case 'h':
			aggregate.setPath(event.hop, event.value)
		case 'p':
			aggregate.addReply(event.hop, event.latencyMS, event.sequence, event.hasSequence)
		}
	}
	scanErr := scanner.Err()
	cmdErr := cmd.Wait()
	if stderr.Len() > 0 {
		if raw.Len() > 0 && raw.Bytes()[raw.Len()-1] != '\n' {
			raw.WriteByte('\n')
		}
		appendMTRDiagnosticBytes(&raw, stderr.Bytes())
	}
	if scanErr != nil {
		return nil, raw.Bytes(), fmt.Errorf("read mtr raw output: %w", scanErr)
	}
	if rawTransmits == 0 || aggregate.sentCount(1) == 0 || len(aggregate.hops) == 0 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, raw.Bytes(), ctxErr
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" && cmdErr != nil {
			message = cmdErr.Error()
		}
		if message == "" {
			message = "no raw events returned"
		}
		return nil, raw.Bytes(), fmt.Errorf("mtr raw mode unavailable: %s", message)
	}

	completed := aggregate.sentCount(1)
	aggregate.completedCount = min(completed, cfg.ReportCycles)
	result := aggregate.summary()
	result["stream_mode"] = "raw"
	result["raw_output"] = strings.TrimSpace(raw.String())
	if emit != nil && aggregate.completedCount > lastEmitted {
		emit(result)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		result["stopped_early"] = true
		result["stop_reason"] = ctxErr.Error()
		if cmdErr != nil {
			result["command_error"] = cmdErr.Error()
		}
		return result, raw.Bytes(), ctxErr
	}
	if cmdErr != nil {
		diagnostic := cmdErr.Error()
		if message := strings.TrimSpace(stderr.String()); message != "" {
			diagnostic += ": " + message
		}
		publicMessage := "mtr process stopped before sampling completed"
		result["stopped_early"] = true
		result["stop_reason"] = publicMessage
		result["command_error"] = diagnostic
		return result, raw.Bytes(), errors.New(publicMessage)
	}
	if completed < cfg.ReportCycles {
		message := fmt.Sprintf("mtr raw mode stopped after %d/%d samples", completed, cfg.ReportCycles)
		result["stopped_early"] = true
		result["stop_reason"] = message
		return result, raw.Bytes(), errors.New(message)
	}
	return result, raw.Bytes(), nil
}

func appendMTRDiagnosticString(target *bytes.Buffer, value string) {
	if target == nil || value == "" {
		return
	}
	remaining := maxMTRRawDiagnosticBytes - target.Len()
	if remaining <= 0 {
		return
	}
	if len(value) > remaining {
		value = value[:remaining]
	}
	target.WriteString(value)
}

func appendMTRDiagnosticBytes(target *bytes.Buffer, value []byte) {
	if target == nil || len(value) == 0 {
		return
	}
	remaining := maxMTRRawDiagnosticBytes - target.Len()
	if remaining <= 0 {
		return
	}
	if len(value) > remaining {
		value = value[:remaining]
	}
	target.Write(value)
}

type mtrRawEvent struct {
	kind        byte
	hop         int
	value       string
	latencyMS   float64
	sequence    int
	hasSequence bool
}

func parseMTRRawEvent(line string) (mtrRawEvent, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 || len(fields[0]) != 1 {
		return mtrRawEvent{}, false
	}
	position, err := strconv.Atoi(fields[1])
	if err != nil || position < 0 {
		return mtrRawEvent{}, false
	}
	event := mtrRawEvent{kind: fields[0][0], hop: position + 1}
	switch event.kind {
	case 'x':
		if sequence, err := strconv.Atoi(fields[2]); err == nil {
			event.sequence = sequence
			event.hasSequence = true
		}
		return event, true
	case 'h':
		event.value = strings.TrimSpace(fields[2])
		return event, event.value != ""
	case 'p':
		latencyUS, err := strconv.ParseFloat(fields[2], 64)
		if err != nil || latencyUS < 0 {
			return mtrRawEvent{}, false
		}
		event.latencyMS = latencyUS / 1000
		if len(fields) > 3 {
			if sequence, err := strconv.Atoi(fields[3]); err == nil {
				event.sequence = sequence
				event.hasSequence = true
			}
		}
		return event, true
	default:
		return mtrRawEvent{}, false
	}
}

func runMTRReport(ctx context.Context, cfg *mtrRunConfig, cycles int) (map[string]any, []byte, error, error) {
	if cfg == nil {
		return nil, nil, nil, errors.New("mtr config is required")
	}
	if cycles < 1 {
		cycles = 1
	}
	baseArgs := []string{"-r", "-c", strconv.Itoa(cycles), "-i", strconv.Itoa(mtrSampleIntervalSeconds), "-m", strconv.Itoa(cfg.MaxHops), "-n"}
	switch cfg.Protocol {
	case "udp":
		baseArgs = append(baseArgs, "-u")
	case "tcp":
		baseArgs = append(baseArgs, "-T")
	}
	args := append(append([]string{}, baseArgs...), "-j", cfg.Target)
	out, cmdErr := mtrCommandContext(ctx, cfg.Path, args...).CombinedOutput()
	result, parseErr := parseMTRJSON(out)
	if parseErr != nil {
		if mtrShouldFallbackToText(out, cmdErr) {
			textArgs := append(append([]string{}, baseArgs...), cfg.Target)
			out, cmdErr = mtrCommandContext(ctx, cfg.Path, textArgs...).CombinedOutput()
			result = parseMTRText(out)
			parseErr = nil
			if len(mtrHops(result)) == 0 {
				parseErr = errors.New("mtr text report is missing hops")
			}
		}
		if cmdErr != nil {
			return nil, out, cmdErr, fmt.Errorf("mtr failed: %s", strings.TrimSpace(string(out)))
		}
		if parseErr != nil {
			return nil, out, cmdErr, parseErr
		}
	}
	return result, out, cmdErr, nil
}

func finalizeMTRResult(ctx context.Context, cfg *mtrRunConfig, started time.Time, result map[string]any, raw []byte, cmdErr error) map[string]any {
	targetIP := cfg.Target
	hops, _ := result["hops"].([]map[string]any)
	result["mtr"] = elapsedMS(started)
	result["hop_count"] = len(hops)
	result["max_hops"] = cfg.MaxHops
	result["report_cycles"] = cfg.ReportCycles
	result["completed_count"] = cfg.ReportCycles
	result["sample_count"] = cfg.ReportCycles
	result["protocol"] = cfg.Protocol
	result["reached"] = traceReachedTarget(hops, targetIP)
	result["raw_output"] = strings.TrimSpace(string(raw))
	if targetIP != "" {
		result["target_ip"] = targetIP
	}
	if cmdErr != nil {
		result["command_error"] = cmdErr.Error()
	}
	return result
}

func mtrHops(result map[string]any) []map[string]any {
	if result == nil {
		return nil
	}
	hops, _ := result["hops"].([]map[string]any)
	return hops
}

type mtrAggregate struct {
	cfg            *mtrRunConfig
	started        time.Time
	targetIP       string
	completedCount int
	hops           map[int]*mtrHopStats
}

type mtrHopStats struct {
	hop            int
	sent           int
	received       int
	latency        mtrLatencyStats
	currentPath    string
	paths          map[string]*mtrPathStats
	sentSequences  map[int]struct{}
	replySequences map[int]struct{}
}

type mtrPathStats struct {
	host     string
	ip       string
	received int
	latency  mtrLatencyStats
}

type mtrLatencyStats struct {
	count int
	sum   float64
	sumSq float64
	best  float64
	worst float64
	last  float64
}

func newMTRAggregate(cfg *mtrRunConfig, started time.Time, targetIP string) *mtrAggregate {
	return &mtrAggregate{
		cfg:      cfg,
		started:  started,
		targetIP: targetIP,
		hops:     map[int]*mtrHopStats{},
	}
}

func (a *mtrAggregate) hopStats(hop int) *mtrHopStats {
	if a == nil || hop <= 0 || a.cfg == nil || hop > a.cfg.MaxHops {
		return nil
	}
	stats := a.hops[hop]
	if stats == nil {
		stats = &mtrHopStats{
			hop:            hop,
			paths:          map[string]*mtrPathStats{},
			sentSequences:  map[int]struct{}{},
			replySequences: map[int]struct{}{},
		}
		a.hops[hop] = stats
	}
	return stats
}

func (a *mtrAggregate) addTransmit(hop int, sequence int, hasSequence bool) bool {
	stats := a.hopStats(hop)
	if stats == nil {
		return false
	}
	if hasSequence {
		if _, exists := stats.sentSequences[sequence]; exists {
			return false
		}
		stats.sentSequences[sequence] = struct{}{}
	}
	stats.sent++
	return true
}

func (a *mtrAggregate) hasTransmit(hop int, sequence int, hasSequence bool) bool {
	if a == nil || !hasSequence {
		return false
	}
	stats := a.hops[hop]
	if stats == nil {
		return false
	}
	_, exists := stats.sentSequences[sequence]
	return exists
}

func (a *mtrAggregate) setPath(hop int, value string) {
	stats := a.hopStats(hop)
	value = strings.TrimSpace(value)
	if stats == nil || value == "" {
		return
	}
	key := value
	path := stats.paths[key]
	if path == nil {
		path = &mtrPathStats{}
		stats.paths[key] = path
	}
	if ip := net.ParseIP(value); ip != nil {
		path.ip = ip.String()
		key = path.ip
		if key != value {
			delete(stats.paths, value)
			stats.paths[key] = path
		}
	} else {
		path.host = value
	}
	stats.currentPath = key
}

func (a *mtrAggregate) addReply(hop int, latencyMS float64, sequence int, hasSequence bool) {
	stats := a.hopStats(hop)
	if stats == nil {
		return
	}
	if hasSequence {
		if _, exists := stats.replySequences[sequence]; exists {
			return
		}
		stats.replySequences[sequence] = struct{}{}
		if _, exists := stats.sentSequences[sequence]; !exists {
			stats.sentSequences[sequence] = struct{}{}
			stats.sent++
		}
	} else if stats.sent <= stats.received {
		stats.sent++
	}
	stats.received++
	stats.latency.add(latencyMS)
	key := stats.currentPath
	if key == "" {
		key = "unknown"
	}
	path := stats.paths[key]
	if path == nil {
		path = &mtrPathStats{host: key}
		stats.paths[key] = path
	}
	path.received++
	path.latency.add(latencyMS)
}

func (a *mtrAggregate) sentCount(hop int) int {
	if a == nil || a.hops[hop] == nil {
		return 0
	}
	return a.hops[hop].sent
}

func (a *mtrAggregate) summary() map[string]any {
	if a == nil || a.cfg == nil {
		return nil
	}
	hops := make([]map[string]any, 0, len(a.hops))
	for hop := 1; hop <= a.cfg.MaxHops; hop++ {
		stats := a.hops[hop]
		if stats == nil {
			continue
		}
		hops = append(hops, stats.summary())
	}
	result := map[string]any{
		"hops":            hops,
		"mtr":             elapsedMS(a.started),
		"hop_count":       len(hops),
		"max_hops":        a.cfg.MaxHops,
		"report_cycles":   a.cfg.ReportCycles,
		"sample_count":    a.cfg.ReportCycles,
		"completed_count": a.completedCount,
		"protocol":        a.cfg.Protocol,
		"reached":         traceReachedTarget(hops, a.targetIP),
	}
	if a.targetIP != "" {
		result["target_ip"] = a.targetIP
	}
	return result
}

func (s *mtrHopStats) summary() map[string]any {
	hop := map[string]any{"hop": s.hop, "sent": s.sent}
	if s.sent > 0 {
		lost := max(0, s.sent-s.received)
		hop["loss_percent"] = math.Round((float64(lost)*100/float64(s.sent))*10) / 10
	}
	s.latency.apply(hop)
	paths := s.pathSummaries()
	if len(paths) == 1 {
		copyMTRPathIdentity(hop, paths[0])
	} else if len(paths) > 1 {
		hop["multipath"] = true
		hop["path_count"] = len(paths)
		hop["paths"] = paths
	}
	if s.received == 0 && s.sent > 0 {
		hop["timeout"] = true
	}
	return hop
}

func (s *mtrHopStats) pathSummaries() []map[string]any {
	if s == nil || len(s.paths) == 0 {
		return nil
	}
	paths := make([]map[string]any, 0, len(s.paths))
	for _, stats := range s.paths {
		if stats == nil || (stats.ip == "" && stats.host == "") {
			continue
		}
		path := map[string]any{"received": stats.received}
		if stats.ip != "" {
			path["ip"] = stats.ip
		}
		if stats.host != "" && stats.host != "unknown" {
			path["host"] = stats.host
		}
		stats.latency.apply(path)
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		left := intFromAnyDefault(paths[i]["received"], 0)
		right := intFromAnyDefault(paths[j]["received"], 0)
		if left != right {
			return left > right
		}
		return firstNonEmptyMTRPathValue(paths[i]) < firstNonEmptyMTRPathValue(paths[j])
	})
	return paths
}

func (s *mtrLatencyStats) add(latencyMS float64) {
	if s == nil || latencyMS < 0 {
		return
	}
	s.count++
	s.sum += latencyMS
	s.sumSq += latencyMS * latencyMS
	s.last = latencyMS
	if s.count == 1 || latencyMS < s.best {
		s.best = latencyMS
	}
	if s.count == 1 || latencyMS > s.worst {
		s.worst = latencyMS
	}
}

func (s *mtrLatencyStats) apply(target map[string]any) {
	if s == nil || target == nil || s.count == 0 {
		return
	}
	target["last_ms"] = roundMTRMillis(s.last)
	target["avg_ms"] = roundMTRMillis(s.sum / float64(s.count))
	target["best_ms"] = roundMTRMillis(s.best)
	target["worst_ms"] = roundMTRMillis(s.worst)
	if s.count > 1 {
		mean := s.sum / float64(s.count)
		variance := (s.sumSq / float64(s.count)) - (mean * mean)
		if variance < 0 {
			variance = 0
		}
		target["stdev_ms"] = roundMTRMillis(math.Sqrt(variance))
	}
}

func roundMTRMillis(value float64) float64 {
	return math.Round(value*1000) / 1000
}

func copyMTRPathIdentity(target map[string]any, path map[string]any) {
	if target == nil || path == nil {
		return
	}
	for _, key := range []string{"ip", "host"} {
		if value := strings.TrimSpace(fmt.Sprint(path[key])); value != "" && value != "<nil>" {
			target[key] = value
		}
	}
}

func firstNonEmptyMTRPathValue(path map[string]any) string {
	return firstNonEmptyStringAgent(stringFromMap(path, "ip"), stringFromMap(path, "host"))
}

type mtrProgressEmitter struct {
	updates   chan map[string]any
	done      chan struct{}
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func newMTRProgressEmitter(parent context.Context, cfg config, task taskRequest) *mtrProgressEmitter {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	emitter := &mtrProgressEmitter{
		updates: make(chan map[string]any, 1),
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	report := mtrProgressReporter(ctx, cfg, task)
	go func() {
		defer close(emitter.done)
		for summary := range emitter.updates {
			report(summary)
		}
	}()
	return emitter
}

func (e *mtrProgressEmitter) Emit(summary map[string]any) {
	if e == nil || summary == nil {
		return
	}
	snapshot := cloneAnyMap(summary)
	select {
	case e.updates <- snapshot:
		return
	default:
	}
	select {
	case <-e.updates:
	default:
	}
	select {
	case e.updates <- snapshot:
	default:
	}
}

func (e *mtrProgressEmitter) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		e.cancel()
		close(e.updates)
		select {
		case <-e.done:
		case <-time.After(time.Second):
		}
	})
}

func mtrProgressReporter(ctx context.Context, cfg config, task taskRequest) func(map[string]any) {
	return func(summary map[string]any) {
		completed := intFromAnyDefault(summary["completed_count"], 0)
		total := intFromAnyDefault(summary["report_cycles"], intFromAnyDefault(summary["sample_count"], 0))
		if completed <= 0 || total <= 0 {
			return
		}
		progress := int(math.Round(float64(completed) * 100 / float64(total)))
		if progress < 1 {
			progress = 1
		}
		if progress > 100 {
			progress = 100
		}
		extra := cloneAnyMap(summary)
		extra["event_kind"] = "mtr_report"
		extra["task_type"] = "mtr"
		extra["live_running"] = true
		event := taskEvent{
			TaskID:    task.ID,
			Status:    "running",
			Message:   fmt.Sprintf("mtr report %d/%d", completed, total),
			Progress:  progress,
			Extra:     extra,
			CreatedAt: time.Now().UTC(),
		}
		reportCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := postAgentJSON(reportCtx, cfg, "/api/agent/v1/tasks/"+url.PathEscape(task.ID)+"/events", event, nil); err != nil {
			log.Printf("report task event failed task_id=%s: %v", task.ID, err)
		}
	}
}

func mtrPositiveFloat(raw any) float64 {
	value, ok := floatFromAny(raw)
	if !ok || value <= 0 {
		return 0
	}
	return value
}

func firstPositiveMTRFloat(values ...any) float64 {
	for _, value := range values {
		if parsed := mtrPositiveFloat(value); parsed > 0 {
			return parsed
		}
	}
	return 0
}

func mtrClampedLossPercent(raw any) float64 {
	value, ok := floatFromAny(raw)
	if !ok {
		return 0
	}
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func parseMTRJSON(raw []byte) (map[string]any, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse mtr json: %w", err)
	}
	report, _ := doc["report"].(map[string]any)
	if report == nil {
		return nil, errors.New("mtr json report is missing")
	}
	rawHubs, _ := report["hubs"].([]any)
	hops := make([]map[string]any, 0, len(rawHubs))
	for _, rawHub := range rawHubs {
		hub, _ := rawHub.(map[string]any)
		if hub == nil {
			continue
		}
		hop := map[string]any{}
		if value := intFromAny(hub["count"]); value > 0 {
			hop["hop"] = value
		}
		host := strings.TrimSpace(fmt.Sprint(hub["host"]))
		if host != "" && host != "<nil>" {
			hop["host"] = host
			if ip := net.ParseIP(host); ip != nil {
				hop["ip"] = ip.String()
			}
		}
		copyMTRFloat(hop, "loss_percent", hub["Loss%"])
		copyMTRFloat(hop, "sent", hub["Snt"])
		copyMTRFloat(hop, "last_ms", hub["Last"])
		copyMTRFloat(hop, "avg_ms", hub["Avg"])
		copyMTRFloat(hop, "best_ms", hub["Best"])
		copyMTRFloat(hop, "worst_ms", hub["Wrst"])
		copyMTRFloat(hop, "stdev_ms", hub["StDev"])
		hops = append(hops, hop)
	}
	return map[string]any{"hops": hops}, nil
}

func mtrJSONUnsupported(raw []byte) bool {
	text := strings.ToLower(strings.TrimSpace(string(raw)))
	return strings.Contains(text, "invalid option") &&
		(strings.Contains(text, "-j") || strings.Contains(text, "'j'") || strings.Contains(text, " j") || strings.Contains(text, "--json") || strings.Contains(text, "json"))
}

func mtrShouldFallbackToText(raw []byte, cmdErr error) bool {
	if mtrJSONUnsupported(raw) {
		return true
	}
	text := strings.TrimLeft(string(raw), " \t\r\n")
	if text == "" || strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		return false
	}
	lower := strings.ToLower(text)
	if mtrLooksLikeTextReport(lower) {
		return true
	}
	return cmdErr == nil &&
		(strings.Contains(lower, "mtr") || strings.Contains(lower, "usage") || strings.Contains(lower, "invalid option") || strings.Contains(lower, "unknown option"))
}

func mtrLooksLikeTextReport(lower string) bool {
	return strings.Contains(lower, "loss%") &&
		(strings.Contains(lower, "snt") || strings.Contains(lower, "|--"))
}

func parseMTRText(raw []byte) map[string]any {
	hops := make([]map[string]any, 0)
	for _, line := range strings.Split(string(raw), "\n") {
		hop := parseMTRTextHop(line)
		if hop != nil {
			hops = append(hops, hop)
		}
	}
	return map[string]any{"hops": hops}
}

func parseMTRTextHop(line string) map[string]any {
	line = strings.TrimSpace(line)
	if line == "" || !strings.Contains(line, "|") {
		return nil
	}
	separator := "|--"
	separatorIndex := strings.Index(line, separator)
	if separatorIndex < 0 {
		separator = "|"
		separatorIndex = strings.Index(line, separator)
	}
	left := strings.TrimSpace(line[:separatorIndex])
	right := strings.TrimSpace(line[separatorIndex+len(separator):])
	hopToken := strings.TrimSuffix(strings.TrimSpace(left), ".")
	hopNumber, err := strconv.Atoi(strings.TrimSpace(hopToken))
	if err != nil || hopNumber <= 0 {
		return nil
	}
	hop := map[string]any{"hop": hopNumber}
	fields := strings.Fields(right)
	if len(fields) == 0 {
		hop["timeout"] = true
		return hop
	}
	metricIndex := mtrTextMetricStart(fields)
	if metricIndex < 0 {
		metricIndex = len(fields)
	}
	hostText := strings.TrimSpace(strings.Join(fields[:metricIndex], " "))
	if hostText == "???" || hostText == "" {
		hop["timeout"] = true
	} else {
		host := strings.Fields(hostText)[0]
		hop["host"] = strings.Trim(host, "()")
		for _, field := range strings.Fields(hostText) {
			if ip := net.ParseIP(strings.Trim(field, "()")); ip != nil {
				hop["ip"] = ip.String()
				break
			}
		}
	}
	metrics := fields[metricIndex:]
	if len(metrics) >= 2 {
		setMTRTextFloat(hop, "loss_percent", metrics[0])
		setMTRTextFloat(hop, "sent", metrics[1])
	}
	if len(metrics) >= 7 {
		setMTRTextFloat(hop, "last_ms", metrics[2])
		setMTRTextFloat(hop, "avg_ms", metrics[3])
		setMTRTextFloat(hop, "best_ms", metrics[4])
		setMTRTextFloat(hop, "worst_ms", metrics[5])
		setMTRTextFloat(hop, "stdev_ms", metrics[6])
	}
	return hop
}

func mtrTextMetricStart(fields []string) int {
	for index := 0; index < len(fields)-1; index++ {
		loss := strings.TrimSuffix(strings.TrimSpace(fields[index]), "%")
		if _, err := strconv.ParseFloat(loss, 64); err != nil {
			continue
		}
		if _, err := strconv.ParseFloat(strings.TrimSpace(fields[index+1]), 64); err == nil {
			return index
		}
	}
	return -1
}

func setMTRTextFloat(hop map[string]any, key string, raw string) {
	value := strings.TrimSpace(strings.TrimSuffix(raw, "%"))
	if value == "" {
		return
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err == nil {
		hop[key] = parsed
	}
}

func copyMTRFloat(target map[string]any, key string, raw any) {
	if value, ok := floatFromAny(raw); ok {
		target[key] = value
	}
}
