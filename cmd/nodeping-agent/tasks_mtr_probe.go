package main

import (
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
	"strconv"
	"strings"
	"time"
)

type mtrRunConfig struct {
	Target       string
	Path         string
	ReportCycles int
	MaxHops      int
	Protocol     string
}

func runMTR(ctx context.Context, target string, options map[string]any) (map[string]any, error) {
	cfg, err := newMTRRunConfig(target, options)
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
	mtrCfg, err := newMTRRunConfig(target, task.Options)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	targetIP := firstResolvedIP(ctx, mtrCfg.Target)
	aggregate := newMTRAggregate(mtrCfg, started, targetIP)
	reportProgress := mtrProgressReporter(ctx, cfg, task)
	var lastRaw []byte
	var lastCmdErr error
	for cycle := 1; cycle <= mtrCfg.ReportCycles; cycle++ {
		report, raw, cmdErr, err := runMTRReport(ctx, mtrCfg, 1)
		if err != nil {
			if aggregate.completedCount > 0 {
				result := aggregate.summary()
				result["stopped_early"] = true
				result["stop_reason"] = err.Error()
				result["raw_output"] = strings.TrimSpace(string(lastRaw))
				if lastCmdErr != nil {
					result["command_error"] = lastCmdErr.Error()
				}
				return result, nil
			}
			return nil, err
		}
		lastRaw = raw
		lastCmdErr = cmdErr
		aggregate.addReport(report)
		reportProgress(aggregate.summary())
	}
	result := aggregate.summary()
	result["raw_output"] = strings.TrimSpace(string(lastRaw))
	if lastCmdErr != nil {
		result["command_error"] = lastCmdErr.Error()
	}
	return result, nil
}

func newMTRRunConfig(target string, options map[string]any) (*mtrRunConfig, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("mtr target is required")
	}
	path, err := exec.LookPath("mtr")
	if err != nil {
		return nil, errors.New("mtr command not found")
	}
	reportCycles := intOption(options, "report_cycles", 5)
	if reportCycles < 1 {
		reportCycles = 1
	}
	if reportCycles > 20 {
		reportCycles = 20
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
		Target:       target,
		Path:         path,
		ReportCycles: reportCycles,
		MaxHops:      maxHops,
		Protocol:     protocol,
	}, nil
}

func runMTRReport(ctx context.Context, cfg *mtrRunConfig, cycles int) (map[string]any, []byte, error, error) {
	if cfg == nil {
		return nil, nil, nil, errors.New("mtr config is required")
	}
	if cycles < 1 {
		cycles = 1
	}
	baseArgs := []string{"-r", "-c", strconv.Itoa(cycles), "-m", strconv.Itoa(cfg.MaxHops), "-n"}
	switch cfg.Protocol {
	case "udp":
		baseArgs = append(baseArgs, "-u")
	case "tcp":
		baseArgs = append(baseArgs, "-T")
	}
	args := append(append([]string{}, baseArgs...), "-j", cfg.Target)
	out, cmdErr := exec.CommandContext(ctx, cfg.Path, args...).CombinedOutput()
	result, parseErr := parseMTRJSON(out)
	if parseErr != nil {
		if mtrShouldFallbackToText(out, cmdErr) {
			textArgs := append(append([]string{}, baseArgs...), cfg.Target)
			out, cmdErr = exec.CommandContext(ctx, cfg.Path, textArgs...).CombinedOutput()
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
	targetIP := firstResolvedIP(ctx, cfg.Target)
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
	hop          int
	host         string
	ip           string
	sent         float64
	lost         float64
	latencyCount int
	latencySum   float64
	latencySumSq float64
	bestMS       float64
	worstMS      float64
	lastMS       float64
	timeout      bool
	lastSample   map[string]any
}

func newMTRAggregate(cfg *mtrRunConfig, started time.Time, targetIP string) *mtrAggregate {
	return &mtrAggregate{
		cfg:      cfg,
		started:  started,
		targetIP: targetIP,
		hops:     map[int]*mtrHopStats{},
	}
}

func (a *mtrAggregate) addReport(report map[string]any) {
	if a == nil {
		return
	}
	a.completedCount++
	for index, hop := range mtrHops(report) {
		hopNumber := intFromAnyDefault(hop["hop"], index+1)
		if hopNumber <= 0 {
			hopNumber = index + 1
		}
		stats := a.hops[hopNumber]
		if stats == nil {
			stats = &mtrHopStats{hop: hopNumber}
			a.hops[hopNumber] = stats
		}
		stats.addHop(hop)
	}
}

func (s *mtrHopStats) addHop(hop map[string]any) {
	if s == nil || hop == nil {
		return
	}
	s.lastSample = cloneAnyMap(hop)
	if host := strings.TrimSpace(stringFromMap(hop, "host")); host != "" {
		s.host = host
	}
	if ip := strings.TrimSpace(stringFromMap(hop, "ip")); ip != "" {
		s.ip = ip
	}
	sent := mtrPositiveFloat(hop["sent"])
	if sent <= 0 {
		sent = 1
	}
	lossPercent := mtrClampedLossPercent(hop["loss_percent"])
	lost := sent * lossPercent / 100
	if boolFromMap(hop, "timeout") && lossPercent == 0 {
		lost = sent
		lossPercent = 100
	}
	s.sent += sent
	s.lost += lost
	latency := firstPositiveMTRFloat(hop["last_ms"], hop["avg_ms"], hop["rtt_ms"])
	if latency > 0 && lossPercent < 100 {
		s.latencyCount++
		s.latencySum += latency
		s.latencySumSq += latency * latency
		s.lastMS = latency
		best := firstPositiveMTRFloat(hop["best_ms"], latency)
		worst := firstPositiveMTRFloat(hop["worst_ms"], latency)
		if s.bestMS <= 0 || best < s.bestMS {
			s.bestMS = best
		}
		if worst > s.worstMS {
			s.worstMS = worst
		}
	}
	s.timeout = s.latencyCount == 0 && s.lost >= s.sent
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
	hop := map[string]any{"hop": s.hop}
	for key, value := range s.lastSample {
		hop[key] = value
	}
	hop["hop"] = s.hop
	if s.host != "" {
		hop["host"] = s.host
	}
	if s.ip != "" {
		hop["ip"] = s.ip
	}
	if s.sent > 0 {
		hop["sent"] = s.sent
		hop["loss_percent"] = math.Round((s.lost*100/s.sent)*10) / 10
	}
	if s.latencyCount > 0 {
		hop["last_ms"] = s.lastMS
		hop["avg_ms"] = math.Round((s.latencySum/float64(s.latencyCount))*1000) / 1000
		hop["best_ms"] = s.bestMS
		hop["worst_ms"] = s.worstMS
		if s.latencyCount > 1 {
			mean := s.latencySum / float64(s.latencyCount)
			variance := (s.latencySumSq / float64(s.latencyCount)) - (mean * mean)
			if variance < 0 {
				variance = 0
			}
			hop["stdev_ms"] = math.Round(math.Sqrt(variance)*1000) / 1000
		}
	} else if s.timeout {
		hop["timeout"] = true
	}
	return hop
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
