package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"
)

func executeAndReport(ctx context.Context, cfg config, task taskRequest) {
	timeout := time.Duration(task.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	acceptedCtx, acceptedCancel := context.WithTimeout(taskCtx, minDuration(timeout, 2*time.Second))
	if err := postAgentJSON(acceptedCtx, cfg, "/api/agent/v1/tasks/"+url.PathEscape(task.ID)+"/events", taskEvent{
		TaskID: task.ID, Status: "running", Message: "agent started task", CreatedAt: time.Now().UTC(),
	}, nil); err != nil && taskCtx.Err() == nil {
		log.Printf("report task acceptance failed task_id=%s: %v", task.ID, err)
	}
	acceptedCancel()
	result := executeTask(taskCtx, cfg, task)
	reportCtx, reportCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer reportCancel()
	if err := postAgentResultWithRetry(reportCtx, cfg, task.ID, result); err != nil {
		log.Printf("report task result failed task_id=%s: %v", task.ID, err)
	}
}

func minDuration(left time.Duration, right time.Duration) time.Duration {
	if left > 0 && left < right {
		return left
	}
	return right
}

func postAgentResultWithRetry(ctx context.Context, cfg config, taskID string, result taskResult) error {
	endpoint := "/api/agent/v1/tasks/" + url.PathEscape(taskID) + "/result"
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * 500 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		if err := postAgentJSON(ctx, cfg, endpoint, result, nil); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func executeTask(ctx context.Context, cfg config, task taskRequest) taskResult {
	started := time.Now()
	result := taskResult{TaskID: task.ID, Status: "running", FinishedAt: time.Now().UTC()}
	payload, err := payloadMap(task.Payload)
	if err != nil {
		return failTask(task.ID, "INVALID_PAYLOAD", err.Error())
	}
	var latency float64
	var response map[string]any
	var responseIP string
	targetSummary := ""
	switch task.TaskType {
	case "ping":
		target, _ := payloadString(payload, "ping")
		targetSummary = target
		latency, responseIP, err = runPingWithOptions(ctx, target, task.Options)
		response = map[string]any{"ping": latency}
		if responseIP != "" {
			response["response_ip"] = responseIP
		}
	case "tcp_ping":
		target, _ := payloadString(payload, "tcp_ping")
		targetSummary = target
		latency, responseIP, err = runTCPPingWithOptions(ctx, target, task.Options)
		response = map[string]any{"tcp_ping": latency}
		if responseIP != "" {
			response["response_ip"] = responseIP
		}
	case "long_ping":
		target, _ := payloadString(payload, "long_ping")
		targetSummary = target
		response, err = runLongPingWithProgress(ctx, cfg, task, target)
		latency = floatFromMap(response, "avg_latency_ms")
		responseIP = stringFromMap(response, "response_ip")
	case "long_tcp_ping":
		target, _ := payloadString(payload, "long_tcp_ping")
		targetSummary = target
		response, err = runLongTCPPingWithProgress(ctx, cfg, task, target)
		latency = floatFromMap(response, "avg_latency_ms")
		responseIP = stringFromMap(response, "response_ip")
	case "udp_probe":
		target, _ := payloadString(payload, "udp_probe")
		targetSummary = target
		response, err = runUDPProbe(ctx, target, task.Options)
		latency = udpProbeTaskLatency(response)
		responseIP = stringFromMap(response, "response_ip")
	case "http_ping":
		target, httpPingOptions := httpPingPayload(payload)
		targetSummary = target
		latency, responseIP, err = runHTTPPing(ctx, target, mergeAgentOptions(task.Options, httpPingOptions))
		response = map[string]any{"http_ping": latency}
		if responseIP != "" {
			response["response_ip"] = responseIP
		}
	case "http_request":
		target, method, headers, body, publishIPSourceResponseBody := httpRequestPayload(payload)
		targetSummary = target
		latency, responseIP, response, err = runHTTPRequestForTask(ctx, method, target, headers, body, task.Options, publishIPSourceResponseBody)
	case "http3_check":
		target, http3Options := http3CheckPayload(payload)
		targetSummary = target
		response, err = runHTTP3Check(ctx, target, mergeAgentOptions(task.Options, http3Options))
		latency = floatFromMap(response, "http3_check")
		responseIP = stringFromMap(response, "response_ip")
	case "dns_lookup":
		dnsPayload, _ := payload["dns"].(map[string]any)
		if dnsPayload == nil {
			dnsPayload, _ = payload["dns_lookup"].(map[string]any)
		}
		targetSummary = dnsTargetSummary(dnsPayload)
		response, err = runDNSLookup(ctx, dnsPayload)
	case "dns_compare":
		dnsPayload, _ := payload["dns_compare"].(map[string]any)
		if dnsPayload == nil {
			dnsPayload = payload
		}
		targetSummary = dnsTargetSummary(dnsPayload)
		response, err = runDNSCompare(ctx, dnsPayload, task.Options)
	case "tls_check":
		tlsPayload := tlsCheckPayload(payload)
		targetSummary = tlsTargetSummary(tlsPayload)
		response, err = runTLSCheck(ctx, tlsPayload, task.Options)
		responseIP = stringFromMap(response, "response_ip")
	case "traceroute":
		target, _ := payloadString(payload, "traceroute")
		targetSummary = target
		response, err = runTraceroute(ctx, target, task.Options)
		responseIP = stringFromMap(response, "target_ip")
	case "mtr":
		target, _ := payloadString(payload, "mtr")
		targetSummary = target
		response, err = runMTRWithProgress(ctx, cfg, task, target)
		responseIP = stringFromMap(response, "target_ip")
	case "node_status":
		response, err = runNodeStatus()
	case "ip":
		ip := discoverPublicIP(ctx)
		if ip == "" {
			err = errors.New("public IP discovery failed")
		}
		responseIP = ip
		response = map[string]any{"ip": ip}
	case "agent_doctor":
		response, err = runAgentDoctor(ctx, cfg)
	case "agent_upgrade":
		response, err = runAgentUpgrade(ctx, cfg, payload, task.Options)
	case "agent_dependency_fix":
		response, err = runAgentDependencyFix(ctx, cfg, payload, task.Options)
	default:
		return failTask(task.ID, "UNSUPPORTED_TASK", "unsupported task type: "+task.TaskType)
	}
	result.FinishedAt = time.Now().UTC()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			result.Status = "cancelled"
			result.Success = false
			result.ErrorCode = "TASK_CANCELLED"
			result.ErrorMessage = "task cancelled"
			result.LatencyMS = elapsedMS(started)
			result.ResponseIP = responseIP
			result.Result = response
			result.Extra = taskResultExtra(task, targetSummary)
			return result
		}
		if errors.Is(err, context.DeadlineExceeded) {
			result.Status = "timeout"
			result.Success = false
			result.ErrorCode = "TASK_TIMEOUT"
			result.ErrorMessage = "task timed out"
			result.LatencyMS = elapsedMS(started)
			result.ResponseIP = responseIP
			result.Result = response
			result.Extra = taskResultExtra(task, targetSummary)
			return result
		}
		result.Status = "failed"
		result.Success = false
		result.ErrorCode = "TASK_FAILED"
		result.ErrorMessage = err.Error()
		result.LatencyMS = elapsedMS(started)
		if latency > 0 {
			result.LatencyMS = latency
		}
		result.ResponseIP = responseIP
		result.Result = response
		result.Extra = taskResultExtra(task, targetSummary)
		return result
	}
	if latency <= 0 && task.TaskType != "udp_probe" {
		latency = elapsedMS(started)
	}
	result.Status = "completed"
	result.Success = true
	result.LatencyMS = latency
	result.ResponseIP = responseIP
	result.Result = response
	result.Extra = taskResultExtra(task, targetSummary)
	return result
}

func taskResultExtra(task taskRequest, target string) map[string]any {
	extra := map[string]any{
		"agent_task_id": task.ID,
		"task_type":     task.TaskType,
	}
	if target = strings.TrimSpace(target); target != "" {
		extra["target"] = target
	}
	return extra
}

func udpProbeTaskLatency(response map[string]any) float64 {
	if response == nil {
		return 0
	}
	if boolFromMap(response, "response_received") {
		if latency := floatFromMap(response, "response_latency_ms"); latency > 0 {
			return latency
		}
	}
	if latency := floatFromMap(response, "udp_probe"); latency > 0 {
		return latency
	}
	if latency := floatFromMap(response, "send_latency_ms"); latency > 0 {
		return latency
	}
	return 0
}

func dnsTargetSummary(payload map[string]any) string {
	if len(payload) == 0 {
		return ""
	}
	for _, key := range []string{"domain", "host", "target", "name"} {
		if value := strings.TrimSpace(fmt.Sprint(payload[key])); value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func failTask(taskID string, code string, message string) taskResult {
	return taskResult{TaskID: taskID, Status: "failed", Success: false, ErrorCode: code, ErrorMessage: message, FinishedAt: time.Now().UTC()}
}

func payloadMap(raw json.RawMessage) (map[string]any, error) {
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func payloadString(payload map[string]any, key string) (string, bool) {
	value, ok := payload[key]
	if !ok {
		return "", false
	}
	return strings.TrimSpace(fmt.Sprint(value)), true
}

func tlsCheckPayload(payload map[string]any) map[string]any {
	out := map[string]any{}
	switch value := payload["tls_check"].(type) {
	case map[string]any:
		for key, item := range value {
			out[key] = item
		}
	case string:
		out["target"] = value
	default:
		for key, item := range payload {
			out[key] = item
		}
	}
	for _, key := range []string{"host", "target", "server_name", "port"} {
		if isBlankAny(out[key]) && !isBlankAny(payload[key]) {
			out[key] = payload[key]
		}
	}
	if isBlankAny(out["target"]) && !isBlankAny(out["host"]) {
		out["target"] = out["host"]
	}
	if isBlankAny(out["host"]) && !isBlankAny(out["target"]) {
		out["host"] = out["target"]
	}
	return out
}

func tlsTargetSummary(payload map[string]any) string {
	for _, key := range []string{"target", "host"} {
		if value := strings.TrimSpace(fmt.Sprint(payload[key])); value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func isBlankAny(value any) bool {
	text := strings.TrimSpace(fmt.Sprint(value))
	return value == nil || text == "" || text == "<nil>"
}

func httpRequestPayload(payload map[string]any) (string, string, map[string]string, string, bool) {
	raw, _ := payload["http_request"].(map[string]any)
	if raw == nil {
		raw = payload
	}
	target := strings.TrimSpace(fmt.Sprint(raw["url"]))
	method := strings.ToUpper(strings.TrimSpace(fmt.Sprint(raw["method"])))
	headers := map[string]string{}
	if rawHeaders, ok := raw["headers"].(map[string]any); ok {
		for key, value := range rawHeaders {
			headers[key] = fmt.Sprint(value)
		}
	}
	body := ""
	if raw["body"] != nil {
		body = fmt.Sprint(raw["body"])
	}
	publishIPSourceResponseBody := boolOptionDefault(raw, "publish_ip_source_response_body", false)
	return target, method, headers, body, publishIPSourceResponseBody
}

func httpPingPayload(payload map[string]any) (string, map[string]any) {
	raw, ok := payload["http_ping"].(map[string]any)
	if !ok || raw == nil {
		target, _ := payloadString(payload, "http_ping")
		return target, nil
	}
	target := strings.TrimSpace(firstNonEmptyStringAgent(
		fmt.Sprint(raw["url"]),
		fmt.Sprint(raw["target"]),
	))
	options := map[string]any{}
	if originalHost := strings.TrimSpace(fmt.Sprint(raw["original_host"])); originalHost != "" && originalHost != "<nil>" {
		options["original_host"] = originalHost
	}
	return target, options
}

func http3CheckPayload(payload map[string]any) (string, map[string]any) {
	raw, ok := payload["http3_check"].(map[string]any)
	if !ok || raw == nil {
		target, _ := payloadString(payload, "http3_check")
		return target, nil
	}
	target := strings.TrimSpace(firstNonEmptyStringAgent(
		fmt.Sprint(raw["url"]),
		fmt.Sprint(raw["target"]),
	))
	options := map[string]any{}
	if originalHost := strings.TrimSpace(fmt.Sprint(raw["original_host"])); originalHost != "" && originalHost != "<nil>" {
		options["original_host"] = originalHost
	}
	return target, options
}

func mergeAgentOptions(base map[string]any, overlays ...map[string]any) map[string]any {
	if len(base) == 0 && len(overlays) == 0 {
		return nil
	}
	merged := map[string]any{}
	for key, value := range base {
		merged[key] = value
	}
	for _, overlay := range overlays {
		for key, value := range overlay {
			merged[key] = value
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}
