package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

func runDNSLookup(ctx context.Context, payload map[string]any) (map[string]any, error) {
	domain := strings.TrimSuffix(strings.TrimSpace(fmt.Sprint(payload["domain"])), ".")
	if domain == "" {
		return nil, errors.New("dns domain is required")
	}
	recordType := "A"
	if records, ok := payload["record_types"].([]any); ok && len(records) > 0 {
		recordType = strings.ToUpper(strings.TrimSpace(fmt.Sprint(records[0])))
	}
	started := time.Now()
	answers, err := lookupDNSRecord(ctx, domain, recordType, payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"answers": answers, "dns_lookup": elapsedMS(started)}, nil
}

func runDNSCompare(ctx context.Context, payload map[string]any, options map[string]any) (map[string]any, error) {
	domain := strings.TrimSpace(fmt.Sprint(payload["domain"]))
	if domain == "" || domain == "<nil>" {
		domain = strings.TrimSpace(fmt.Sprint(payload["target"]))
	}
	if domain == "" || domain == "<nil>" {
		return nil, errors.New("dns_compare domain is required")
	}
	recordType := strings.ToUpper(strings.TrimSpace(fmt.Sprint(payload["record_type"])))
	if recordType == "" || recordType == "<NIL>" {
		recordType = strings.ToUpper(strings.TrimSpace(stringOptionAny(options, "record_type")))
	}
	if recordType == "" {
		recordType = "A"
	}
	resolvers := compareResolvers(payload["resolvers"])
	if len(resolvers) == 0 {
		resolvers = compareResolvers(options["compare_resolvers"])
	}
	if len(resolvers) == 0 {
		resolvers = []string{"system", "223.5.5.5", "119.29.29.29"}
	}
	if len(resolvers) > 6 {
		resolvers = resolvers[:6]
	}
	started := time.Now()
	rows := make([]map[string]any, 0, len(resolvers))
	sets := map[string]int{}
	successes := 0
	for _, resolver := range resolvers {
		rowPayload := map[string]any{
			"domain":       domain,
			"record_types": []any{recordType},
		}
		if !strings.EqualFold(resolver, "system") {
			rowPayload["dns_server"] = resolver
			rowPayload["dns_protocol"] = dnsProtocolFromResolverText(resolver)
		}
		rowStarted := time.Now()
		result, err := runDNSLookup(ctx, rowPayload)
		row := map[string]any{
			"resolver":   resolver,
			"latency_ms": elapsedMS(rowStarted),
			"success":    err == nil,
		}
		if err != nil {
			row["error"] = err.Error()
		} else {
			successes++
			answers, _ := result["answers"].([]map[string]any)
			row["answers"] = answers
			key := answerSetKey(answers)
			row["answer_set_key"] = key
			sets[key]++
		}
		rows = append(rows, row)
	}
	consistent := len(sets) <= 1 && successes == len(resolvers)
	return map[string]any{
		"dns_compare":    elapsedMS(started),
		"domain":         domain,
		"record_type":    recordType,
		"resolvers":      rows,
		"resolver_count": len(resolvers),
		"success_count":  successes,
		"mismatch_count": maxInt(0, len(sets)-1),
		"consistent":     consistent,
	}, nil
}

func lookupDNSRecord(ctx context.Context, domain string, recordType string, payload map[string]any) ([]map[string]any, error) {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordType == "" {
		recordType = "A"
	}
	server := strings.TrimSpace(fmt.Sprint(payload["dns_server"]))
	if server == "" || server == "<nil>" || strings.EqualFold(server, "system") {
		return lookupDNSSystem(ctx, domain, recordType)
	}
	protocol := strings.ToLower(strings.TrimSpace(fmt.Sprint(payload["dns_protocol"])))
	if protocol == "" || protocol == "<nil>" {
		protocol = dnsProtocolFromResolverText(server)
	}
	if protocol == "" {
		protocol = "udp"
	}
	if err := requirePublicResolverHost(ctx, server); err != nil {
		return nil, err
	}
	query, err := buildDNSQueryMessage(domain, recordType, protocol)
	if err != nil {
		return nil, err
	}
	resp, err := exchangeDNSQuery(ctx, server, protocol, query)
	if err != nil {
		return nil, err
	}
	return parseDNSAnswers(resp, recordType)
}

func lookupDNSSystem(ctx context.Context, domain string, recordType string) ([]map[string]any, error) {
	var answers []map[string]any
	switch recordType {
	case "AAAA", "A":
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if recordType == "A" && ip.To4() == nil {
				continue
			}
			if recordType == "AAAA" && ip.To4() != nil {
				continue
			}
			answers = append(answers, map[string]any{"type": recordType, "data": ip.String()})
		}
	case "CNAME":
		cname, err := net.DefaultResolver.LookupCNAME(ctx, domain)
		if err != nil {
			return nil, err
		}
		answers = append(answers, map[string]any{"type": "CNAME", "data": cname})
	case "MX":
		rows, err := net.DefaultResolver.LookupMX(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			answers = append(answers, map[string]any{"type": "MX", "data": row.Host, "preference": row.Pref})
		}
	case "TXT":
		rows, err := net.DefaultResolver.LookupTXT(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			answers = append(answers, map[string]any{"type": "TXT", "data": row})
		}
	case "NS":
		rows, err := net.DefaultResolver.LookupNS(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			answers = append(answers, map[string]any{"type": "NS", "data": row.Host})
		}
	default:
		return nil, fmt.Errorf("unsupported dns record type: %s", recordType)
	}
	return answers, nil
}

func buildDNSQueryMessage(domain string, recordType string, protocol string) ([]byte, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(domain, ".") + ".")
	if err != nil {
		return nil, err
	}
	id := uint16(time.Now().UnixNano())
	if strings.EqualFold(protocol, "doq") {
		id = 0
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsMessageType(recordType), Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func dnsMessageType(recordType string) dnsmessage.Type {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "AAAA":
		return dnsmessage.TypeAAAA
	case "CNAME":
		return dnsmessage.TypeCNAME
	case "MX":
		return dnsmessage.TypeMX
	case "TXT":
		return dnsmessage.TypeTXT
	case "NS":
		return dnsmessage.TypeNS
	default:
		return dnsmessage.TypeA
	}
}

func exchangeDNSQuery(ctx context.Context, server string, protocol string, query []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tcp":
		return exchangeDNSTCP(ctx, dnsServerAddressForProtocol(server, "tcp"), query)
	case "dot":
		return exchangeDNSDoT(ctx, server, dnsServerAddressForProtocol(server, "dot"), query)
	case "doh":
		return exchangeDNSDoH(ctx, server, query)
	case "doq":
		return exchangeDNSDoQ(ctx, server, dnsServerAddressForProtocol(server, "doq"), query)
	default:
		return exchangeDNSUDP(ctx, dnsServerAddressForProtocol(server, "udp"), query)
	}
}

func exchangeDNSUDP(ctx context.Context, serverAddr string, query []byte) ([]byte, error) {
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 3*time.Second)}
	conn, err := dialer.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(deadlineTimeout(ctx, 3*time.Second)))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func exchangeDNSTCP(ctx context.Context, serverAddr string, query []byte) ([]byte, error) {
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 3*time.Second)}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return exchangeDNSFramedAgent(conn, query)
}

func exchangeDNSDoT(ctx context.Context, server string, serverAddr string, query []byte) ([]byte, error) {
	dialer := net.Dialer{Timeout: deadlineTimeout(ctx, 3*time.Second)}
	conn, err := tls.DialWithDialer(&dialer, "tcp", serverAddr, &tls.Config{
		ServerName: dnsTLSServerName(server, serverAddr),
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return exchangeDNSFramedAgent(conn, query)
}

func exchangeDNSDoQ(ctx context.Context, server string, serverAddr string, query []byte) ([]byte, error) {
	conn, err := quic.DialAddr(ctx, serverAddr, &tls.Config{
		ServerName: dnsTLSServerName(server, serverAddr),
		NextProtos: []string{"doq"},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{HandshakeIdleTimeout: deadlineTimeout(ctx, 3*time.Second)})
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	_ = stream.SetDeadline(time.Now().Add(deadlineTimeout(ctx, 3*time.Second)))
	resp, err := exchangeDNSFramedAgent(stream, query)
	_ = stream.Close()
	return resp, err
}

func exchangeDNSDoH(ctx context.Context, server string, query []byte) ([]byte, error) {
	endpoint, err := dohEndpointAgent(server)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("accept", "application/dns-message")
	client := &http.Client{Timeout: deadlineTimeout(ctx, 5*time.Second), Transport: safeHTTPTransport(ctx, "", false), CheckRedirect: safeHTTPRedirectPolicy(false)}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("doh http status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func exchangeDNSFramedAgent(conn io.ReadWriter, query []byte) ([]byte, error) {
	if deadlineConn, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetDeadline(time.Now().Add(3 * time.Second))
	}
	if len(query) > 65535 {
		return nil, fmt.Errorf("dns query is too large")
	}
	prefix := []byte{byte(len(query) >> 8), byte(len(query))}
	if _, err := conn.Write(append(prefix, query...)); err != nil {
		return nil, err
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header))
	if size <= 0 || size > 65535 {
		return nil, fmt.Errorf("invalid dns response size")
	}
	resp := make([]byte, size)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func parseDNSAnswers(resp []byte, recordType string) ([]map[string]any, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(resp)
	if err != nil {
		return nil, err
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("dns resolver returned %s", header.RCode.String())
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var answers []map[string]any
	for {
		resource, err := parser.Answer()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		answer := dnsResourceAnswer(resource)
		if answer == nil {
			continue
		}
		if recordType != "" && !strings.EqualFold(fmt.Sprint(answer["type"]), recordType) {
			if !strings.EqualFold(recordType, "A") || !strings.EqualFold(fmt.Sprint(answer["type"]), "CNAME") {
				continue
			}
		}
		answers = append(answers, answer)
	}
	return answers, nil
}

func dnsResourceAnswer(resource dnsmessage.Resource) map[string]any {
	switch body := resource.Body.(type) {
	case *dnsmessage.AResource:
		return map[string]any{"type": "A", "data": net.IP(body.A[:]).String()}
	case *dnsmessage.AAAAResource:
		return map[string]any{"type": "AAAA", "data": net.IP(body.AAAA[:]).String()}
	case *dnsmessage.CNAMEResource:
		return map[string]any{"type": "CNAME", "data": body.CNAME.String()}
	case *dnsmessage.MXResource:
		return map[string]any{"type": "MX", "data": body.MX.String(), "preference": body.Pref}
	case *dnsmessage.TXTResource:
		return map[string]any{"type": "TXT", "data": strings.Join(body.TXT, "")}
	case *dnsmessage.NSResource:
		return map[string]any{"type": "NS", "data": body.NS.String()}
	default:
		return nil
	}
}

func dnsServerAddress(server string) string {
	return dnsServerAddressForProtocol(server, "udp")
}

func dnsServerAddressForProtocol(server string, protocol string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if strings.Contains(server, "://") {
		if parsed, err := url.Parse(server); err == nil && parsed.Host != "" {
			server = parsed.Host
		}
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	port := "53"
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "dot", "doq":
		port = "853"
	case "doh":
		port = "443"
	}
	if strings.Count(server, ":") > 1 {
		return net.JoinHostPort(strings.Trim(server, "[]"), port)
	}
	return net.JoinHostPort(server, port)
}

func dnsTLSServerName(server string, serverAddr string) string {
	host := strings.TrimSpace(server)
	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil {
			host = parsed.Hostname()
		}
	}
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	if host == "" {
		if splitHost, _, err := net.SplitHostPort(serverAddr); err == nil {
			host = splitHost
		}
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func dohEndpointAgent(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("doh server is required")
	}
	if strings.Contains(server, "://") {
		parsed, err := url.Parse(server)
		if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
			return "", fmt.Errorf("doh server must be an https URL")
		}
		if parsed.Path == "" {
			parsed.Path = "/dns-query"
		}
		parsed.RawQuery = ""
		parsed.Fragment = ""
		parsed.User = nil
		return parsed.String(), nil
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return "https://" + server + "/dns-query", nil
	}
	return "https://" + net.JoinHostPort(strings.Trim(server, "[]"), "443") + "/dns-query", nil
}

func dnsProtocolFromResolverText(resolver string) string {
	resolver = strings.TrimSpace(strings.ToLower(resolver))
	if strings.HasPrefix(resolver, "https://") {
		return "doh"
	}
	return "udp"
}

func compareResolvers(raw any) []string {
	var values []string
	switch rows := raw.(type) {
	case []any:
		for _, item := range rows {
			values = append(values, fmt.Sprint(item))
		}
	case []string:
		values = append(values, rows...)
	case string:
		values = strings.FieldsFunc(rows, func(r rune) bool {
			return r == ',' || r == '\n' || r == ';'
		})
	}
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func answerSetKey(answers []map[string]any) string {
	if len(answers) == 0 {
		return ""
	}
	values := make([]string, 0, len(answers))
	for _, answer := range answers {
		values = append(values, fmt.Sprint(answer["type"])+"="+fmt.Sprint(answer["data"]))
	}
	sort.Strings(values)
	return strings.Join(values, "|")
}
