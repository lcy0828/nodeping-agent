//go:build unbound_native_e2e && !windows

package dnstapcollector

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const nativeE2EName = "fixture.nodeping.test."

const (
	nativeE2ERootName = "a.root-servers.net."
	nativeE2ERootIP   = "127.0.0.253"
)

func TestPatchedUnboundNativeDNSTapE2E(t *testing.T) {
	unboundPath := requiredExecutable(t, "NODEPING_UNBOUND_BINARY")
	checkconfPath := requiredExecutable(t, "NODEPING_UNBOUND_CHECKCONF_BINARY")
	workDir := t.TempDir()
	if err := os.Chmod(workDir, 0o700); err != nil {
		t.Fatalf("chmod work directory: %v", err)
	}

	stopAuthority := startNativeE2EAuthority(t)
	defer stopAuthority()
	unboundPort := reserveLoopbackPort(t)

	listenerBase, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatalf("resolve collector temporary root: %v", err)
	}
	listener, err := OpenListener(listenerBase)
	if err != nil {
		t.Fatalf("open collector listener: %v", err)
	}
	defer listener.Close()

	configPath := filepath.Join(workDir, "unbound.conf")
	rootHintsPath := filepath.Join(workDir, "root.hints")
	rootHints := fmt.Sprintf(". 3600000 IN NS %s\n%s 3600000 IN A %s\n", nativeE2ERootName, nativeE2ERootName, nativeE2ERootIP)
	if err := os.WriteFile(rootHintsPath, []byte(rootHints), 0o600); err != nil {
		t.Fatalf("write root hints: %v", err)
	}
	config := nativeE2EConfig(workDir, rootHintsPath, listener.Endpoint(), unboundPort)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write Unbound config: %v", err)
	}
	check := exec.Command(checkconfPath, configPath)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("unbound-checkconf failed: %v\n%s", err, output)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	collected := make(chan Result, 1)
	collectorError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			collectorError <- acceptErr
			return
		}
		collected <- NewDefault().Collect(ctx, connection)
	}()

	var processOutput bytes.Buffer
	command := exec.Command(unboundPath, "-d", "-c", configPath)
	command.Stdout = &processOutput
	command.Stderr = &processOutput
	if err := command.Start(); err != nil {
		t.Fatalf("start Unbound: %v", err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	defer stopNativeE2EProcess(command, processDone)

	response := queryNativeE2EUnbound(t, ctx, unboundPort, processDone, &processOutput)
	if len(response.Answer) != 1 || response.Answer[0].String() != nativeE2EName+"\t0\tIN\tA\t192.0.2.123" {
		t.Fatalf("Unbound answer = %v", response.Answer)
	}

	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal Unbound: %v", err)
	}
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatalf("Unbound exit: %v\n%s", err, processOutput.String())
		}
	case <-ctx.Done():
		t.Fatalf("Unbound did not exit after TERM: %v\n%s", ctx.Err(), processOutput.String())
	}

	var result Result
	select {
	case err := <-collectorError:
		t.Fatalf("collector accept: %v", err)
	case result = <-collected:
	case <-ctx.Done():
		t.Fatalf("collector did not finish: %v", ctx.Err())
	}
	if !result.Complete || result.Status != CollectionComplete {
		t.Fatalf("collector result = %s, error=%v\n%s", result.Status, result.Error, processOutput.String())
	}
	if result.FrameCount != 4 || len(result.Events) != 4 ||
		result.Pairing.Integrity != PairingExact || result.Pairing.Matched != 2 ||
		result.Pairing.NoResponse != 0 || result.Pairing.OrphanResponses != 0 ||
		result.Pairing.Ambiguous != 0 || len(result.Exchanges) != 2 {
		t.Fatalf("pairing = %+v, exchanges=%d, frames=%d\n%s", result.Pairing, len(result.Exchanges), result.FrameCount, processOutput.String())
	}
	matchedQuestions := make(map[Question]int, 2)
	for _, exchange := range result.Exchanges {
		if exchange.Status != PairMatched {
			t.Fatalf("exchange = %+v\n%s", exchange, processOutput.String())
		}
		for _, event := range result.Events {
			if event.Sequence == exchange.QuerySequence {
				matchedQuestions[event.Question]++
				break
			}
		}
	}
	expectedQuestions := map[Question]int{
		{Name: ".", Type: dns.TypeNS, Class: dns.ClassINET}:          1,
		{Name: nativeE2EName, Type: dns.TypeA, Class: dns.ClassINET}: 1,
	}
	if !reflect.DeepEqual(matchedQuestions, expectedQuestions) {
		t.Fatalf("matched questions = %+v, want %+v\n%s", matchedQuestions, expectedQuestions, processOutput.String())
	}
}

func requiredExecutable(t *testing.T, environmentName string) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(environmentName))
	if path == "" {
		t.Fatalf("%s is required", environmentName)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", environmentName, err)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable: %s", environmentName, path)
	}
	return path
}

func startNativeE2EAuthority(t *testing.T) func() {
	t.Helper()
	address := net.JoinHostPort(nativeE2ERootIP, "53")
	packet, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatalf("listen iterative authority UDP on %s (run this tagged test with elevated privileges): %v", address, err)
	}
	stream, err := net.Listen("tcp4", address)
	if err != nil {
		_ = packet.Close()
		t.Fatalf("listen iterative authority TCP on %s: %v", address, err)
	}
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		if len(request.Question) == 1 {
			switch question := request.Question[0]; {
			case question.Name == "." && question.Qtype == dns.TypeNS:
				response.Answer = []dns.RR{&dns.NS{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600000},
					Ns:  nativeE2ERootName,
				}}
				response.Extra = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: nativeE2ERootName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600000},
					A:   net.ParseIP(nativeE2ERootIP),
				}}
			case question.Name == nativeE2EName && question.Qtype == dns.TypeA:
				response.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: nativeE2EName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 123),
				}}
			default:
				response.Rcode = dns.RcodeNameError
			}
		}
		_ = writer.WriteMsg(response)
	})
	udpServer := &dns.Server{PacketConn: packet, Handler: handler}
	tcpServer := &dns.Server{Listener: stream, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	return func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	}
}

func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve Unbound port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release Unbound port: %v", err)
	}
	return port
}

func nativeE2EConfig(workDir, rootHintsPath, tapEndpoint string, port int) string {
	return fmt.Sprintf(`server:
	directory: %q
	root-hints: %q
	username: ""
	chroot: ""
	pidfile: ""
	interface: 127.0.0.1@%d
	access-control: 127.0.0.0/8 allow
	do-ip4: yes
	do-ip6: no
	do-udp: yes
	do-tcp: yes
	do-daemonize: no
	use-syslog: no
	verbosity: 4
	module-config: "iterator"
	do-not-query-localhost: no
	local-zone: "test." nodefault
	qname-minimisation: no
	cache-min-ttl: 0
	cache-max-ttl: 0
	msg-cache-size: 1m
	rrset-cache-size: 1m
dnstap:
	dnstap-enable: yes
	dnstap-bidirectional: yes
	dnstap-socket-path: %q
	dnstap-send-identity: yes
	dnstap-send-version: yes
	dnstap-identity: "nodeping-native-e2e"
	dnstap-version: "unbound-1.25.1"
	dnstap-log-resolver-query-messages: yes
	dnstap-log-resolver-response-messages: yes
	`, workDir, rootHintsPath, port, tapEndpoint)
}

func queryNativeE2EUnbound(t *testing.T, ctx context.Context, port int, processDone <-chan error, output *bytes.Buffer) *dns.Msg {
	t.Helper()
	client := &dns.Client{Net: "udp", Timeout: 250 * time.Millisecond}
	query := new(dns.Msg)
	query.SetQuestion(nativeE2EName, dns.TypeA)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for {
		response, _, err := client.ExchangeContext(ctx, query, address)
		if err == nil && response != nil {
			return response
		}
		select {
		case processErr := <-processDone:
			t.Fatalf("Unbound exited before answering: %v\n%s", processErr, output.String())
		case <-ctx.Done():
			t.Fatalf("query Unbound: %v\n%s", ctx.Err(), output.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func stopNativeE2EProcess(command *exec.Cmd, processDone <-chan error) {
	if command.Process == nil || command.ProcessState != nil {
		return
	}
	select {
	case <-processDone:
		return
	default:
	}
	_ = command.Process.Kill()
	select {
	case <-processDone:
	case <-time.After(2 * time.Second):
	}
}
