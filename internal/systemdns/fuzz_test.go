package systemdns

import "testing"

func FuzzParseResolvConf(f *testing.F) {
	f.Add([]byte("nameserver 127.0.0.53\noptions rotate timeout:2 attempts:3\n"))
	f.Add([]byte("nameserver fe80::53%eth0\nsearch example.com\n"))
	f.Add([]byte("search example.com\n"))
	f.Add([]byte("nameserver 1.1.1.1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver invalid extra\n"))
	f.Add([]byte{0xff, 0x00, '\n'})
	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := ParseResolvConf(input)
		if err != nil {
			return
		}
		if err := validateResult(result, false); err != nil {
			t.Fatalf("successful parse produced invalid result: %v", err)
		}
	})
}

func FuzzParseSCUtilDNS(f *testing.F) {
	f.Add([]byte("resolver #1\nnameserver[0] : 127.0.0.53\norder : 100000\n"))
	f.Add([]byte("resolver #1\ndomain : corp.example\nnameserver[0] : fe80::53\nif_index : 4 (en0)\nflags : Scoped\n"))
	f.Add([]byte("resolver #1\nnameserver[0] : 10.0.0.53.5353\ntimeout : 60\n"))
	f.Add([]byte("resolver #1\ndomain : local\noptions : mdns\ntimeout : 5\n"))
	f.Add([]byte{0xff, 0x00, '\n'})
	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := ParseSCUtilDNS(input)
		if err != nil {
			return
		}
		if err := validateResult(result, false); err != nil {
			t.Fatalf("successful parse produced invalid result: %v", err)
		}
	})
}
