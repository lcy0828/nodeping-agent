# dnstap collector upstream manifest

This directory records the exact upstream schema and license material used by
`internal/dnstapcollector`. Runtime types come from pinned Go modules; no local
protobuf output is generated or compiled.

| Component | Version | Module sum | License |
| --- | --- | --- | --- |
| `github.com/dnstap/golang-dnstap` | `v0.4.0` | `h1:KRHBoURygdGtBjDI2w4HifJfMAhhOqDuktAokaSa234=` | Apache-2.0 for Go code; the vendored schema is dedicated under CC0-1.0 in its header |
| `github.com/farsightsec/golang-framestream` | `v0.3.0` | `h1:/spFQHucTle/ZIPkYqrfshQqPe2VQEzesH243TjIwqA=` | Apache-2.0 |
| `google.golang.org/protobuf` | `v1.36.11` | `h1:fV6ZwhNocDyBLK0dj+fg8ektcVegBBuEolpbTQyBNVE=` | BSD-3-Clause |

Pinned file hashes:

- `dnstap.proto`: `078039018f8aa49d47de21139a81da576f109705b444fdb1c186e27a4282479f`
- `LICENSE-APACHE-2.0.txt`: `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`
- `LICENSE-PROTOBUF-BSD-3-CLAUSE.txt`: `4835612df0098ca95f8e7d9e3bffcb02358d435dbb38057c844c99d7f725eb20`

Run `go run ./scripts/verify-dnstap-supply-chain.go` from any directory in
the repository. The verifier parses `go list -m -json`, compares the vendored
files byte-for-byte with their module sources, checks every pinned hash and
runs `go mod verify`.

This manifest is not the release SBOM. CycloneDX/SPDX generation and signed
Unbound helper artifacts remain separate P3b/P3c gates.
