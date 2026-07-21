# Unbound helper upstream manifest

This directory pins the audited delta applied to the future NodePing Unbound
helper. It does not contain a prebuilt helper and does not enable
`dns_observe_v1`.

| Component | Version | Source SHA-256 | Purpose |
| --- | --- | --- | --- |
| Unbound | `1.25.1` | `0fe8b6277b0959cfd17562debac0aa5f71e0b02dc4ffa9c60271c583edab586f` | Recursive resolver and dnstap producer |
| protobuf-c | `1.5.2` | `e2c86271873a79c92b58fef7ebf8de1aa0df4738347a8bd5d4e65a80a16d0d24` | dnstap C runtime and compiler |
| Protobuf | `21.12` (`libprotoc 3.21.12`) | `2c6a36c7b5a55accae063667ef3c55f2642e67476d96d355ff0acb13dbb47f09` | Builds the pinned protobuf-c compiler |
| OpenSSL | `3.5.7` LTS | `a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8` | DNSSEC cryptography and TLS primitives |
| libevent | `2.1.13-stable` | `f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c` | Resolver event loop |
| Expat | `2.8.2` | `3ad89b8588e6644bd4e49981480d48b21289eebbcd4f0a1a4afb1c29f99b6ab4` | XML parsing used by `unbound-anchor` |

Pinned Git tag objects and commits:

| Component | Tag object | Commit |
| --- | --- | --- |
| Unbound `release-1.25.1` | `98c762cbfb8660a6213d5e8fcff7260f8a618705` | `75b6dba593d4fff000434cd64807c6ebd50bd244` |
| Protobuf `v21.12` | `f502b8e9c831bda0bea57d9cbeefca3eb76e4254` | `f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c` |
| protobuf-c `v1.5.2` | lightweight tag | `4719fdd7760624388c2c5b9d6759eb6a47490626` |
| OpenSSL `openssl-3.5.7` | `6ca677c395a4ae4472a12c5857c122ec33b36f66` | `8cf17aaeb4599f8af87fefd810b5b5fee90fe69e` |
| libevent `release-2.1.13-stable` | `211c4234e44e0e7df720f744a0c70be017e39622` | `79ddfb460847999b807cba76d04e73891f29c6ee` |
| Expat `R_2_8_2` | `6738842bf91d354a8683c59c91f5c08c7c72437e` | `c61098da494eea1cbd091118118dcee417faacea` |

Native reproducibility checks use the Unbound commit time as
`SOURCE_DATE_EPOCH=1779265372` and the logical install prefix
`/opt/nodeping/unbound`. OpenSSL is staged under the fixed logical prefix
`/opt/nodeping/unbound/deps/openssl`; other build-only prefixes are passed to
Unbound as stable relative paths. Compiler prefix maps remove random source
roots from the remaining components.

Unbound source URL:
`https://nlnetlabs.nl/downloads/unbound/unbound-1.25.1.tar.gz`.

The online provenance verifier checks each signed archive, detached signature,
and release-key file by SHA-256 before invoking GnuPG in an empty keyring. It
then requires the exact signing and primary fingerprints below:

| Component | Signature SHA-256 | Signing fingerprint | Primary fingerprint |
| --- | --- | --- | --- |
| Unbound | `387296d9a53d59fef89b5ccc3be7a58306fcb3c5febf1e99270ccca9030127a1` | `231018690C4D903EF419146AA144323DEAACDF45` | same |
| OpenSSL | `d3d082bee3f658c31db53af625eceecf29d777c7010394bed5787ebcc98abdf2` | `BA5473A2B0587B07FB27CF2D216094DFD0CB81EF` | same |
| libevent | `d875a6a702adbd0bb28e99e0add5cd9558514d4167068374a3d1676fa9fb31e0` | `7A02B3521DC75C542BA015456AFEE6D49E92B601` | `2133BC600AB133E1D826D173FE43009C4607B1FB` |
| Expat | `7a1b630aa5cbffa6e3dab55d3e0a50438d5b36c61926b3628b59e707af5d3640` | `CB8DE70A90CFBF6C3BF5CC5696262ACFFBD3AEC6` | `3176EF7DB2367F1FCA4F306B1F9B0E909AF37285` |

OpenSSL's authoritative `pubkeys.asc` is pinned by SHA-256 and includes the
retired BA54 release key that signed 3.5.7 plus its cross-certification of the
current canonical trust anchor `B146647E45A7B33947AB226B2A2C87D161692D40`.
Protobuf 21.12 and protobuf-c 1.5.2 do not publish detached signatures for
these release archives; their archive hashes and Git tag object/commit values
are therefore recorded explicitly rather than reported as signed provenance.

Pinned repository hashes:

- `LICENSE-BSD-3-CLAUSE.txt`: `8eb9a16cbfb8703090bbfa3a2028fd46bb351509a2f90dc1001e51fbe6fd45db`
- `LICENSE-EXPAT-MIT.txt`: `31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87`
- `LICENSE-LIBEVENT.txt`: `ff02effc9b331edcdac387d198691bfa3e575e7d244ad10cb826aa51ef085670`
- `LICENSE-PROTOBUF-C-BSD-2-CLAUSE.txt`: `2d1d028bd27f8c85bc970d720519d2069ca6213fcb26b9dea444a7c39d24bbb3`
- `LICENSE-PROTOBUF-BSD-3-CLAUSE.txt`: `6e5e117324afd944dcf67f36cf329843bc1a92229a8cd9bb573d7a83130fea7d`
- `patches/0001-dnstap-deterministic-evidence.patch`: `a42affbccfa7ede0d86672258c8775a69bf02156b299bcc8d55bfc3a791557ae`
- fixture base64 file: `433ac209b6debb835db91aea903ac26d5f43ef6d57e21959e0a3fe0e4c3feac5`
- fixture metadata file: `05fa6bb5a2009c756be24ea435788b400f7991378d7ed40570ebc9d9d142ad9b`
- decoded producer-to-collector fixture: `1d5808f68adac8b66c2c0d51fc2bfbb29b40b62fbd5e47df1afd07db67da9dc2`

The patch has three fail-closed compatibility changes:

1. Resolver query and response events use the same actual network-send
   timestamp, allowing exact pairing without a time-window heuristic.
2. Shutdown drains the current output frame and every registered worker queue
   before STOP. The existing two-second stop-flush timer remains the hard
   deadline; timeout or output failure closes without a valid completion proof.
3. Bidirectional Frame Streams shutdown waits up to Unbound's existing
   two-second stop-flush deadline for a syntactically exact FINISH frame.

On 2026-07-19 the current patch applied cleanly and built from fresh Unbound
1.25.1 source trees on macOS arm64 and Ubuntu 24.04 arm64. The Ubuntu helper
completed 20 immediate-TERM local iterative queries with exactly four data
frames (`. NS` and `fixture.nodeping.test. A`, query and response), followed by
`STOP/FINISH`; no one-second producer delay is present in the test. Both hosts
then produced identical unsigned helper hashes from two random build roots
while statically linking the pinned OpenSSL, libevent, Expat, and protobuf-c
libraries. Hosted-runner evidence for these workflows, the other native
targets, pinned release toolchains, reproducible six-target release builds,
signing, notarization, and final SBOMs remain P3b/P3c release gates.
