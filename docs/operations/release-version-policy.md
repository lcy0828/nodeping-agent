# Release Version Policy

NodePing uses two independent release tag series:

- Server: `server-vM.m.p`
- Agent: `vM.m.p`

`M`, `m`, and `p` are each exactly one decimal digit. Release numbers are a
three-digit, base-10 counter rather than a statement of semantic compatibility.
Prerelease suffixes, build metadata, multi-digit components, and `0.0.0` are
not allowed.

## Sequence

The sequence starts and carries as follows:

```text
0.0.1 ... 0.0.9
0.1.0 ... 0.1.9
0.2.0 ... 0.2.9
...
0.9.0 ... 0.9.9
1.0.0
```

Every release must use the next number. Skipping a number, reusing a number,
or moving an existing tag is prohibited. Tags must be annotated and must
resolve to a commit. Server and Agent versions advance independently.

Examples:

```text
valid:   server-v0.2.0  server-v0.2.9  v0.1.0  v1.0.0
invalid: server-v0.1.60 server-v0.2.10 v0.0.0  v0.1.0-rc.1
```

## Existing Tags

Tags created before this policy remain immutable and available for rollback.
They do not authorize another release using the old multi-digit numbering.

The migration baselines are:

- Server: the last policy-compatible historical number is `server-v0.1.9`;
  the next Server release is `server-v0.2.0`.
- Agent: the last policy-compatible historical number is `v0.0.9`; the next
  Agent release is `v0.1.0`.

The release helper ignores legacy tags such as `server-v0.1.60` and `v0.0.38`
when calculating the next new version.

## Release Commands

Inspect the next tag:

```sh
./scripts/release-tag.sh next server
./scripts/release-tag.sh next agent
```

Create and verify an annotated tag:

```sh
release_tag=$(./scripts/release-tag.sh next server)
git tag -a "$release_tag" -m "$release_tag"
./scripts/release-tag.sh verify server "$release_tag"
git push origin main
git push origin "$release_tag"
```

Use `agent` instead of `server` for an Agent release. The Agent GitHub Actions
workflow and the Server TeamCity image-build entry point both run the same
verification before publishing artifacts.

## Agent Upgrade Compatibility

Every Agent release must include a versioned compatibility contract:

```text
deploy/nodeping-agent/upgrade-compatibility/<release>.env
```

The contract names the immediately preceding published Agent release, the
oldest release supported for direct upgrade, the Docker binary paths used by
old host updaters, and the evidence used to mark the release compatible.
Contracts are retained per release so a later release cannot overwrite the
decision recorded for an earlier one.

Before creating or pushing an Agent tag, run:

```sh
release_tag=$(./scripts/release-tag.sh next agent)
./scripts/agent-upgrade-compatibility.sh verify "$release_tag"
go test -count=1 ./cmd/nodeping-agent ./deploy/nodeping-agent
./scripts/ci/test-agent-image-compatibility.sh "$release_tag"
./scripts/agent-upgrade-compatibility.sh gate "$release_tag"
```

The image test builds the candidate and executes `-version` through every
path listed in the contract. This includes paths used by older Docker host
updaters, not only the current image entry point.

If compatibility cannot be preserved, set `status=incompatible` and record a
machine-readable `incompatibility_reason`. A tag-triggered release will then
stop. Only repository owner `lcy0828` may rerun the **Agent Release** workflow
manually, and the owner must enter the exact confirmation printed by the
failed gate:

```text
CONFIRM_INCOMPATIBLE_AGENT_UPGRADE:<previous_release>-><release>
```

Agents and automation must not manufacture this confirmation or dispatch the
manual approval on the owner's behalf.

### Docker v0.0.35 Migration

`v0.0.35` host updaters execute `/usr/local/bin/nodeping-agent` inside the
new container. Newer images keep the canonical binary at
`/usr/local/lib/nodeping-agent/nodeping-agent` and expose the old path as a
compatibility link. When an older Docker deployment still passes
`NODEPING_AGENT_UPGRADE_MODE=request_file`, the current Compose deployment
also explicitly enables promotion to the in-container updater. The first
upgrade is therefore completed by the old host watcher; subsequent upgrades
are handled inside the container.
