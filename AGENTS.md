# Repository Agent Instructions

## Agent Release Compatibility

These rules apply to every NodePing Agent release (`vM.m.p`):

1. Add a versioned contract at
   `deploy/nodeping-agent/upgrade-compatibility/<release>.env`. Its
   `previous_release` must be the immediately preceding published Agent
   release.
2. Keep `status=compatible` only after the previous-version direct-upgrade
   contract, Go regression tests, and Docker legacy-path smoke test pass.
3. Run `./scripts/agent-upgrade-compatibility.sh gate <release>` before
   creating or pushing the release tag, then run
   `./scripts/ci/test-agent-image-compatibility.sh <release>`.
4. If direct upgrade compatibility cannot be preserved, stop and obtain an
   explicit confirmation from the repository owner. Codex must not change an
   incompatible contract to `compatible`, invent the confirmation phrase, or
   dispatch the approval workflow on the owner's behalf.
5. An incompatible release may be published only by repository owner
   `lcy0828` through the manual Agent Release workflow with the exact
   confirmation shown by the failed compatibility gate.

Existing release tags are immutable. Never move or overwrite a published tag
to bypass the compatibility gate.
