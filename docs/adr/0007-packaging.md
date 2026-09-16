# ADR-0007: macOS Packaging and Signing

Status: Proposed
Date: 2026-09-12
Tasks: MOP-061, MOP-072

## Context

Broker, adapters, launch configuration, macOS privacy permissions, updates, and the future helper need stable identities, ownership, signing, installation, rollback, and uninstall behavior.

## Required decision

Define bundle/process identities, code-signing and notarization needs, installation paths, launchd ownership, file permissions, update authority, migration sequencing, helper authorization, TCC/Accessibility/Automation permission UX, rollback, uninstall, and credential cleanup.

## Constraints

The model cannot grant OS permissions, install persistence, alter update authority, or bypass security prompts. The privileged helper is packaged and authenticated separately. Uninstall and emergency disable must remove remote execution authority and verify the result.

## Acceptance evidence

Fresh install, upgrade, downgrade rejection, rollback, signature failure, partial install, permission denial/revocation, helper mismatch, uninstall, and stale-credential tests are required.

## Candidate implementation evidence

Revision `a06eb81` extends startup assembly so the active Edge and Authority
key configurations are restored before constructing the native Broker and a
separate owner-only Authority channel. The channel has an independent socket,
explicit native peer identity, ordered runtime lifecycle, reverse cleanup, and
defensive key wiping. This remains startup-assembly evidence only; no
persistent LaunchAgent or production service was installed.

Revision `f47ecc5` adds a dedicated protected Authority Control key
configuration. Exactly one operator key is selected from an explicit file or
Keychain source, bound to a secret digest, rejected when revoked or outside
its validity window, and activated through audited monotonic revision history
with exact restart restore. The host-only uninstall assembly constructs its
authenticated IPC client from that activated manager. This remains a
host-only candidate; production Keychain ACL review, signed packaging,
launchd startup, live rotation/deletion, and final host evidence remain open.

Revision `eeebec3` binds the uninstall coordinator to the real owner-only
`AuthorityControlIpcClient`. The client authenticates complete commands and
responses, rejects replay through the durable authority ledger, validates the
owner-only socket and stable target identity, and supplies bounded switch and
revocation readback. The action factory is idempotent and exact-Edge-bound.
This is still a host-only library boundary; protected key delivery, installed
launchd startup, live uninstall, and final host evidence are not established.

Revision `f24b506` adds a host-only uninstall coordinator that requires the
separately authenticated authority channel to disable the global kill switch
and revoke the selected Edge before any plist or launchd removal. It requires
authority readback before and after uninstall and never restores authority
automatically after a failure. This strengthens the proposed uninstall
sequence but does not accept the ADR or prove installed packaging.

Source revisions `fde7341`, `5804f04`, `8fe6663`, `b4945c3`, `662801b`, and `c59983e` add a bounded launchd plist renderer, an unprivileged LaunchAgent template, a signal-aware `BrokerServiceEntrypoint`, a host-only install-plan executor, double-`lstat` filesystem checks, and temporary-root-tested descriptor-relative plist install/upgrade/rollback/uninstall primitives. The renderer emits no shell, environment, `UserName`, or privileged launchd fields and requires canonical absolute paths and fixed argv boundaries. The plan adds fixed `codesign`/`launchctl` argv, exact previous-revision preconditions, explicit operation confirmation, final launchd/Broker/signature readback, explicit rollback/uninstall actions, post-bootstrap identity validation, owner/mode/symlink/device/inode checks, atomic writes/removal, and content/absence readback. A mismatched readback boots out the exact service and leaves the plist/backup for explicit recovery rather than overwriting an uncertain target. This remains a packaging boundary candidate only; no signed artifact, notarization, live LaunchAgent install/bootstrap, installed Edge identity handshake, or uninstall acceptance evidence exists. Evidence: `evidence/2026-09-13-install-plan-executor.md`.

Revision `018565d` adds a bounded read-only `launchctl print` parser and a
real system-service smoke, plus a separate spawned Broker/Edge package-process
smoke that binds native UDS authorization to the Edge PID/start-time identity
and verifies the response proof. These strengthen local process/readback
evidence only; they do not install a LaunchAgent, bootstrap a service, or
establish Developer ID provenance, notarization, Keychain ACLs, or live
upgrade/rollback acceptance. Evidence:
`evidence/2026-09-13-packaged-process-and-launchd-readback.md`.

Revision `8ac5fe0` adds the fixed packaged `service-main.js` entrypoint and an
owner-only, root-bound `broker-service.json` loader. Startup restores exact
persisted signed Policy and Edge-key activations, captures the launchd Edge
PID/start-time identity before native listener construction, and wipes loaded
Edge keys on close. This is governed startup assembly evidence only; no live
LaunchAgent bootstrap, production signing, Keychain ACL, or upgrade/rollback
acceptance is claimed. Evidence:
`evidence/2026-09-13-governed-broker-service-entrypoint.md`.

The current revision supersedes the earlier non-installing limitation
for the unprivileged temporary package slice. The executor now receives only
raw host observations and composes final readback internally; its observer
waits through launchd startup, double-reads launchd/native/plist identities,
and reads strict signature details. A physical-Mac temporary package started
the real zero-capability Broker under a LaunchAgent and completed exact
uninstall. This remains partial: the Broker status callback is an explicit
owner-only fixture, and Developer ID/notarization, production persistence,
upgrade/rollback, remote Edge, and root-domain helper evidence remain open.
Evidence: `evidence/2026-09-14-live-install-plan.md`.

Revision `576038e` adds the reviewed `com.mac-operator.edge.plist.in`
template beside the Broker template. The static regression checks both
templates for fixed component labels, exact entrypoint placeholders, and the
absence of shell, environment, user, or privileged launchd fields. The
deployment sequence now requires Edge launchd identity/readback before Broker
startup and keeps the Broker status socket as a separately authenticated
operator/readback channel. Revision `18e9103` also proves a separately spawned
Edge process can complete the signed HTTPS-to-native-Broker exchange when the
Broker binds the exact Edge UID/GID and PID/start-time identity. These are
reviewable packaging and temporary process-boundary evidence only; persistent
LaunchAgent installation, Developer ID/notarization, remote issuer
interoperability, and production key distribution remain open.

The packaged-service smoke adds temporary host evidence for the same boundary:
with `MOPS_REAL_INSTALL=1`, it copies the compiled packages and dependencies
into an isolated owner-only root, bootstraps the real Edge LaunchAgent before
Broker, verifies launchd argument vectors, TLS listener readiness, native and
status socket identity/mode, HMAC Broker status, PID identity, and empty
capabilities, then bootouts and verifies both labels are absent. It refuses to
run when either fixed label is already loaded. Workspace dependency symlinks
are deliberately excluded from this evidence because they are not an
installed-package boundary. Persistent installation, production signing,
remote issuer interoperability, Keychain ACLs, and privileged helper
installation remain open. Evidence:
`evidence/2026-09-14-packaged-edge-broker-launchd.md`.

The subsequent packaging boundary adds component-specific Edge plan and
readback contracts: `buildMacOsEdgeInstallPlan` binds the reviewed Edge label
and expected listener, while `composeMacOsEdgeInstallReadback` and
`validateMacOsEdgeInstallReadback` require an independently observed running,
listening Edge plus exact launchd, PID/start-time, plist, and signature
identity. `executeMacOsEdgeInstallPlan` reuses the bounded atomic plist and
launchd recovery flow and rejects mismatched host confirmation before any
mutation. Edge readback has no Broker-status fallback. These are still
host-only APIs; production installer authorization and signed release
provenance remain open.

The LaunchAgent precondition boundary now follows the same host-authority
rule as the privileged helper package: `executeMacOsInstallPlan` and
`executeMacOsEdgeInstallPlan` require a host-owned reader sampled twice before
any signature command, plist write, or launchd transition. The reader binds
the exact GUI-domain service identity, LaunchAgent type, reviewed program,
arguments, and plist path; non-install operations also bind the prior runtime
source revision. Caller-provided state is only a consistency hint. Focused
tests and the full regression are green; host-observer factories now assemble
the precondition source from the same bounded Launchd and authenticated
component status channels used for final readback. No new real service
mutation is claimed. Evidence:
`evidence/2026-09-16-launchagent-precondition-readback.md`.

The Edge-to-Broker Keychain delivery channel now has a separate durable
replay ledger in BrokerStore. The fixed key identity is checked before replay
admission, which survives a Broker restart and reclaims only expired entries;
live capacity exhaustion fails closed. This closes a protocol replay/DoS gap in
the host-only candidate but does not accept production Keychain rotation,
signing, or installed lifecycle evidence. Evidence:
`evidence/2026-09-16-keychain-delivery-replay-ledger.md`.

Native package compatibility now binds every macOS N-API artifact to a
compile-time `darwin` platform and `arm64`/`x64` architecture declaration;
Broker loaders require an exact match with the running Node host before
exposing native operations. This is a runtime packaging guard, not release
provenance: Developer ID signing, notarization, and immutable distribution
remain open. Evidence:
`evidence/2026-09-16-native-host-compatibility.md`.

The package signature readback boundary now classifies `codesign` provenance
instead of treating Team ID and CDHash as sufficient. Developer ID artifacts
must expose a bounded `Developer ID Application` authority whose Team ID
matches the readback TeamIdentifier; ad-hoc artifacts are accepted only under
the explicit development policy. Broker/Edge and helper observers share the
parser and reject ambiguous provenance before service readiness. This is an
implementation guard, not Developer ID/notarization evidence: the physical
host currently has only an ad-hoc development artifact and no persistent
service was installed. Evidence:
`evidence/2026-09-16-signature-provenance-readback.md`.

The host-only notarization assessment boundary now uses fixed `/usr/sbin/spctl`
arguments, an empty environment, bounded timeout/output, and canonical path
validation. Its parser accepts only `Notarized Developer ID` provenance whose
authority matches the expected Team ID, and returns no raw assessment output.
Production Developer ID Broker/Edge LaunchAgent plans and the root helper
package run this check after code-signature verification and before mutation;
their final readback also requires matching evidence. Explicit ad-hoc plans
omit the gate. Physical probes confirm that Apple System artifacts are not
accepted as Developer ID releases; no notarized artifact or production
capability is enabled. Evidence:
`evidence/2026-09-16-notarization-assessment-boundary.md`.

Revision `9541b6b` adds the read-only release-artifact preflight. An owner-only
manifest binds one canonical artifact path, deterministic bounded tree digest,
byte count, owner UID, and exact Developer ID identifier/Team ID/CDHash. The
preflight rejects symlink/special-file entries, unsafe owners/modes, identity
swaps, digest/size mismatches, and resource overruns before running the fixed
codesign and Gatekeeper commands. Its CLI emits only bounded evidence. This
closes the implementation gate but not certificate custody, a successful
notarized artifact, immutable distribution, or persistent installation.
Evidence: `evidence/2026-09-16-release-artifact-preflight.md`.
