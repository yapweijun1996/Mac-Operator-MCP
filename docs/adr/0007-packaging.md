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
