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
