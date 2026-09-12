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

Source revisions `fde7341`, `5804f04`, `8fe6663`, `b4945c3`, and `662801b` add a bounded launchd plist renderer, an unprivileged LaunchAgent template, a signal-aware `BrokerServiceEntrypoint`, a non-executing install preflight plan, double-`lstat` filesystem checks, and temporary-root-tested descriptor-relative plist install/upgrade/rollback/uninstall primitives. The renderer emits no shell, environment, `UserName`, or privileged launchd fields and requires canonical absolute paths and fixed argv boundaries. The plan adds fixed `codesign`/`launchctl` argv, exact previous-revision preconditions, explicit rollback/uninstall actions, post-bootstrap identity validation, owner/mode/symlink/device/inode checks, atomic writes/removal, and content/absence readback. This remains a packaging boundary candidate only; no signed artifact, notarization, live launchd readback, production install, or uninstall acceptance evidence exists.
