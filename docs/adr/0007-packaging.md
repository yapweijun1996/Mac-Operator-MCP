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

Source revision `fde7341` adds a bounded launchd plist renderer, an unprivileged LaunchAgent template, and a signal-aware `BrokerServiceEntrypoint` whose readback binds component, source, contract, policy, runtime, and enabled-capability state. The renderer emits no shell, environment, `UserName`, or privileged launchd fields and requires canonical absolute paths and fixed argv boundaries. This is a packaging boundary candidate only; no install, signing, notarization, live launchd readback, upgrade, rollback, or uninstall acceptance evidence exists.
