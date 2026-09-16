# Task sandbox macOS privacy-zone boundary

- Date: 2026-09-16
- Source revision: `0b2245e`
- Scope: Broker-rendered Seatbelt profile for the disabled task runner

## Change

The Broker-owned sandbox renderer now denies macOS privacy and account
database zones in addition to the existing credential and persistence zones.
The fixed profile covers user and system TCC application-support paths and
the `/var`/`/private/var` forms of TCC, `dslocal`, ConfigurationProfiles,
system keychains, `authd`, and `lockdown`. The renderer uses fixed SBPL regex
patterns for the system families so bounded multi-root profiles remain within
the serialized argument budget. User TCC variants are included in the
Broker-owned project secret-directory deny regex.

The serialized SBPL argument remains bounded at 8 KiB; the previous 4 KiB
limit could not represent the fixed deny set together with a valid multi-root
profile. No task caller can supply SBPL text or alter these deny rules.

## Verification

Commands run on the physical Darwin host:

```text
npm run build
node --test packages/broker/dist/sandbox-profile.test.js
MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 node --test --test-timeout=120000 packages/broker/dist/sandbox-profile.test.js
npm test
```

The renderer/runner suite passes 13/13 with 5 explicit skips; the same result
holds with the real-sandbox opt-in because the host descriptor-exec gate is
unavailable. The complete regression passes 876/876 with 14 explicit skips
(890 total). The static cases verify the fixed database regexes and the
multi-root profile path. No production task capability was enabled and no
privacy-database contents were read.

## Limit

This proves profile construction and bounded deny declarations only. The
physical host still lacks the required descriptor-backed executable launcher,
so no new real sandbox execution evidence is claimed. Credential-content,
remount, crash/restart, process-tree, packaging, and `mac_task_run`
enablement gates remain open.
