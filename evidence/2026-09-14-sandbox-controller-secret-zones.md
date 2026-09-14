# Sandbox controller-secret zone evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Status: partial MOP-086 evidence; production task enablement remains disabled

## Change

Broker-owned Seatbelt profiles now deny controller state directories under the
current user's home, including `.codex` and `.openai`, in addition to the
existing SSH, cloud, Docker, GnuPG, Kubernetes, browser, Mail, Messages, and
Keychain zones. The deny rules are rendered from fixed Broker source; task
profiles cannot add or remove them.

## Verification

Command:

```text
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js packages/broker/dist/task-runner.test.js
```

Result: 21 passed, 0 failed, 0 skipped.

The real sandbox canary confirmed that inherited controller/`HOME`/SSH-agent/
AWS-profile values were absent and readability checks for `.ssh`, `.codex`,
`.docker`, `.openai`, Chrome, Safari, Mail, Messages, Keychains, and the local
Docker socket all returned denied without opening their contents. The allowed
temporary root remained readable/writable and the selected loopback network
readback continued to pass.

## Limits

This is deny-list and environment-boundary evidence, not proof of real
credential-content isolation, remount resistance, post-snapshot process escape,
crash cleanup, or a production-supported sandbox mechanism. `sandbox-exec` is
deprecated and the task runner remains explicitly disabled by default.
