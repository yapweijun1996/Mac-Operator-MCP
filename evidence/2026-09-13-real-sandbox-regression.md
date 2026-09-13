# Real macOS Sandbox Regression Evidence

Date: 2026-09-13
Source revision: `a8d9007`
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0

## Command and result

```text
MOPS_REAL_SANDBOX=1 npm test
398 tests, 398 passed, 0 failed, 0 skipped
```

The focused sandbox suite also passed 9/9. This is current host evidence for
the existing opt-in `SandboxExecTaskRunner` boundary; it does not enable
`mac_task_run` or change production policy.

## Covered behavior

- Broker-rendered deny-default profile and canonical temporary-root boundary.
- Empty child environment: controller secret, `HOME`, SSH-agent, and cloud
  profile canaries are not inherited.
- Protected file, root-contained `.env`, outside symlink, SSH, Docker config,
  Chrome, Safari, Mail, Messages, Keychain, and Docker socket access denial.
- Explicit localhost TCP allowlist acceptance, second-port denial, and
  external DNS/network denial.
- Child process/fork denial under the single-process profile.
- Hostile Perl `fork`/`setsid`/marker-write denial with no marker left behind.
- Active cancellation mapped to process-group termination and failed
  verification rather than a false success.

## Limits and release impact

The run proves only the tested host/profile combinations. It does not prove
credential isolation against real secrets, Docker daemon behavior, persistence
or remount identity, owned-group process-tree semantics, descendants created
after the last snapshot, UDP behavior, external allowlisted networking, or
production packaging. `MOP-043`, `MOP-045`, `VT-SBX-01`, and `VT-SBX-02` remain
blocked/open until those boundaries have independent evidence and review.

## Source hashes

- `49f679f99b4cac6062439de72ed4ca12e57ab9eaa259a624e2e195e6e30706f5` `packages/broker/src/sandbox-profile.ts`
- `e105b052cf979ee8beec1e1ff281f2a8306667171262eb2d24af3a91bbb3e49a` `packages/broker/src/sandbox-profile.test.ts`
- `b264c40cb03fe3f24e10242678cbe53a23ef4729329a1da2442859b87522d600` `packages/broker/src/task-runner.ts`
