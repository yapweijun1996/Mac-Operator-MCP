# Privileged Broker dispatch evidence

- Source revision: `24c704e`
- Scope: Broker admission and helper Job dispatch only; no root process or real privileged adapter was enabled.
- Focused command: `npx tsc -b packages/broker/tsconfig.json --pretty false && node --test packages/broker/dist/privileged-broker-dispatch.test.js`
- Result: 2 tests passed, 0 failed, 0 skipped.

The integration fixture enables only `mac_priv_service_control` in an isolated
in-memory policy, issues a single-use `explicit_privileged_policy` approval,
and supplies an injected helper command factory/client. The Broker normalized
the service payload, recorded approval intent, created and leased a Broker Job,
validated helper result identity and postcondition evidence, persisted a
completed Job, and returned a bounded tool result. The test also verifies that
an enabled policy with a disabled helper executor returns `POLICY_DENIED`
without creating a Job.

The implementation keeps the signed Edge envelope digest separate from the
normalized privileged payload digest. The helper protocol remains separately
authenticated and allowlisted; default policy and default executor settings
remain disabled, so this evidence does not claim Developer ID signing,
root-domain installation, real service/package/power adapters, or production
privileged enablement.
