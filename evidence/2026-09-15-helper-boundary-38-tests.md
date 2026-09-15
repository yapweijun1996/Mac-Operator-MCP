# Privileged Helper Boundary Evidence

Date: 2026-09-15

Source revision: `bfe4f41`

Command:

```text
find packages/broker/dist -maxdepth 1 -type f -name 'privileged-helper*.test.js' -print0 | xargs -0 node --test
38 tests, 38 passed, 0 failed, 0 skipped
```

The L5 helper prototype tests cover owner-only peer authentication, HMAC
command/response binding, durable replay rejection across BrokerStore reopen,
fixed service/package/power allowlists, typed payload validation, separately
authenticated helper-owned status, trailing-frame rejection, denied-peer
rejection, approval/Job binding, and active authority revocation. No root
command, real package install, reboot, shutdown, or helper installation was
performed.

This is protocol and policy-boundary evidence only. Developer ID provenance,
root-domain installation/readback, protected production Keychain material,
operator approval UI, and enabling privileged operations remain gated.
