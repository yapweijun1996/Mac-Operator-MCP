# Local CI-Equivalent Verification Evidence

Date: 2026-09-15

Source revision: `48d5b12`

Host: physical macOS host used by the repository test harness

Commands:

```text
npm run verify:canonical:native
{"profile":"jcs-utf8-v1","vectors":5,"passed":5}

npm audit --audit-level=high
found 0 vulnerabilities
```

These commands reproduce the canonical-JSON native vector check and the
repository dependency audit from `.github/workflows/verify.yml`. They are
local evidence only; no remote GitHub Actions run was observed or claimed.
The audit result is point-in-time dependency evidence and does not close
native signing, runtime isolation, packaging, or release-review gates.
