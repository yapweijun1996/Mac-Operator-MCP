# Dependency Audit Evidence

Date: 2026-09-15

Source revision: `ab7a309`

Command:

```text
npm audit --omit=dev --audit-level=high
found 0 vulnerabilities
```

The production dependency graph reported no high-severity-or-greater npm
advisories. This is a point-in-time registry audit and does not replace code
review, native artifact provenance, macOS signing, or runtime isolation tests.
