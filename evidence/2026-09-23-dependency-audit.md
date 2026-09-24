# NPM Dependency Advisory Audit

Date: 2026-09-23

## Scope and result

The current repository `package.json` and `package-lock.json` were checked
against the configured npm advisory registry using:

- `npm audit --json`
- `npm audit --omit=dev --json`

Both reports returned zero known vulnerabilities. The full report counted 120
dependency entries: 98 production, 22 development, and one peer dependency.
The production-only report counted 98 production dependencies and returned
zero vulnerabilities.

## Limits

This is a time-of-check registry advisory result for the current lockfile. It
does not establish source-code safety, native-code safety, package provenance,
compromised-but-unreported packages, or the absence of advisories published
after the audit.

No packages were installed or updated, and no lockfile changes were made by
the audit commands.
