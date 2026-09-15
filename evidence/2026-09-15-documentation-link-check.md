# Documentation Navigation Evidence

- Source revision: `66068f4`
- Date: 2026-09-15
- Scope: MOP-087 README and operator-runbook navigation

The new dependency-free `npm run verify:docs` check parses README local
Markdown links, rejects repository escapes, requires regular-file targets, and
checks that the testing, configuration, deployment, operations, incident,
rollback, kill-switch, and persistence cutover runbooks are present. External
links and anchors are not treated as local filesystem targets.

Verification on the physical host:

- `npm run verify:docs`: passed for 29 README local links and 8 required
  runbooks.
- `npm run lint`: passed across 636 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.

This closes navigation/path-presence checking only. Runbook content remains
draft where it depends on production signing, installed launchd ownership,
remote deployment, or operator approval evidence.
