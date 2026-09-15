# Task-profile argument-pattern safety evidence

Date: 2026-09-15
Source revision: `c42c7a8` (`test: reject unbounded task pattern ranges`)

## Boundary

Task profiles are host-owned policy inputs, but a malformed or replaced
profile must not be able to monopolize the Broker. JavaScript `RegExp` has no
execution timeout, so arbitrary nested groups, alternation, and backreferences
could create a regular-expression denial-of-service during task admission.

`TaskProfileRegistry` now rejects patterns longer than 256 characters and
accepts only an anchored, structurally restricted fragment: literals, escaped
characters, character classes, and simple quantifiers whose explicit bounds
cannot exceed the per-argument 1 KiB limit. Unbounded range quantifiers,
grouping, alternation, and numeric backreferences fail closed before the
pattern is compiled. The profile's existing argument-count and total-byte
budgets remain enforced separately.

## Verification

Commands run from the repository root:

```text
npm run build
node --test --test-concurrency=1 packages/broker/dist/task-profile.test.js
npm run lint
git diff --check
```

Results:

- Task-profile tests: 4 passed, 0 failed, 0 skipped.
- The regression rejects nested-group, alternation, and oversized patterns;
  ordinary anchored character-class patterns continue to resolve normally.
- Style and whitespace checks pass.

## Limits

This closes the profile-regex configuration DoS boundary only. It does not
prove descriptor/fexec atomic executable selection, in-syscall remount
resistance, production sandbox selection, or production task enablement.
