# Latest non-overlapping local regression

Date: 2026-09-15

## Command

The built test set was run serially while intentionally excluding the already
running `packages/broker/dist/broker.test.js` and
`packages/broker/dist/persistence.test.js` processes:

```text
find packages -path '*/dist/*.test.js' ! -name 'broker.test.js' ! -name 'persistence.test.js' -print0 | xargs -0 node --test --test-concurrency=1
```

## Result

```text
tests 595
pass 589
fail 0
skipped 6
```

The run includes the audit failure-target, credential-field, and
secret-shaped-string redaction changes. The six skips are explicit host-gated tests (including real
Keychain/sandbox/install checks); no test was force-enabled. This is a local
regression result only and does not claim completion of physical-Mac,
production-signing, installed lifecycle, isolation, or independent review
gates.
