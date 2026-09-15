# Active mutation approval revalidation evidence

- Source revision: `b4cac00`
- Boundary: Broker mutation admission, dispatch control, and completion
- Change: once a mutation consumes an approval, Broker revalidates the
  request-owner binding, approval consumption, revocation state, and expiry
  during pre-dispatch, active control callbacks, and final readback. A revoked
  or expired approval cancels the request and leaves a started Job in
  `unknown`; no success result is published.
- Focused verification: `Broker cancels an active filesystem mutation after
  approval revocation` — 1/1 passed.
- Regression verification: the non-overlapping package suite reports 539
  tests, 533 passed, 6 skipped, 0 failed. The two pre-existing long-lived
  `broker.test.js` and `persistence.test.js` processes were excluded and left
  untouched.
- Scope: this closes the local active-approval revalidation path only. Human
  approval UI/channel, protected Keychain distribution, unattended ownership,
  and production service evidence remain open.
