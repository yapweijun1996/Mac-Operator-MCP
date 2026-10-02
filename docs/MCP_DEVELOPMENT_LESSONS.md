# MCP Development Lessons (landmines checklist)

Source: code review of Mac-Operator-MCP on 2026-10-02 (PR #4 and follow-up review).
Status legend: **Fixed** = changed in code; **Accepted** = known trade-off; **Open** = not changed.
Everything here came from reading code; items marked "not run" were not exercised by tests in the review sandbox (Node 22).

## How to use this list

Before starting a new MCP server, walk through each entry and write down for your project: does it apply, and what is the decision.

## 1. Authentication and OAuth

### 1.1 Constant-time compare can throw instead of returning false
- Risk: `crypto.timingSafeEqual` throws if the two buffers differ in length. A corrupted stored hash or MAC then crashes the login or integrity check path instead of failing cleanly.
- Check: every call site compares byte lengths (or validates a fixed hex format) first.
- Seen in: `verifyPassword`, audit anchor MAC check. Status: **Fixed** (verifyPassword change not run).

### 1.2 Anonymous dynamic client registration can exhaust capacity
- Risk: an unauthenticated `/register` that stores records which never expire, behind a fixed record cap, lets anyone fill the cap and block real connectors from registering. The same shape applies to any unauthenticated endpoint that writes durable records (authorize transactions, sessions).
- Check: every anonymous write has an expiry, or an eviction rule that never deletes records referenced by a grant.
- Status: **Fixed** for clients (evict oldest clients with no grant); sessions expire on their own.
- Note: deduplicating by name does not help; the attacker just varies the name.

### 1.3 Good baseline to copy
PKCE S256 only, exact redirect URI allowlist, refresh-token rotation with replay detection that revokes the grant, ES256 with algorithm allowlist, issuer and audience checks, token size cap, strict zod schemas on every record.

## 2. Rate limiting and lockout behind a tunnel

### 2.1 A tunnel hides the client address
- Risk: behind Cloudflare Tunnel (or any reverse proxy) every request reaches the origin from `127.0.0.1`. Per-IP limits become one global limit, and trusting `X-Forwarded-For` is spoofable.
- Decision recorded: keep `trust proxy` off and a global login limiter; a test asserts forwarded addresses cannot bypass it. Status: **Accepted**.
- Consequence: an attacker can lock the owner out. Mitigation chosen: escalating lockout (2, 5, 10 minutes) so recovery is short and brute force stays expensive. If you want real per-source limits, enforce them at the edge (Cloudflare rules) or trust the proxy header only from a loopback peer.

### 2.2 Order of middleware decides what is protected
- Risk: a rate limiter placed after bearer authentication only limits authenticated callers. Anonymous floods are unlimited at that layer.
- Reviewed and downgraded: with bind host `127.0.0.1`, a token size cap, an algorithm allowlist and local-only signature verification, a bogus token costs one local verify. Status: **Accepted** (no code change).
- Check: the server binds loopback only; token verification does no network call before the signature is valid.

## 3. Storage and availability

### 3.1 Fail-closed storage can become fail-dead
- Risk: strict schemas plus "seal the whole store on any parse error" is safe, but one unreadable record, or a new field added in a later version, makes the whole auth service unavailable until fixed by hand.
- Check: records carry a schema version; there is a migration step; logs name the failing record kind and id.
- Status: **Open**.

### 3.2 Do not do write work on every request
- Risk: `store.prune()` runs a DELETE on every HTTP request, including anonymous ones. Fine at small scale, wasteful under flood.
- Better: run it on a timer or on write. Status: **Open**.

## 4. Operating a real machine through MCP

### 4.1 UI automation needs the target to be frontmost
- `mac_ui_observe` fails with `PRECONDITION_FAILED` ("running but is not frontmost") until the app is focused. Focus first, then observe. Observation without a screenshot (`capture_mode: none`) avoids capturing screen content.

### 4.2 Capability listing is not authority
- `enabled`, `implemented` and `planned` are separate. Terminal execution, test/build runs and coding agents showed `scope_not_granted` until the owner re-consented. Always call the capabilities tool before assuming a tool works.

### 4.3 OAuth login can fail silently on the client side
- Seen: leftover tabs for the terminal authorize page and a loopback callback (`127.0.0.1:<port>/callback`) showing "Network error". A callback that cannot reach the local client means the grant never completes. Check the local listener before blaming the server.

### 4.4 Keep secrets out of what you echo
- Authorization URLs in browser tabs contain `client_id`, `state` and `code_challenge`. Do not paste them into chats or tickets.

## 5. Build, test and CI environment

### 5.1 Runtime version drives which tests can run
- The project needs Node 24.7+ for native Argon2id. On Node 22 the auth test file fails at import (`node:crypto` has no `argon2` export), so none of its tests run.
- Check: pin the Node version in CI and in `engines`; put tests that do not need the native feature in separate files so they still run on older runtimes (the eviction test did this).

### 5.2 A "proof" is only what you ran
- Distinguish in PRs: ran and passed / typechecked only / not run and why.

## 6. Git and cloud-session pitfalls

- A 403 on `git push` is a permission problem, not a network problem; retrying does not help. Reconnect GitHub and make sure the app covers the repository.
- Session credentials are chosen at session start. After fixing access, the same session may still fail; a new session with the repo selected is the reliable fix.
- Temporary containers are reclaimed. Keep a patch (`git format-patch`) of anything unpushed.
