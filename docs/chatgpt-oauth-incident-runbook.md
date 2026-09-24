# Mac-Operator-MCP ChatGPT OAuth incident and recovery runbook (2026-09-21)

Project: Mac-Operator-MCP
Endpoint: https://mac.yapweijun1996.com/mcp
Status: Historical R0 incident evidence. The current personal service/API is
R1-verified with 17 scopes and 30 read-only tools; the installed ChatGPT app
still needs a fresh owner-confirmed grant. This incident contains multiple
independent failure layers. The precise cause of the intermittent network
timeout remains unproven.

Evidence and failure layers

1. Initial "does not implement OAuth": verified Cloudflare discovery block.
Cloudflare events showed a ChatGPT discovery request from Australia matching the GeoIP Block rule, including /.well-known/openid-configuration/mcp. A host-only Mac exception was saved with owner authorization. Subsequent ChatGPT traffic reached /mcp and received the expected 401 challenge. This explains the observed blocked discovery, but does not establish the cause of later timeouts.

2. "Request timeout" after Create, before the login page: observed remote-path failure with an unresolved exact cause.
ChatGPT browser Network showed HTTP 500 with Request timeout from /backend-api/aip/connectors/mcp/oauth_config and /backend-api/aip/connectors/mcp. Manual endpoint configuration also timed out. Some Cloudflare Skip events lacked corresponding completed origin responses; other metadata requests completed in 1–3 ms at the origin. Skip means firewall allowance, not successful end-to-end delivery.
A public SDK login/tool/revocation probe from the Mac repeatedly passed while ChatGPT failed. It did not reproduce the remote ChatGPT network path or native browser behavior.
The shared cloudflared tunnel was reconnected at 04:36:29 UTC without changing routing, TLS validation, firewall policy or OAuth requirements. A later manual configuration returned a PKCE validation error. Resetting the form and using fresh automatic discovery returned 200 with pkce_required=true and pkce_methods=["S256"].
Recovery followed reconnect plus fresh discovery. Do not record stale tunnel, QUIC, DNS, or any other lower-level transport hypothesis as the proven root cause. A successful restart is recovery evidence, not causal proof.
Connector creation can commit despite a client timeout: a later creation attempt reported the name already existed. Inspect the existing connector and use its sign-in flow instead of creating duplicates.

3. Browser request_failed: form policy and callback policy defects.
The original auth application used Referrer-Policy: no-referrer on login and consent forms while requiring same-origin POSTs and CSRF validation. Native browser form behavior can produce Origin:null under this policy. The SDK explicitly supplied Origin, masking the browser-policy conflict.
Observed login POST at 04:42:16 UTC returned 400 before password hashing. Login/consent responses were changed to Referrer-Policy: same-origin; other endpoints retain no-referrer. Null/foreign origins and invalid CSRF remain rejected. The next owner login at 04:45:26 returned 303 and delivered consent. The exact failing request's Origin header was not captured; the mechanism is supported by code/policy analysis and successful corrected browser behavior, not a captured header trace.
The original consent CSP used form-action 'self', conflicting with cross-origin ChatGPT OAuth callback redirects in Chromium. First consent POST returned 303, a repeat returned 400 because the one-use session had already been consumed, and no token exchange followed.
Consent responses now allow self plus only the callback origin derived from the validated stored transaction. Login remains self-only. Redirect allowlisting, CSRF, PKCE and one-use codes remain enforced. Expired/consumed sessions now show a Start a new connection recovery page. The original CSP console violation was not captured; code analysis and successful corrected callback flow support this defect diagnosis.

4. SDK listed three tools while ChatGPT listed two: verified OAuth scope mismatch.
The initial MCP challenge required only `mac.control.read`, and the first ChatGPT app stored that as its requested/default scope. Its active grant contained only `mac.control.read`; `mac_system_summary` requires `mac.system.read`, so the server correctly omitted it. Protected-resource `scopes_supported` metadata describes available scopes but does not add permission to an existing grant. Reconnecting the same app reused its stored scope configuration.
Personal deployment now configures the MCP endpoint to require both initial read scopes. A new ChatGPT development app was created with `mac.control.read` and `mac.system.read` selected as default scopes, then authorized again. Do not fix this class of issue by mapping a higher-scope tool to a lower scope or by broadening token interpretation.

Final acceptance evidence
At 04:48 UTC the owner reached ChatGPT's /connector_platform_oauth_redirect and OpenAI's token exchange returned 200. The existing connector displayed its connected account and discovered mac_health and mac_capabilities.
At 04:52:05 UTC real ChatGPT invoked mac_health and displayed healthy. Origin diagnostics independently recorded an authenticated tools/call, protocol 2026-07-28, HTTP 200, duration 639 ms. Legacy compatibility remained rejected. Do not infer additional tool permissions from this two-action UI grant.
At 05:34:58 UTC the newly authorized `Mac Operator MCP Read Only` app exposed all three actions and real ChatGPT invoked `mac_system_summary`. The UI displayed bounded macOS, CPU, memory, uptime and load facts. Origin diagnostics recorded an authenticated `tools/call`, protocol 2026-07-28, HTTP 200, duration 263 ms. The active grant contained both read scopes.
Recorded validation: 15 auth tests and 3 diagnostics tests passed during the first acceptance. The scope correction subsequently passed typecheck, style, documentation checks, 9 focused Edge/startup tests, 18 Auth/diagnostics tests, and the public SDK probe. These are incident-time results, not a claim of a fresh test run on every future read.

Reusable troubleshooting procedure
1. Identify the failing stage: Create/discovery, login, consent, callback, token exchange, tool discovery, or tool call.
2. Correlate one actual request across ChatGPT Network, Cloudflare action/Ray ID and UTC timestamp, tunnel observations, and origin receipt/completion/abort plus elapsed time. Missing correlation is uncertainty, not proof of a specific component failure.
3. Check expected unauthenticated 401 challenge and discovery metadata: issuer, resource, registration endpoint and S256. Prefer a clean automatic-discovery form; manual URLs may omit capability metadata.
4. Check whether a connector already exists after creation timeout before retrying creation.
5. Test native browser forms and callback navigation: cookies, SameSite, Origin, Referrer-Policy, CSP and one-use session behavior. SDK calls with explicit headers do not cover these browser policies.
6. Treat first consent 303 followed by replay 400 as a possibly consumed session, not evidence of a wrong password. Restart authorization from ChatGPT.
7. Use bounded secret-safe diagnostics. Do not log authorization/cookie values, query values, request bodies, passwords or tokens.
8. Keep fixes bounded: host-specific firewall exceptions; validated callback origins; preserve TLS, CSRF, PKCE, redirect allowlists and origin checks. A shared-tunnel restart affects other routes and must be treated accordingly.
9. Require full acceptance: browser login -> consent -> ChatGPT callback -> token exchange -> discovered tools -> real health tool call with origin confirmation. HTTP 200 alone can still contain a JSON-RPC error.
10. Record observed facts, strong inferences and unknowns separately. Do not generalize this incident into "every timeout is Cloudflare" or "restart proves tunnel root cause."
11. If the SDK lists more tools than ChatGPT, inspect the active grant's exact scopes and the ChatGPT app's default/action scopes. Existing-app reconnect may reuse stored scope configuration. After correcting scopes, reauthorize and verify a real tool call; a successful `tools/list` alone is insufficient.

Source of truth
Repository: /Users/yapweijun/Documents/GitHub/Mac-Operator-MCP
Incident chronology: docs/personal-deployment.md, especially September 21 connection recovery, Browser form origin correction, Consent callback correction, and Real ChatGPT acceptance completed.
Implementation: packages/auth/src/app.ts; packages/auth/src/pages.ts; packages/auth/src/connection-diagnostics.ts; packages/auth/src/personal-service.ts; packages/edge/src/https-edge.ts; packages/edge/src/service-startup.ts.
Regression coverage: packages/auth/src/auth.test.ts; packages/auth/src/connection-diagnostics.test.ts; packages/edge/src/https-edge.test.ts; packages/edge/src/service-startup.test.ts.
Public SDK probe: scripts/verify-personal-connection.mjs (creates and revokes its own test grant; does not replace real ChatGPT acceptance).
Public policy references recorded in incident docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy and https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action.
OAuth scope behavior reference: https://developers.openai.com/plugins/build/auth.
