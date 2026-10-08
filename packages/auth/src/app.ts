import { createPublicKey, timingSafeEqual, type KeyObject } from "node:crypto";
import express, { type Request, type Response, type NextFunction } from "express";
import OAuth2Server from "@node-oauth/oauth2-server";
import { exportJWK } from "jose";
import { z } from "zod";
import { configSchema, ownerTerminalAuthConfig, OAUTH_SCOPES, scopesForGrantProfile, type AuthConfig } from "./contracts.js";
import { AuthStore, type GrantRevocationListener } from "./store.js";
import { AuthProvider, fingerprint, nonce } from "./provider.js";
import { verifyPassword } from "./password.js";
import { guiSessionPage, approvalLoginPage, approvalResultPage, approvalReviewPage, consentPage, loginPage, expiredRequestPage, expiredApprovalPage, stylesheet } from "./pages.js";
import type { ApprovalBrowserBridge, ApprovalBrowserPreview } from "./approval-browser-bridge.js";

const contentSecurityPolicy = (callbackOrigin?: string): string =>
  `default-src 'none'; style-src 'self'; form-action 'self'${callbackOrigin ? ` ${callbackOrigin}` : ""}; frame-ancestors 'none'; base-uri 'none'`;
class BrowserSessionError extends Error {}

const APPROVAL_COOKIE = "__Host-mac-approval";
const sessionMs = 10 * 60 * 1000;
const loginBody = z.object({ csrf: z.string().length(64), username: z.string().max(64), password: z.string().max(1024) }).strict();
const consentBody = z.object({ csrf: z.string().length(64), decision: z.enum(["allow", "deny"]) }).strict();
const approvalLoginBody = loginBody;
const approvalDecisionBody = z.object({ csrf: z.string().length(64), decision: z.enum(["allow", "deny", "allow-session", "allow-permanent"]) }).strict();
const approvalSessionMs = 30 * 60 * 1000;
const approvalRequestId = z.string().regex(/^[A-Za-z0-9._:@/+-]{1,128}$/u);

export async function createAuthApp(input: { config: AuthConfig; store: AuthStore; signingKey: KeyObject; statusKey: Buffer; approvalBridge?: ApprovalBrowserBridge; onGrantRevoked?: GrantRevocationListener }): Promise<{ app: express.Express; provider: AuthProvider; metadata: Record<string, unknown> }> {
  const config = configSchema.parse(input.config);
  const { store, signingKey } = input;
  const basePath = new URL(config.issuer).pathname.replace(/\/$/u, "");
  const COOKIE = basePath === "/terminal" ? "__Host-mac-terminal-session" : "__Host-mac-session";
  const endpoint = (path: string) => `${basePath}${path}`;
  if (input.statusKey.length !== 32) throw new Error("Status key must be 32 bytes");
  const provider = new AuthProvider(store, config, signingKey);
  if (input.onGrantRevoked) store.setGrantRevocationListener(input.onGrantRevoked);
  const supportedScopes: readonly string[] = scopesForGrantProfile(config.grantProfile, config.dockerReadAccess, config.ownerTerminalScope);
  const account = store.get("account", "owner");
  if (!account || account.principalId !== config.principalId) throw new Error("Owner account is not provisioned");
  const publicJwk = await exportJWK(createPublicKey(signingKey));
  const app = express();
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    if (req.headers.host !== new URL(config.issuer).host) { res.status(403).end(); return; }
    next();
  });
  if (config.ownerTerminalConnection === true) {
    const terminal = await createAuthApp({ config: ownerTerminalAuthConfig(config), store, signingKey,
      statusKey: input.statusKey, ...(input.onGrantRevoked ? { onGrantRevoked: input.onGrantRevoked } : {}) });
    app.get("/.well-known/oauth-authorization-server/terminal", (_req, res) => {
      res.set("Cache-Control", "no-store").json(terminal.metadata);
    });
    app.use("/terminal", terminal.app);
  }
  app.set("trust proxy", false);
  let windowStart = 0;
  let requests = 0;
  let loginAttempts = 0;
  let activePasswords = 0;
  // Escalating lockout after repeated login bursts: 2, 5, then 10 minutes. The level resets
  // after a successful login or an hour without a new lockout.
  const lockoutSeconds = [120, 300, 600];
  let lockedUntil = 0;
  let lockoutLevel = 0;
  let lastLockoutAt = 0;
  const loginBlocked = (res: Response): boolean => {
    const now = Date.now();
    if (now < lockedUntil) { res.set("Retry-After", String(Math.ceil((lockedUntil - now) / 1000))).status(429).end(); return true; }
    if (now - lastLockoutAt >= 3_600_000) lockoutLevel = 0;
    if (++loginAttempts > 10) {
      const seconds = lockoutSeconds[Math.min(lockoutLevel, lockoutSeconds.length - 1)] ?? 600;
      lockoutLevel++; lastLockoutAt = now; lockedUntil = now + seconds * 1000;
      res.set("Retry-After", String(seconds)).status(429).end(); return true;
    }
    if (activePasswords >= 2) { res.set("Retry-After", "60").status(429).end(); return true; }
    return false;
  };
  app.use((req, res, next) => {
    res.set({ "Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": contentSecurityPolicy() });
    // Native form POSTs use Origin: null under no-referrer. Preserve the
    // same-origin signal for CSRF checks without sending referrers off-site.
    if (["/oauth/login", "/oauth/consent", "/approval/login", "/approval/access", "/approval/review", "/approval/decision", "/approval/gui-session", "/approval/gui-session/revoke"].includes(req.path)) {
      res.set("Referrer-Policy", "same-origin");
    }
    if (Date.now() - windowStart >= 60_000) { windowStart = Date.now(); requests = 0; loginAttempts = 0; }
    if (++requests > 300) { res.set("Retry-After", "60").status(429).json({ error: "rate_limit_exceeded" }); return; }
    try { store.prune(); next(); } catch { res.status(503).json({ error: "temporarily_unavailable" }); }
  });
  app.use(express.urlencoded({ extended: false, limit: "8kb", parameterLimit: 20 }));
  app.use(express.json({ limit: "8kb", strict: true }));
  app.get("/oauth/style.css", (_req, res) => { res.type("text/css").send(stylesheet); });
  const metadata = { issuer: config.issuer, authorization_response_iss_parameter_supported: true,
    authorization_endpoint: new URL("authorize", config.issuer).href,
    token_endpoint: new URL("token", config.issuer).href, registration_endpoint: new URL("register", config.issuer).href,
    revocation_endpoint: new URL("revoke", config.issuer).href, jwks_uri: new URL("jwks", config.issuer).href,
    response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"], revocation_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"], scopes_supported: supportedScopes };
  app.get("/.well-known/oauth-authorization-server", (_req, res) => { res.json(metadata); });
  app.get("/jwks", (_req, res) => { res.json({ keys: [{ ...publicJwk, kid: config.keyId, alg: "ES256", use: "sig" }] }); });

  app.post("/register", (req, res) => {
    const data = z.object({ client_name: z.string().min(1).max(100).default("MCP client"),
      redirect_uris: z.array(z.string().max(2048)).min(1).max(8),
      token_endpoint_auth_method: z.literal("none").default("none"),
      grant_types: z.array(z.enum(["authorization_code", "refresh_token"])).max(2).default(["authorization_code", "refresh_token"]),
      response_types: z.array(z.literal("code")).length(1).default(["code"]),
      scope: z.string().max(2048).optional()
    }).parse(req.body);
    if (data.redirect_uris.some(uri => !config.allowedRedirectUris.includes(uri)) ||
        (data.scope && data.scope.split(" ").some(scope => !supportedScopes.includes(scope)))) {
      res.status(400).json({ error: "invalid_client_metadata" }); return;
    }
    const clientId = nonce();
    // Connector registration outlives individual seven-day user grants.
    const record = { id: clientId, name: data.client_name, redirectUris: data.redirect_uris, expiresAt: Number.MAX_SAFE_INTEGER, ...provider.resourceBinding() };
    try { store.put("client", clientId, record); }
    catch (error) {
      // Anonymous registrations never expire; when full, drop the oldest unused ones instead of locking out new connectors.
      if (!(error instanceof Error) || error.message !== "Auth capacity exceeded" || store.evictUnusedClients(100) === 0) throw error;
      store.put("client", clientId, record);
    }
    res.status(201).json({ client_id: clientId, client_id_issued_at: Math.floor(Date.now() / 1000), client_name: data.client_name,
      redirect_uris: data.redirect_uris, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] });
  });

  const cookieId = (req: Request, cookieName: string): string => {
    const cookies = (req.headers.cookie ?? "").split(";").map(value => value.trim()).filter(value => value.startsWith(`${cookieName}=`));
    if (cookies.length !== 1) throw new BrowserSessionError("Invalid browser session");
    const value = cookies[0]!.slice(cookieName.length + 1);
    if (!/^[a-f0-9]{64}$/u.test(value)) throw new BrowserSessionError("Invalid browser session");
    return fingerprint(value);
  };
  const browser = (req: Request) => {
    const key = cookieId(req, COOKIE);
    const session = store.get("session", key);
    if (!session || session.expiresAt <= Date.now()) throw new BrowserSessionError("Expired browser session");
    const transaction = store.get("transaction", session.transactionId);
    if (!transaction || !provider.matchesResource(transaction) || transaction.expiresAt <= Date.now()) throw new BrowserSessionError("Expired authorization request");
    const client = store.get("client", transaction.clientId);
    if (!client || !provider.matchesResource(client)) throw new BrowserSessionError("Invalid authorization client");
    return { key, session, transaction };
  };
  const csrfCheck = (req: Request, expected: string, actual: string): void => {
    const origin = req.headers.origin;
    if ((origin !== undefined && origin !== new URL(config.issuer).origin) || actual.length !== 64 ||
        !timingSafeEqual(Buffer.from(expected), Buffer.from(actual))) throw new Error("Invalid browser request");
  };
  const setSession = (res: Response, value: string): void => {
    res.cookie(COOKIE, value, { secure: true, httpOnly: true, sameSite: "lax", path: "/", maxAge: sessionMs });
  };
  const setApprovalSession = (res: Response, value: string): void => {
    res.cookie(APPROVAL_COOKIE, value, { secure: true, httpOnly: true, sameSite: "lax", path: "/", maxAge: approvalSessionMs });
  };
  const approvalBrowser = (req: Request) => {
    const key = cookieId(req, APPROVAL_COOKIE);
    const session = store.get("approval_session", key);
    if (!session || session.expiresAt <= Date.now()) throw new BrowserSessionError("Expired approval session");
    return { key, session };
  };
  const rotateApprovalSession = (key: string, session: ReturnType<typeof approvalBrowser>["session"], res: Response) => {
    const id = nonce();
    store.transaction(() => {
      if (!store.delete("approval_session", key)) throw new BrowserSessionError("Approval session already consumed");
      store.put("approval_session", fingerprint(id), { ...session, csrf: nonce() });
    });
    setApprovalSession(res, id);
  };

  app.get("/authorize", async (req, res) => {
    const query = z.object({ client_id: z.string().max(128), redirect_uri: z.string().max(2048), response_type: z.literal("code"),
      state: z.string().min(1).max(512), code_challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/u), code_challenge_method: z.literal("S256"),
      scope: z.string().max(2048).default(supportedScopes.join(" ")), resource: z.literal(config.resource)
    }).parse(req.query);
    const client = await provider.getClient(query.client_id);
    const scopes = client && await provider.validateScope({}, client, query.scope.split(" "));
    if (!client || !client.redirectUris?.includes(query.redirect_uri) || !scopes) { res.status(400).json({ error: "invalid_request" }); return; }
    const transactionId = nonce();
    const sessionId = nonce();
    store.transaction(() => {
      store.put("transaction", transactionId, { clientId: client.id, redirectUri: query.redirect_uri, state: query.state, challenge: query.code_challenge,
        scopes: scopes as Array<(typeof OAUTH_SCOPES)[number]>, expiresAt: Date.now() + sessionMs, ...provider.resourceBinding() });
      store.put("session", fingerprint(sessionId), { transactionId, csrf: nonce(), authenticated: false, expiresAt: Date.now() + sessionMs });
    });
    setSession(res, sessionId);
    res.redirect(303, endpoint("/oauth/login"));
  });
  app.get("/oauth/login", (req, res) => {
    const { session } = browser(req);
    if (session.authenticated) { res.redirect(303, endpoint("/oauth/consent")); return; }
    res.type("html").send(loginPage(session.csrf, false, basePath));
  });
  app.post("/oauth/login", async (req, res) => {
    const body = loginBody.parse(req.body);
    const { key, session } = browser(req);
    csrfCheck(req, session.csrf, body.csrf);
    if (loginBlocked(res)) return;
    activePasswords++;
    let valid: boolean;
    try {
      // Always hash, including unknown usernames, to avoid an account oracle.
      const current = store.get("account", "owner")!;
      valid = await verifyPassword(body.password, current.salt, current.passwordHash) && body.username === current.username;
    } finally { activePasswords--; }
    if (!valid) { res.status(401).type("html").send(loginPage(session.csrf, true, basePath)); return; }
    lockoutLevel = 0;
    const newId = nonce();
    store.transaction(() => {
      // A concurrent login/reset may already have invalidated this session.
      if (!store.delete("session", key)) throw new BrowserSessionError("Invalid browser session");
      store.put("session", fingerprint(newId), { ...session, csrf: nonce(), authenticated: true });
    });
    setSession(res, newId);
    res.redirect(303, endpoint("/oauth/consent"));
  });
  app.get("/oauth/consent", (req, res) => {
    const { session, transaction } = browser(req);
    if (!session.authenticated) { res.redirect(303, endpoint("/oauth/login")); return; }
    const client = store.get("client", transaction.clientId);
    if (!client) throw new Error("Client unavailable");
    // Chromium applies form-action to the final redirect after a form POST.
    // Only this validated transaction's callback origin is allowed here.
    res.set("Content-Security-Policy", contentSecurityPolicy(new URL(transaction.redirectUri).origin));
    res.type("html").send(consentPage(session.csrf, client.name, transaction.redirectUri,
      transaction.scopes.includes("mac.system.read"), config.grantProfile !== "r1",
      transaction.scopes.includes("mac.ui.control"), transaction.scopes.includes("mac.terminal.exec"), basePath, config.guiAccess === "desktop"));
  });
  app.post("/oauth/consent", async (req, res) => {
    const body = consentBody.parse(req.body);
    const { key, session, transaction } = browser(req);
    csrfCheck(req, session.csrf, body.csrf);
    if (!session.authenticated) { res.status(403).end(); return; }
    res.set("Content-Security-Policy", contentSecurityPolicy(new URL(transaction.redirectUri).origin));
    store.transaction(() => { store.delete("session", key); store.delete("transaction", session.transactionId); });
    res.clearCookie(COOKIE, { secure: true, httpOnly: true, sameSite: "lax", path: "/" });
    if (body.decision === "deny") {
      const redirect = new URL(transaction.redirectUri);
      redirect.searchParams.set("error", "access_denied"); redirect.searchParams.set("state", transaction.state);
      redirect.searchParams.set("iss", config.issuer);
      res.redirect(303, redirect.href); return;
    }
    const oauthResponse = new OAuth2Server.Response();
    await provider.oauth.authorize(new OAuth2Server.Request({ method: "GET", headers: {}, query: {
      client_id: transaction.clientId, redirect_uri: transaction.redirectUri, response_type: "code", state: transaction.state,
      scope: transaction.scopes.join(" "), code_challenge: transaction.challenge, code_challenge_method: "S256"
    } }), oauthResponse, { authenticateHandler: { handle: async () => ({ id: config.principalId }) } });
    const redirect = new URL(String(oauthResponse.headers?.location));
    redirect.searchParams.set("iss", config.issuer);
    res.redirect(303, redirect.href);
  });

  app.get("/approval", async (req, res) => {
    if (!input.approvalBridge) { res.status(404).end(); return; }
    const requestId = approvalRequestId.parse(req.query.request_id);
    const preview = await input.approvalBridge.preview(requestId);
    if (!preview || preview.expiresAtMs <= Date.now()) { res.status(410).type("html").send(expiredApprovalPage()); return; }
    let previous: ReturnType<typeof approvalBrowser> | undefined;
    try { previous = approvalBrowser(req); }
    catch (error) { if (!(error instanceof BrowserSessionError)) throw error; }
    const sessionId = nonce();
    // Reuse owner authentication, never an operation approval or its CSRF token.
    const authenticated = previous?.session.authenticated === true;
    store.transaction(() => {
      if (previous) store.delete("approval_session", previous.key);
      store.put("approval_session", fingerprint(sessionId), { requestId, csrf: nonce(), authenticated,
        expiresAt: authenticated ? previous!.session.expiresAt : Date.now() + sessionMs,
        ...(authenticated && previous?.session.guiGrantId ? { guiGrantId: previous.session.guiGrantId } : {}) });
    });
    setApprovalSession(res, sessionId);
    res.redirect(303, authenticated ? "/approval/review" : "/approval/login");
  });
  // Owner access management is independent of a short-lived operation preview.
  app.get("/approval/access", async (req, res) => {
    if (!input.approvalBridge?.listSessions) { res.status(404).end(); return; }
    let previous: ReturnType<typeof approvalBrowser> | undefined;
    try { previous = approvalBrowser(req); }
    catch (error) { if (!(error instanceof BrowserSessionError)) throw error; }
    const sessionId = nonce();
    const authenticated = previous?.session.authenticated === true;
    store.transaction(() => {
      if (previous) store.delete("approval_session", previous.key);
      store.put("approval_session", fingerprint(sessionId), { requestId: "manage-browser-access", csrf: nonce(), authenticated,
        expiresAt: authenticated ? previous!.session.expiresAt : Date.now() + sessionMs });
    });
    setApprovalSession(res, sessionId);
    res.redirect(303, authenticated ? "/approval/gui-session" : "/approval/login");
  });
  app.get("/approval/login", async (req, res) => {
    if (!input.approvalBridge) { res.status(404).end(); return; }
    const { session } = approvalBrowser(req);
    if (session.requestId === "manage-browser-access") {
      if (session.authenticated) { res.redirect(303, "/approval/gui-session"); return; }
      res.type("html").send(approvalLoginPage(session.csrf, false, undefined, true)); return;
    }
    const preview = await input.approvalBridge.preview(session.requestId);
    if (!preview || preview.expiresAtMs <= Date.now()) { res.status(410).type("html").send(expiredApprovalPage()); return; }
    if (session.authenticated) { res.redirect(303, "/approval/review"); return; }
    res.type("html").send(approvalLoginPage(session.csrf, false, preview.expiresAtMs));
  });
  app.post("/approval/login", async (req, res) => {
    if (!input.approvalBridge) { res.status(404).end(); return; }
    const body = approvalLoginBody.parse(req.body);
    const { key, session } = approvalBrowser(req);
    csrfCheck(req, session.csrf, body.csrf);
    if (loginBlocked(res)) return;
    activePasswords++;
    let valid: boolean;
    try {
      const current = store.get("account", "owner")!;
      valid = await verifyPassword(body.password, current.salt, current.passwordHash) && body.username === current.username;
    } finally { activePasswords--; }
    if (!valid) { res.status(401).type("html").send(approvalLoginPage(session.csrf, true, undefined, session.requestId === "manage-browser-access")); return; }
    lockoutLevel = 0;
    const newId = nonce();
    store.transaction(() => {
      if (!store.delete("approval_session", key)) throw new BrowserSessionError("Invalid approval session");
      store.put("approval_session", fingerprint(newId), { ...session, csrf: nonce(), authenticated: true, expiresAt: Date.now() + approvalSessionMs });
    });
    setApprovalSession(res, newId);
    res.redirect(303, session.requestId === "manage-browser-access" ? "/approval/gui-session" : "/approval/review");
  });
  app.get("/approval/review", async (req, res) => {
    if (!input.approvalBridge) { res.status(404).end(); return; }
    const { session } = approvalBrowser(req);
    if (!session.authenticated) { res.redirect(303, "/approval/login"); return; }
    const preview = await input.approvalBridge.preview(session.requestId);
    if (!preview || preview.expiresAtMs <= Date.now()) { res.status(410).type("html").send(expiredApprovalPage()); return; }
    res.type("html").send(approvalReviewPage(session.csrf, preview));
  });
  app.post("/approval/decision", async (req, res) => {
    if (!input.approvalBridge) { res.status(404).end(); return; }
    const body = approvalDecisionBody.parse(req.body);
    const { key, session } = approvalBrowser(req);
    csrfCheck(req, session.csrf, body.csrf);
    if (!session.authenticated) { res.status(403).end(); return; }
    if (body.decision === "deny") {
      rotateApprovalSession(key, session, res);
      res.type("html").send(approvalResultPage(false)); return;
    }
    try {
      if (body.decision === "allow-session" || body.decision === "allow-permanent") {
        const preview = await input.approvalBridge.preview(session.requestId);
        const start = body.decision === "allow-permanent" ? input.approvalBridge.startPersistentSession : input.approvalBridge.startSession;
        if (!preview?.sessionEligible || !start) { res.status(403).end(); return; }
        if (session.guiGrantId) await input.approvalBridge.revokeSession?.(session.guiGrantId);
        const grant = await start(session.requestId);
        rotateApprovalSession(key, { ...session, guiGrantId: grant.id, expiresAt: grant.persistent ? session.expiresAt : Math.max(session.expiresAt, grant.expiresAtMs) }, res);
        res.redirect(303, "/approval/gui-session"); return;
      }
      const result = await input.approvalBridge.issue(session.requestId);
      rotateApprovalSession(key, session, res);
      res.type("html").send(approvalResultPage(true, result.approvalId));
    } catch {
      const preview = await input.approvalBridge.preview(session.requestId);
      if (!preview || preview.expiresAtMs <= Date.now()) { res.status(410).type("html").send(expiredApprovalPage()); return; }
      res.status(409).type("html").send(approvalReviewPage(session.csrf, preview, true));
    }
  });
  app.get("/approval/gui-session", async (req, res) => {
    let session: ReturnType<typeof approvalBrowser>["session"];
    try { session = approvalBrowser(req).session; }
    catch (error) {
      if (!(error instanceof BrowserSessionError)) throw error;
      res.redirect(303, "/approval/access"); return;
    }
    if (!session.authenticated) { res.status(403).end(); return; }
    const grant = session.guiGrantId ? await input.approvalBridge?.sessionStatus?.(session.guiGrantId) : undefined;
    res.type("html").send(guiSessionPage(session.csrf, grant, await input.approvalBridge?.listSessions?.()));
  });
  app.post("/approval/gui-session/revoke", async (req, res) => {
    const body = z.object({ csrf: z.string().length(64), grant_id: z.string().regex(/^gui-session:[a-f0-9-]{36}$/u).optional() }).strict().parse(req.body);
    const { key, session } = approvalBrowser(req);
    csrfCheck(req, session.csrf, body.csrf);
    if (!session.authenticated || !input.approvalBridge?.revokeSession) { res.status(403).end(); return; }
    const grantId = body.grant_id ?? session.guiGrantId;
    if (grantId) {
      if (grantId !== session.guiGrantId && !(await input.approvalBridge.listSessions?.())?.some(grant => grant.id === grantId)) {
        res.status(403).end(); return;
      }
      await input.approvalBridge.revokeSession(grantId);
    }
    const { guiGrantId: _ended, ...remaining } = session;
    rotateApprovalSession(key, remaining, res);
    res.redirect(303, "/approval/gui-session");
  });
  app.post("/token", async (req, res) => {
    if (!req.is("application/x-www-form-urlencoded")) { res.status(400).json({ error: "invalid_request" }); return; }
    const data = z.object({ grant_type: z.enum(["authorization_code", "refresh_token"]), client_id: z.string().max(128),
      code: z.string().max(256).optional(), redirect_uri: z.string().max(2048).optional(), code_verifier: z.string().max(128).optional(),
      refresh_token: z.string().max(256).optional(), scope: z.string().max(2048).optional(), resource: z.literal(config.resource).optional()
    }).strict().parse(req.body);
    if (req.headers.authorization || (data.grant_type === "authorization_code" && !data.code_verifier)) {
      res.status(400).json({ error: "invalid_request" }); return;
    }
    const oauthResponse = new OAuth2Server.Response();
    const encoded = new URLSearchParams(Object.entries(data).filter((entry): entry is [string, string] => typeof entry[1] === "string")).toString();
    await provider.oauth.token(new OAuth2Server.Request({ method: "POST", headers: {
      "content-type": "application/x-www-form-urlencoded", "content-length": String(Buffer.byteLength(encoded))
    }, query: {}, body: data }), oauthResponse);
    res.status(oauthResponse.status ?? 200).json(oauthResponse.body);
  });
  app.post("/revoke", async (req, res) => {
    const body = z.object({ client_id: z.string().max(128), token: z.string().max(8192), token_type_hint: z.string().optional() }).strict().parse(req.body);
    const refresh = store.get("refresh", fingerprint(body.token));
    if (refresh) {
      const grant = store.get("grant", refresh.grantId);
      if (grant && provider.matchesResource(grant)) store.revoke(refresh.grantId, body.client_id);
    }
    else {
      const access = await provider.getAccessToken(body.token);
      if (access && access.client.id === body.client_id) store.revoke(String(access.user.grantId), body.client_id);
    }
    res.status(200).end();
  });

  // This channel returns no account or token data. A separate host-managed
  // credential binds the Edge to the issuer; ordinary MCP users cannot query it.
  app.post("/oauth/status", (req, res) => {
    const header = req.headers.authorization ?? "";
    const expected = `Bearer ${input.statusKey.toString("hex")}`;
    if (header.length !== expected.length || !timingSafeEqual(Buffer.from(header), Buffer.from(expected))) { res.status(401).end(); return; }
    const body = z.object({ sessionId: z.string().regex(/^[a-f0-9]{64}$/u), subject: z.string().max(128) }).strict().parse(req.body);
    const grant = store.get("grant", body.sessionId);
    res.json({ active: Boolean(grant && provider.matchesResource(grant) && !grant.revoked && grant.expiresAt > Date.now() && grant.principalId === body.subject),
      scopes: grant && provider.matchesResource(grant) && !grant.revoked && grant.expiresAt > Date.now() && grant.principalId === body.subject ? grant.scopes : [] });
  });
  app.use((_req, res) => { res.status(404).end(); });
  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof BrowserSessionError) {
      res.status(400).type("html").send(_req.path.startsWith("/approval") ? expiredApprovalPage(true) : expiredRequestPage(basePath));
    } else if (error instanceof OAuth2Server.OAuthError) {
      res.status(error.code >= 400 && error.code < 500 ? error.code : 503).json({ error: error.code < 500 ? error.name : "temporarily_unavailable" });
    } else if (error instanceof z.ZodError) res.status(400).json({ error: "invalid_request" });
    else res.status(400).json({ error: "request_failed" });
  });
  return { app, provider, metadata };
}
