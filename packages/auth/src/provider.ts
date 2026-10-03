import { createHash, createPublicKey, randomBytes, type KeyObject } from "node:crypto";
import OAuth2Server from "@node-oauth/oauth2-server";
import { jwtVerify, SignJWT } from "jose";
import { OAUTH_SCOPES, scopesForGrantProfile, type AuthConfig } from "./contracts.js";
import { AuthStore } from "./store.js";

export const fingerprint = (value: string): string => createHash("sha256").update(value).digest("hex");
export const nonce = (): string => randomBytes(32).toString("hex");
const ACCESS_SECONDS = 300;
export const GRANT_MS = 7 * 24 * 60 * 60 * 1000;

/** Protocol validation belongs to oauth2-server; durable authority belongs here. */
export class AuthProvider implements OAuth2Server.AuthorizationCodeModel, OAuth2Server.RefreshTokenModel {
  readonly oauth: OAuth2Server;

  constructor(readonly store: AuthStore, readonly config: AuthConfig, private readonly key: KeyObject) {
    this.oauth = new OAuth2Server({
      model: this,
      accessTokenLifetime: ACCESS_SECONDS,
      refreshTokenLifetime: GRANT_MS / 1000,
      authorizationCodeLifetime: 60,
      allowEmptyState: false,
      requireClientAuthentication: { authorization_code: false, refresh_token: false }
    });
  }

  /** Legacy records always belong to the original resource, regardless of this provider. */
  matchesResource(record: { resource?: string | undefined }): boolean {
    return (record.resource ?? new URL("/mcp", this.config.issuer).href) === this.config.resource;
  }

  resourceBinding(): { resource?: string } {
    return this.config.resource === new URL("/mcp", this.config.issuer).href ? {} : { resource: this.config.resource };
  }

  async getClient(clientId: string, clientSecret?: string | null): Promise<OAuth2Server.Client | false> {
    if (clientSecret) return false;
    const client = this.store.get("client", clientId);
    return client && this.matchesResource(client) && client.expiresAt > Date.now()
      ? { id: client.id, redirectUris: client.redirectUris, grants: ["authorization_code", "refresh_token"] }
      : false;
  }

  async validateScope(_user: OAuth2Server.User, _client: OAuth2Server.Client, scope?: string[]): Promise<string[] | false> {
    const supportedScopes: readonly string[] = scopesForGrantProfile(this.config.grantProfile, this.config.dockerReadAccess);
    const values = scope ?? [...supportedScopes];
    return values.length > 0 && values.length <= supportedScopes.length && new Set(values).size === values.length &&
      values.every(value => supportedScopes.includes(value)) && values.includes("mac.control.read") ? values : false;
  }

  async saveAuthorizationCode(code: OAuth2Server.AuthorizationCode, client: OAuth2Server.Client, user: OAuth2Server.User): Promise<OAuth2Server.AuthorizationCode> {
    if (code.codeChallengeMethod !== "S256" || !code.codeChallenge || !/^[A-Za-z0-9_-]{43}$/u.test(code.codeChallenge)) {
      throw new OAuth2Server.InvalidRequestError("S256 PKCE is required");
    }
    const grantId = nonce();
    const scopes = code.scope as Array<(typeof OAUTH_SCOPES)[number]>;
    this.store.transaction(() => {
      this.store.put("grant", grantId, { clientId: client.id, principalId: this.config.principalId, scopes, expiresAt: Date.now() + GRANT_MS, revoked: false, ...this.resourceBinding() });
      this.store.put("code", fingerprint(code.authorizationCode), {
        clientId: client.id, redirectUri: code.redirectUri, challenge: code.codeChallenge!, scopes,
        grantId, principalId: this.config.principalId, expiresAt: code.expiresAt.getTime(), ...this.resourceBinding()
      });
    });
    return { ...code, client, user: { ...user, grantId } };
  }

  async getAuthorizationCode(value: string): Promise<OAuth2Server.AuthorizationCode | false> {
    const record = this.store.get("code", fingerprint(value));
    if (!record || !this.matchesResource(record) || record.expiresAt <= Date.now()) return false;
    const client = await this.getClient(record.clientId);
    if (!client) return false;
    return {
      authorizationCode: value, expiresAt: new Date(record.expiresAt), redirectUri: record.redirectUri,
      scope: record.scopes, codeChallenge: record.challenge, codeChallengeMethod: "S256", client,
      user: { id: record.principalId, grantId: record.grantId }
    };
  }

  async revokeAuthorizationCode(code: OAuth2Server.AuthorizationCode): Promise<boolean> {
    const record = this.store.get("code", fingerprint(code.authorizationCode));
    return Boolean(record && this.matchesResource(record) && this.store.delete("code", fingerprint(code.authorizationCode)));
  }

  async generateAccessToken(client: OAuth2Server.Client, user: OAuth2Server.User, scope: string[]): Promise<string> {
    const grantId = String(user.grantId);
    const grant = this.store.get("grant", grantId);
    if (!grant || !this.matchesResource(grant) || grant.revoked || grant.clientId !== client.id || grant.principalId !== user.id || grant.expiresAt <= Date.now() ||
        scope.some(value => !(grant.scopes as string[]).includes(value))) throw new OAuth2Server.InvalidGrantError("Invalid grant");
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ sid: grantId, azp: client.id, scope: scope.join(" ") })
      .setProtectedHeader({ alg: "ES256", kid: this.config.keyId, typ: "at+jwt" })
      .setIssuer(this.config.issuer).setAudience(this.config.resource).setSubject(this.config.principalId)
      .setIssuedAt(now).setExpirationTime(Math.min(now + ACCESS_SECONDS, Math.floor(grant.expiresAt / 1000)))
      .setJti(nonce()).sign(this.key);
  }

  async generateRefreshToken(): Promise<string> { return nonce(); }

  async saveToken(token: OAuth2Server.Token, client: OAuth2Server.Client, user: OAuth2Server.User): Promise<OAuth2Server.Token> {
    const grantId = String(user.grantId);
    const outcome = this.store.transaction(() => {
      const grant = this.store.get("grant", grantId);
      if (!grant || !this.matchesResource(grant) || grant.revoked || grant.expiresAt <= Date.now() || grant.clientId !== client.id || grant.principalId !== user.id) return undefined;
      // Consume the old refresh token in the same transaction as its successor.
      // Keep consumed hashes until absolute expiry to detect replay after restart.
      if (typeof user.refreshHash === "string") {
        const previous = this.store.get("refresh", user.refreshHash);
        if (!previous || previous.consumed || previous.grantId !== grantId || previous.clientId !== client.id) {
          this.store.revoke(grantId);
          return undefined;
        }
        this.store.put("refresh", user.refreshHash, { ...previous, consumed: true });
      }
      if (!token.refreshToken) throw new Error("Refresh token required");
      this.store.put("refresh", fingerprint(token.refreshToken), { clientId: client.id, grantId, expiresAt: grant.expiresAt, consumed: false });
      // Scope reduction remains effective across subsequent refreshes and status checks.
      this.store.put("grant", grantId, { ...grant, scopes: token.scope as Array<(typeof OAUTH_SCOPES)[number]> });
      return grant.expiresAt;
    });
    if (outcome === undefined) throw new OAuth2Server.InvalidGrantError("Invalid grant");
    return { ...token, client, user,
      accessTokenExpiresAt: new Date(Math.min(token.accessTokenExpiresAt!.getTime(), Math.floor(outcome / 1000) * 1000)),
      refreshTokenExpiresAt: new Date(outcome) };
  }

  async getRefreshToken(value: string): Promise<OAuth2Server.RefreshToken | false> {
    const key = fingerprint(value);
    const record = this.store.get("refresh", key);
    if (!record || record.expiresAt <= Date.now()) return false;
    const grant = this.store.get("grant", record.grantId);
    if (!grant || !this.matchesResource(grant) || grant.revoked || grant.expiresAt <= Date.now()) return false;
    if (record.consumed) { this.store.revoke(record.grantId); return false; }
    const client = await this.getClient(record.clientId);
    if (!client) return false;
    return { refreshToken: value, refreshTokenExpiresAt: new Date(record.expiresAt), scope: grant.scopes, client,
      user: { id: grant.principalId, grantId: record.grantId, refreshHash: key } };
  }

  // The actual atomic consume is deferred to saveToken; protocol failure does
  // not partially rotate a token. A racing exchange is rejected there.
  async revokeToken(): Promise<boolean> { return true; }

  async getAccessToken(value: string): Promise<OAuth2Server.Token | false> {
    try {
      const { payload } = await jwtVerify(value, createPublicKey(this.key), { issuer: this.config.issuer, audience: this.config.resource, algorithms: ["ES256"] });
      if (typeof payload.sid !== "string" || typeof payload.azp !== "string" || typeof payload.scope !== "string" || payload.sub !== this.config.principalId) return false;
      const grant = this.store.get("grant", payload.sid);
      if (!grant || !this.matchesResource(grant) || grant.revoked || grant.expiresAt <= Date.now() || grant.clientId !== payload.azp ||
          payload.scope.split(" ").some(scope => !(grant.scopes as string[]).includes(scope))) return false;
      const client = await this.getClient(payload.azp);
      return client ? { accessToken: value, accessTokenExpiresAt: new Date(payload.exp! * 1000), scope: payload.scope.split(" "), client,
        user: { id: payload.sub, grantId: payload.sid } } : false;
    } catch { return false; }
  }
}
