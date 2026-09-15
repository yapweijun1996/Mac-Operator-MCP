import {
  createLocalJWKSet,
  createRemoteJWKSet,
  customFetch,
  jwtVerify,
  type FetchImplementation,
  type JSONWebKeySet,
  type JWSAlgorithm,
  type JWTPayload,
  type RemoteJWKSet
} from "jose";
import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthTokenVerifier
} from "@modelcontextprotocol/server";
import { SCOPES, type Scope } from "@mac-operator/contracts";

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u;
const DEFAULT_ALGORITHMS: readonly JWSAlgorithm[] = ["RS256", "ES256"];
const DEFAULT_MAX_TOKEN_BYTES = 8 * 1024;
const DEFAULT_MAX_TOKEN_AGE_SECONDS = 3_600;
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 5;
const DEFAULT_JWKS_TIMEOUT_MS = 3_000;
const DEFAULT_JWKS_CACHE_MAX_AGE_MS = 10 * 60 * 1_000;
const DEFAULT_JWKS_COOLDOWN_MS = 30 * 1_000;
const MAX_JWKS_RESPONSE_BYTES = 256 * 1024;
const KNOWN_SCOPES = new Set<string>(SCOPES);

export interface JwtRevocationContext {
  issuerId: string;
  subject: string;
  sessionId: string;
  tokenId: string;
  expiresAt: number;
}

export interface JwtAccessTokenVerifierOptions {
  issuer: URL;
  issuerId: string;
  resourceServerUrl: URL;
  jwks?: JSONWebKeySet;
  jwksUri?: URL;
  jwksFetch?: FetchImplementation;
  allowedAlgorithms?: readonly JWSAlgorithm[];
  maxTokenBytes?: number;
  maxTokenAgeSeconds?: number;
  clockToleranceSeconds?: number;
  /** Permit a controlled test or operator profile to shorten unknown-kid refresh cooldown. */
  jwksCooldownMs?: number;
  revocationCheck?: (context: JwtRevocationContext) => Promise<boolean>;
}

/**
 * Create a Broker-facing verifier for short-lived signed OAuth access tokens.
 *
 * The issuer URL and the Broker issuer ID are intentionally separate. The raw
 * issuer URL stays at the Edge; only the configured bounded issuer ID is
 * projected into the Broker principal. Exactly one protected JWKS source must
 * be configured, and all failures become a generic invalid-token response.
 */
export function createJwtAccessTokenVerifier(options: JwtAccessTokenVerifierOptions): OAuthTokenVerifier {
  const validated = validateOptions(options);
  const keySet = createKeySet(validated);
  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      if (typeof token !== "string" || token.length === 0 || Buffer.byteLength(token, "utf8") > validated.maxTokenBytes) {
        throw invalidToken();
      }
      try {
        const verified = await jwtVerify(token, keySet, {
          algorithms: [...validated.allowedAlgorithms],
          issuer: validated.issuer.href,
          audience: validated.resourceServerUrl.href,
          maxTokenAge: validated.maxTokenAgeSeconds,
          clockTolerance: validated.clockToleranceSeconds,
          requiredClaims: ["exp", "iat", "iss", "sub", "aud", "jti"]
        });
        const claims = verified.payload;
        const subject = readClaimId(claims.sub);
        const tokenId = readClaimId(claims.jti);
        const sessionId = readOptionalClaimId(claims.sid) ?? tokenId;
        const expiresAt = readNumericDate(claims.exp);
        const issuedAtSeconds = readNumericDate(claims.iat);
        const clientId = readOptionalClaimId(claims.azp) ?? readOptionalClaimId(claims.client_id) ?? subject;
        const scopes = readScopes(claims);
        if (validated.revocationCheck && await validated.revocationCheck({
          issuerId: validated.issuerId,
          subject,
          sessionId,
          tokenId,
          expiresAt
        })) {
          throw invalidToken();
        }
        return {
          token,
          clientId,
          scopes,
          expiresAt,
          resource: new URL(validated.resourceServerUrl),
          extra: {
            principalId: subject,
            issuer: validated.issuerId,
            sessionId,
            issuedAtMs: issuedAtSeconds * 1_000
          }
        };
      } catch (error) {
        if (error instanceof OAuthError && error.code === OAuthErrorCode.InvalidToken) throw error;
        throw invalidToken();
      }
    }
  };
}

interface ValidatedOptions {
  issuer: URL;
  issuerId: string;
  resourceServerUrl: URL;
  jwks?: JSONWebKeySet;
  jwksUri?: URL;
  jwksFetch?: FetchImplementation;
  allowedAlgorithms: readonly JWSAlgorithm[];
  maxTokenBytes: number;
  maxTokenAgeSeconds: number;
  clockToleranceSeconds: number;
  jwksCooldownMs: number;
  revocationCheck?: (context: JwtRevocationContext) => Promise<boolean>;
}

function validateOptions(options: JwtAccessTokenVerifierOptions): ValidatedOptions {
  if (!options || typeof options !== "object") throw new Error("JWT verifier options are required");
  validateHttpsUrl(options.issuer, "JWT issuer URL");
  validateHttpsUrl(options.resourceServerUrl, "JWT resource URL");
  if (!ID_PATTERN.test(options.issuerId)) throw new Error("JWT issuer ID is malformed");
  if ((options.jwks === undefined) === (options.jwksUri === undefined)) {
    throw new Error("JWT verifier requires exactly one JWKS source");
  }
  if (options.jwksUri !== undefined) validateHttpsUrl(options.jwksUri, "JWT JWKS URL");
  if (options.jwksFetch !== undefined && options.jwksUri === undefined) {
    throw new Error("JWT JWKS fetch is only valid with a remote JWKS URL");
  }
  const allowedAlgorithms = options.allowedAlgorithms === undefined
    ? DEFAULT_ALGORITHMS
    : [...options.allowedAlgorithms];
  if (
    allowedAlgorithms.length === 0 ||
    allowedAlgorithms.some((algorithm) => typeof algorithm !== "string" || !/^(?:RS|PS|ES|EdDSA)[0-9A-Za-z-]+$/u.test(algorithm))
  ) {
    throw new Error("JWT allowed algorithms are malformed");
  }
  const maxTokenBytes = boundedInteger(options.maxTokenBytes ?? DEFAULT_MAX_TOKEN_BYTES, 256, 64 * 1024, "JWT token byte limit");
  const maxTokenAgeSeconds = boundedInteger(options.maxTokenAgeSeconds ?? DEFAULT_MAX_TOKEN_AGE_SECONDS, 1, 86_400, "JWT max token age");
  const clockToleranceSeconds = boundedInteger(options.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS, 0, 60, "JWT clock tolerance");
  const jwksCooldownMs = boundedInteger(options.jwksCooldownMs ?? DEFAULT_JWKS_COOLDOWN_MS, 0, 10 * 60 * 1_000, "JWT JWKS cooldown");
  return {
    issuer: new URL(options.issuer),
    issuerId: options.issuerId,
    resourceServerUrl: new URL(options.resourceServerUrl),
    ...(options.jwks === undefined ? {} : { jwks: options.jwks }),
    ...(options.jwksUri === undefined ? {} : { jwksUri: new URL(options.jwksUri) }),
    ...(options.jwksFetch === undefined ? {} : { jwksFetch: options.jwksFetch }),
    allowedAlgorithms,
    maxTokenBytes,
    maxTokenAgeSeconds,
    clockToleranceSeconds,
    jwksCooldownMs,
    ...(options.revocationCheck === undefined ? {} : { revocationCheck: options.revocationCheck })
  };
}

function createKeySet(options: ValidatedOptions): RemoteJWKSet | ReturnType<typeof createLocalJWKSet> {
  if (options.jwks !== undefined) {
    try {
      return createLocalJWKSet(options.jwks);
    } catch {
      throw new Error("JWT local JWKS is malformed");
    }
  }
  if (options.jwksUri === undefined) throw new Error("JWT JWKS source is missing");
  try {
    const remoteOptions: Parameters<typeof createRemoteJWKSet>[1] = {
      timeoutDuration: DEFAULT_JWKS_TIMEOUT_MS,
      cacheMaxAge: DEFAULT_JWKS_CACHE_MAX_AGE_MS,
      cooldownDuration: options.jwksCooldownMs
    };
    const fetcher = options.jwksFetch ?? (globalThis.fetch as FetchImplementation | undefined);
    if (typeof fetcher !== "function") throw new Error("JWT remote JWKS fetch is unavailable");
    remoteOptions[customFetch] = createBoundedJwksFetch(fetcher, options.jwksUri);
    return createRemoteJWKSet(options.jwksUri, remoteOptions);
  } catch {
    throw new Error("JWT remote JWKS configuration is malformed");
  }
}

/**
 * Keep remote key material bounded before jose parses it. The JWKS endpoint is
 * startup-owned configuration, but its response is still an untrusted network
 * input and must not become an unbounded JSON allocation.
 */
function createBoundedJwksFetch(fetcher: FetchImplementation, expectedUrl: URL): FetchImplementation {
  return async (url, init) => {
    const response = await fetcher(url, init);
    if (response.redirected || (response.url !== "" && response.url !== expectedUrl.href)) {
      throw new Error("JWT remote JWKS redirects are not allowed");
    }
    if (!response.ok || response.status < 200 || response.status >= 300) {
      throw new Error("JWT remote JWKS response status is not successful");
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== "application/json" && contentType !== "application/jwk-set+json") {
      throw new Error("JWT remote JWKS response content type is not JSON");
    }
    const contentLength = response.headers.get("content-length");
    if (contentLength !== null && (!/^\\d+$/u.test(contentLength) || Number(contentLength) > MAX_JWKS_RESPONSE_BYTES)) {
      throw new Error("JWT remote JWKS response exceeds the byte limit");
    }
    if (response.body === null) {
      const text = await response.text();
      if (Buffer.byteLength(text, "utf8") > MAX_JWKS_RESPONSE_BYTES) {
        throw new Error("JWT remote JWKS response exceeds the byte limit");
      }
      return new Response(text, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      });
    }

    const reader = response.body.getReader();
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        const chunk = Buffer.from(next.value);
        totalBytes += chunk.byteLength;
        if (totalBytes > MAX_JWKS_RESPONSE_BYTES) {
          await reader.cancel();
          throw new Error("JWT remote JWKS response exceeds the byte limit");
        }
        chunks.push(chunk);
      }
    } finally {
      reader.releaseLock();
    }
    return new Response(Buffer.concat(chunks), {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });
  };
}

function readScopes(claims: JWTPayload): string[] {
  const scopeClaim = claims.scope;
  const scpClaim = claims.scp;
  if (scopeClaim !== undefined && typeof scopeClaim !== "string") throw invalidToken();
  if (scpClaim !== undefined && (!Array.isArray(scpClaim) || scpClaim.some((value) => typeof value !== "string"))) {
    throw invalidToken();
  }
  const values = [
    ...(typeof scopeClaim === "string" ? scopeClaim.split(/\s+/u).filter(Boolean) : []),
    ...(Array.isArray(scpClaim) ? scpClaim : [])
  ];
  return [...new Set(values.filter((scope): scope is Scope => KNOWN_SCOPES.has(scope)))];
}

function readClaimId(value: unknown): string {
  const result = readOptionalClaimId(value);
  if (result === undefined) throw invalidToken();
  return result;
}

function readOptionalClaimId(value: unknown): string | undefined {
  return typeof value === "string" && ID_PATTERN.test(value) ? value : undefined;
}

function readNumericDate(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) throw invalidToken();
  return value as number;
}

function validateHttpsUrl(value: URL, label: string): void {
  if (!(value instanceof URL) || value.protocol !== "https:" || value.username || value.password || value.search || value.hash) {
    throw new Error(`${label} must be an HTTPS URL without credentials, query, or fragment`);
  }
}

function boundedInteger(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`${label} is out of bounds`);
  return value;
}

function invalidToken(): OAuthError {
  return new OAuthError(OAuthErrorCode.InvalidToken, "Invalid access token");
}
