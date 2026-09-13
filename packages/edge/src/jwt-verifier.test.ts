import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPair, exportJWK, SignJWT, type JSONWebKeySet } from "jose";
import { OAuthError, OAuthErrorCode } from "@modelcontextprotocol/server";
import { createJwtAccessTokenVerifier, type JwtRevocationContext } from "./jwt-verifier.js";

const issuer = new URL("https://issuer.example.test");
const resourceServerUrl = new URL("https://edge.example.test/mcp");

test("JWT verifier validates issuer/audience/signature and projects bounded Broker identity", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwks = await createJwks(publicKey);
  const verifier = createJwtAccessTokenVerifier({
    issuer,
    issuerId: "issuer-prod",
    resourceServerUrl,
    jwks
  });
  const token = await createToken(privateKey);
  const auth = await verifier.verifyAccessToken(token);
  assert.equal(auth.token, token);
  assert.equal(auth.clientId, "client-1");
  assert.deepEqual(auth.scopes, ["mac.control.read", "mac.app.control"]);
  assert.equal(auth.resource?.href, resourceServerUrl.href);
  assert.equal(auth.extra?.principalId, "principal-1");
  assert.equal(auth.extra?.issuer, "issuer-prod");
  assert.equal(auth.extra?.sessionId, "session-1");
  assert.ok(Number.isSafeInteger(auth.extra?.issuedAtMs));
  assert.ok((auth.extra?.issuedAtMs as number) < (auth.expiresAt as number) * 1_000);
});

test("JWT verifier fails closed for expiry, audience, missing token identity, and revocation", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwks = await createJwks(publicKey);
  const revoked: JwtRevocationContext[] = [];
  const verifier = createJwtAccessTokenVerifier({
    issuer,
    issuerId: "issuer-prod",
    resourceServerUrl,
    jwks,
    revocationCheck: async (context) => {
      revoked.push(context);
      return true;
    }
  });
  const expectedExpiresAt = Math.floor(Date.now() / 1_000) + 300;
  const token = await createToken(privateKey, { expiresAt: expectedExpiresAt });
  await assertInvalid(verifier, token);
  assert.deepEqual(revoked, [{
    issuerId: "issuer-prod",
    subject: "principal-1",
    sessionId: "session-1",
    tokenId: "token-1",
    expiresAt: expectedExpiresAt
  }]);

  const wrongAudience = await createToken(privateKey, { audience: "https://other.example.test/mcp" });
  await assertInvalid(createJwtAccessTokenVerifier({ issuer, issuerId: "issuer-prod", resourceServerUrl, jwks }), wrongAudience);

  const expired = await createToken(privateKey, { expiresAt: Math.floor(Date.now() / 1_000) - 10 });
  await assertInvalid(createJwtAccessTokenVerifier({ issuer, issuerId: "issuer-prod", resourceServerUrl, jwks }), expired);

  const noJti = await createToken(privateKey, { tokenId: null });
  await assertInvalid(createJwtAccessTokenVerifier({ issuer, issuerId: "issuer-prod", resourceServerUrl, jwks }), noJti);
});

test("JWT verifier bounds and caches a remote JWKS fetch", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwks = await createJwks(publicKey);
  let fetchCount = 0;
  const verifier = createJwtAccessTokenVerifier({
    issuer,
    issuerId: "issuer-prod",
    resourceServerUrl,
    jwksUri: new URL("https://issuer.example.test/.well-known/jwks.json"),
    jwksCooldownMs: 0,
    jwksFetch: async () => {
      fetchCount += 1;
      return new Response(JSON.stringify(jwks), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
  });
  const token = await createToken(privateKey);
  await verifier.verifyAccessToken(token);
  await verifier.verifyAccessToken(token);
  assert.equal(fetchCount, 1);
  assert.throws(() => createJwtAccessTokenVerifier({
    issuer: new URL("http://issuer.example.test"),
    issuerId: "issuer-prod",
    resourceServerUrl,
    jwks
  }), /HTTPS URL/u);
  assert.throws(() => createJwtAccessTokenVerifier({ issuer, issuerId: "issuer-prod", resourceServerUrl, jwks, jwksUri: new URL("https://issuer.example.test/jwks") }), /exactly one JWKS/u);
});

test("JWT verifier refreshes remote JWKS when a rotated key id appears", async () => {
  const oldKey = await generateKeyPair("RS256");
  const newKey = await generateKeyPair("RS256");
  let jwks = await createJwks(oldKey.publicKey, "key-1");
  let fetchCount = 0;
  const verifier = createJwtAccessTokenVerifier({
    issuer,
    issuerId: "issuer-prod",
    resourceServerUrl,
    jwksUri: new URL("https://issuer.example.test/.well-known/jwks.json"),
    jwksCooldownMs: 0,
    jwksFetch: async () => {
      fetchCount += 1;
      return new Response(JSON.stringify(jwks), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
  });
  await verifier.verifyAccessToken(await createToken(oldKey.privateKey));
  jwks = await createJwks(newKey.publicKey, "key-2");
  await verifier.verifyAccessToken(await createToken(newKey.privateKey, { keyId: "key-2" }));
  assert.equal(fetchCount, 2);
});

async function createJwks(publicKey: CryptoKey, keyId = "key-1"): Promise<JSONWebKeySet> {
  const jwk = await exportJWK(publicKey);
  return {
    keys: [{ ...jwk, kid: keyId, alg: "RS256", use: "sig" }]
  };
}

async function createToken(
  privateKey: CryptoKey,
  options: { audience?: string; expiresAt?: number; tokenId?: string | null; keyId?: string } = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1_000);
  const token = new SignJWT({
    sid: "session-1",
    azp: "client-1",
    scope: "mac.control.read mac.app.control"
  })
    .setProtectedHeader({ alg: "RS256", kid: options.keyId ?? "key-1", typ: "at+jwt" })
    .setIssuer(issuer.href)
    .setAudience(options.audience ?? resourceServerUrl.href)
    .setSubject("principal-1")
    .setIssuedAt(now - 5)
    .setExpirationTime(options.expiresAt ?? now + 300);
  if (options.tokenId !== null) token.setJti(options.tokenId ?? "token-1");
  return token.sign(privateKey);
}

async function assertInvalid(verifier: { verifyAccessToken(token: string): Promise<unknown> }, token: string): Promise<void> {
  await assert.rejects(verifier.verifyAccessToken(token), (error: unknown) => {
    return error instanceof OAuthError && error.code === OAuthErrorCode.InvalidToken;
  });
}
