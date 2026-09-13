import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import { loadProtectedEdgeAuthenticationKey } from "./authentication-key.js";
import { EdgeRequestFactory } from "./request-factory.js";

test("Edge authentication key loader binds protected file bytes to a digest", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-edge-auth-key-"));
  const path = join(directory, "edge.key");
  const key = randomBytes(32);
  try {
    await writeFile(path, key, { mode: 0o600 });
    assert.deepEqual(await loadProtectedEdgeAuthenticationKey(path, sha256(key)), key);
    await writeFile(path, Buffer.from(key.toString("hex"), "ascii"), { mode: 0o600 });
    assert.deepEqual(await loadProtectedEdgeAuthenticationKey(path, sha256(key)), key);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Edge authentication key loader rejects unsafe files and digest mismatch", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-edge-auth-key-deny-"));
  const path = join(directory, "edge.key");
  const linkPath = join(directory, "edge-link.key");
  const key = randomBytes(32);
  try {
    await writeFile(path, key, { mode: 0o600 });
    await assert.rejects(
      loadProtectedEdgeAuthenticationKey(path, sha256(randomBytes(32))),
      /digest precondition failed/u
    );
    await chmod(path, 0o640);
    await assert.rejects(
      loadProtectedEdgeAuthenticationKey(path, sha256(key)),
      /not be accessible/u
    );
    await chmod(path, 0o600);
    await symlink(path, linkPath);
    await assert.rejects(
      loadProtectedEdgeAuthenticationKey(linkPath, sha256(key)),
      /non-symlink/u
    );
    await chmod(directory, 0o750);
    await assert.rejects(
      loadProtectedEdgeAuthenticationKey(path, sha256(key)),
      /directory must not be accessible/u
    );
    await assert.rejects(
      loadProtectedEdgeAuthenticationKey(`${directory}/./edge.key`, sha256(key)),
      /canonical/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Edge request factory can load a protected key without accepting raw startup bytes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-edge-auth-factory-"));
  const path = join(directory, "edge.key");
  const key = randomBytes(32);
  try {
    await writeFile(path, key, { mode: 0o600 });
    const factory = await EdgeRequestFactory.fromProtectedKeyFile({
      authenticationKeyPath: path,
      expectedAuthenticationKeyDigest: sha256(key),
      authenticationKeyId: "edge-key-1",
      brokerAudience: "mac-operator-broker",
      policyVersion: () => "policy-1",
      now: () => 1_700_000_000_000,
      randomId: (() => {
        let index = 0;
        return () => `id-${++index}`;
      })()
    });
    const request = factory.create("mac_health", {}, {
      principalId: "principal-1",
      issuer: "issuer-1",
      audience: "mac-operator-broker",
      sessionId: "session-1",
      edgeId: "edge-1",
      scopes: ["mac.control.read"],
      issuedAtMs: 1_699_999_000_000,
      expiresAtMs: 1_700_001_000_000
    });
    assert.equal(request.authenticationKeyId, "edge-key-1");
    assert.equal("authenticationKey" in request, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
