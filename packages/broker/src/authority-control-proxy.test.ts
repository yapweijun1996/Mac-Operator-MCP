import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  AuthorityControlIpcClient,
  type AuthorityControlOperation,
  type UnsignedAuthorityControlCommand
} from "./authority-control-ipc.js";
import { AuthorityControlProxyServer } from "./authority-control-proxy.js";

const NOW = 1_700_000_000_000;

test("owner operator proxy authenticates CLI frames and forwards only verified commands", async (t) => {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (process.platform !== "darwin" || uid === undefined || gid === undefined) {
    t.skip("native owner-peer transport requires a Darwin POSIX host");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-authority-proxy-"));
  const socketPath = join(directory, "operator.sock");
  const key = randomBytes(32);
  const forwarded: UnsignedAuthorityControlCommand[] = [];
  const proxy = new AuthorityControlProxyServer({
    socketPath,
    peerPolicy: { expectedUid: uid, expectedGid: gid },
    authenticationKey: key,
    now: () => NOW,
    upstream: {
      async execute(command) {
        forwarded.push(command);
        if (command.operation === "set_switch") {
          return { ok: true, operation: "set_switch", switch_name: command.switchName!, disabled: command.disabled!, responseProof: "" };
        }
        if (command.operation === "revoke") {
          return { ok: true, operation: "revoke", revocation_kind: command.revocationKind!, subject_id: command.subjectId!, revoked: true, responseProof: "" };
        }
        if (command.switchName !== undefined) {
          return { ok: true, operation: "read", switch_name: command.switchName, disabled: false, responseProof: "" };
        }
        return { ok: true, operation: "read", revocation_kind: command.revocationKind!, subject_id: command.subjectId!, revoked: false, responseProof: "" };
      }
    }
  });
  const client = new AuthorityControlIpcClient({ socketPath, authenticationKey: key, now: () => NOW });
  const command = {
    protocolVersion: "0.1",
    requestId: "proxy-request-1",
    nonce: "proxy-nonce-00000001",
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    operation: "set_switch" as AuthorityControlOperation,
    switchName: "process" as const,
    disabled: true,
    expectedDisabled: false,
    reason: "PROXY_TEST"
  } satisfies UnsignedAuthorityControlCommand;
  try {
    await proxy.listen();
    const response = await client.execute(command);
    assert.equal(response.ok, true);
    assert.equal(response.operation, "set_switch");
    assert.equal(response.switch_name, "process");
    assert.equal(response.disabled, true);
    assert.equal(forwarded.length, 1);
    assert.deepEqual(forwarded[0], command);
  } finally {
    client.dispose();
    await proxy.close();
    key.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});
