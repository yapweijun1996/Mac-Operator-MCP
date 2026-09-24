import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fstatSync, openSync, readdirSync } from "node:fs";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  createDescriptorHandoffSocketPair,
  parseDescriptorHandoffFrame,
  receiveAuthenticatedDescriptorHandoff,
  receiveDescriptorHandoff,
  sendDescriptorHandoff
} from "./descriptor-handoff-receiver.js";
import { capturePeerProcessIdentity, loadNativePeerAdapter } from "./peer-credentials.js";

test("native descriptor handoff preserves an opaque payload and descriptor identity", { skip: process.platform !== "darwin" }, () => {
  const native = loadNativePeerAdapter();
  const [sender, receiver] = createDescriptorHandoffSocketPair();
  const source = openSync("/dev/null", "r");
  let received: number | undefined;
  try {
    const sourceStat = fstatSync(source);
    const payload = Buffer.from("signed-attestation-bytes-v1", "utf8");
    sendDescriptorHandoff(sender, payload, [source]);
    const frame = receiveDescriptorHandoff(receiver, { maxPayloadBytes: 1024, expectedDescriptorCount: 1 });
    const receivedDescriptor = frame.descriptors[0];
    assert.ok(receivedDescriptor !== undefined);
    received = receivedDescriptor;
    assert.deepEqual(frame.payload, payload);
    assert.equal(frame.descriptors.length, 1);
    assert.equal(fstatSync(receivedDescriptor).dev, sourceStat.dev);
    assert.equal(fstatSync(receivedDescriptor).ino, sourceStat.ino);
    assert.deepEqual(Object.keys(frame), ["payload", "descriptors"]);
    assert.throws(
      () => sendDescriptorHandoff(sender, payload, [source, source]),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    if (received !== undefined) native.closeUnixDescriptor(received);
    native.closeUnixDescriptor(source);
    native.closeUnixDescriptor(sender);
    native.closeUnixDescriptor(receiver);
  }
});

test("native descriptor handoff closes received descriptors when the expected count mismatches", { skip: process.platform !== "darwin" }, () => {
  const native = loadNativePeerAdapter();
  const [sender, receiver] = createDescriptorHandoffSocketPair();
  const source = openSync("/dev/null", "r");
  const openDescriptorCount = () => readdirSync("/dev/fd").length;
  try {
    sendDescriptorHandoff(sender, Buffer.from("opaque", "utf8"), [source]);
    const beforeReceive = openDescriptorCount();
    assert.throws(
      () => receiveDescriptorHandoff(receiver, { maxPayloadBytes: 1024, expectedDescriptorCount: 2 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    assert.equal(openDescriptorCount(), beforeReceive, "a rejected frame must close every received descriptor");
  } finally {
    native.closeUnixDescriptor(source);
    native.closeUnixDescriptor(sender);
    native.closeUnixDescriptor(receiver);
  }
});

test("native descriptor handoff closes delivered descriptors above the protocol limit", { skip: process.platform !== "darwin" }, (context) => {
  const native = loadNativePeerAdapter();
  const [sender, receiver] = createDescriptorHandoffSocketPair();
  const source = openSync("/dev/null", "r");
  const sourceStat = fstatSync(source);
  const listOpenMatchingDescriptors = () => readdirSync("/dev/fd")
    .map((entry) => Number.parseInt(entry, 10))
    .filter((descriptor) => Number.isSafeInteger(descriptor))
    .filter((descriptor) => {
      try {
        const descriptorStat = fstatSync(descriptor);
        return descriptorStat.dev === sourceStat.dev && descriptorStat.ino === sourceStat.ino;
      } catch {
        return false;
      }
    });
  try {
    const senderProgram = [
      "import array, os, socket",
      "connection = socket.socket(fileno=3)",
      "source = os.open('/dev/null', os.O_RDONLY)",
      "rights = array.array('i', [source] * 5)",
      "frame = b'MOPH' + bytes((1, 5, 0, 0)) + (0).to_bytes(4, 'big')",
      "connection.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])",
      "connection.shutdown(socket.SHUT_WR)"
    ].join("\n");
    const sent = spawnSync("python3", ["-c", senderProgram], {
      stdio: ["ignore", "pipe", "pipe", sender],
      timeout: 5_000
    });
    if ((sent.error as (Error & { code?: string }) | undefined)?.code === "ENOENT") {
      context.skip("python3 is unavailable for the oversized ancillary-data fixture");
      return;
    }
    assert.equal(sent.status, 0, sent.stderr.toString("utf8"));
    const beforeReceive = new Set(listOpenMatchingDescriptors());
    assert.throws(
      () => receiveDescriptorHandoff(receiver, { maxPayloadBytes: 1024, expectedDescriptorCount: 4 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    const leaked = listOpenMatchingDescriptors().filter((descriptor) => !beforeReceive.has(descriptor));
    for (const descriptor of leaked) native.closeUnixDescriptor(descriptor);
    assert.deepEqual(leaked, [], "rejected SCM_RIGHTS descriptors must not remain open");
  } finally {
    native.closeUnixDescriptor(source);
    native.closeUnixDescriptor(sender);
    native.closeUnixDescriptor(receiver);
  }
});

test("authenticated descriptor handoff authorizes the peer before reading the frame", { skip: process.platform !== "darwin" }, () => {
  const native = loadNativePeerAdapter();
  const [sender, receiver] = createDescriptorHandoffSocketPair();
  const source = openSync("/dev/null", "r");
  let received: number | undefined;
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  try {
    sendDescriptorHandoff(sender, Buffer.from("opaque", "utf8"), [source]);
    const result = receiveAuthenticatedDescriptorHandoff(receiver, {
      expectedUid: uid,
      expectedGid: gid,
      allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
    }, { maxPayloadBytes: 1024, expectedDescriptorCount: 1 });
    const receivedDescriptor = result.frame.descriptors[0];
    assert.ok(receivedDescriptor !== undefined);
    received = receivedDescriptor;
    assert.equal(result.credentials.pid, process.pid);
    assert.equal(result.frame.payload.toString("utf8"), "opaque");
  } finally {
    if (received !== undefined) native.closeUnixDescriptor(received);
    native.closeUnixDescriptor(source);
    native.closeUnixDescriptor(sender);
    native.closeUnixDescriptor(receiver);
  }
});

test("native descriptor handoff receive is bounded when the peer sends nothing", { skip: process.platform !== "darwin" }, () => {
  const native = loadNativePeerAdapter();
  const [sender, receiver] = createDescriptorHandoffSocketPair();
  try {
    assert.throws(
      () => receiveDescriptorHandoff(receiver, { maxPayloadBytes: 1024, expectedDescriptorCount: 1, timeoutMs: 25 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    native.closeUnixDescriptor(sender);
    native.closeUnixDescriptor(receiver);
  }
});

test("descriptor handoff parsing is bounded and exact", () => {
  const valid = { payload: Buffer.from("ok"), descriptors: [3] };
  assert.deepEqual(parseDescriptorHandoffFrame(valid, 2, 1).payload, Buffer.from("ok"));
  assert.throws(() => parseDescriptorHandoffFrame(valid, 1, 1), /malformed/u);
  assert.throws(() => parseDescriptorHandoffFrame({ ...valid, descriptors: [3, 4] }, 2, 1), /malformed/u);
  assert.throws(() => parseDescriptorHandoffFrame({ ...valid, extra: true }, 2, 1), /malformed/u);
});
