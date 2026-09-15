import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { ProcessSupervisor } from "./process-supervisor.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";
import {
  DOCKER_CODE_SIGNATURE_EXPECTATION,
  DOCKER_EXECUTABLE_CANDIDATES,
  DockerInspectorImpl,
  dockerObjectIdentityMatches,
  parseDockerContainerRecord,
  parseDockerImageRecord,
  validateDockerLogsRequest,
  validateDockerObjectRequest
} from "./docker-inspector.js";

function result(stdout: string, overrides: Partial<ProcessExecutionResult> = {}): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout,
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 10,
    processGroupId: 10,
    terminationObserved: true,
    ...overrides
  };
}

class FakeSupervisor {
  readonly calls: ProcessExecutionRequest[] = [];
  constructor(private readonly responses: ProcessExecutionResult[]) {}
  async run(request: ProcessExecutionRequest): Promise<ProcessExecutionResult> {
    this.calls.push(request);
    const response = this.responses.shift();
    if (!response) throw new Error("unexpected Docker process call");
    return response;
  }
}

test("Docker status uses fixed local-only commands and omits raw daemon metadata", async () => {
  const supervisor = new FakeSupervisor([
    result("27.5.1\n"),
    result('{"ID":"abc123","Names":"web","State":"running"}\n'),
    result('{"ID":"sha256:deadbeef","Repository":"example/app","Tag":"latest"}\n')
  ]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  const status = await inspector.status(true, false, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.deepEqual(status.daemon, { available: true, version: "27.5.1", context: "local" });
  assert.deepEqual(status.containers, [{ id: "abc123", name: "web", state: "running" }]);
  assert.deepEqual(status.images, [{ id: "sha256:deadbeef", name: "example/app", tag: "latest" }]);
  assert.equal(supervisor.calls[0]?.executable, "/usr/bin/docker");
  assert.deepEqual(supervisor.calls[0]?.args, ["version", "--format", "{{.Server.Version}}"]);
  assert.deepEqual(supervisor.calls[0]?.environment, {
    DOCKER_CONFIG: "/var/empty",
    DOCKER_HOST: "unix:///var/run/docker.sock",
    HOME: "/var/empty"
  });
  assert.equal(supervisor.calls.some((call) => call.args.includes("-H") || call.args.includes("--host")), false);
});

test("Docker signature policy verifies the fixed executable before daemon access", async () => {
  const supervisor = new FakeSupervisor([
    result(""),
    result("", { stderr: "Identifier=docker\nTeamIdentifier=9BNSXJN65R\nCDHash=56df8f23b2a6bfd9d54bb07516561e3e24805ccd\n" }),
    result("27.5.1\n"),
    result('')
  ]);
  const inspector = new DockerInspectorImpl({
    supervisor,
    executable: "/Applications/Docker.app/Contents/Resources/bin/docker",
    requireCodeSignature: true,
    codeSignatureExpectation: DOCKER_CODE_SIGNATURE_EXPECTATION
  });
  const status = await inspector.status(false, false, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(status.daemon.available, true);
  assert.deepEqual(supervisor.calls.slice(0, 2).map((call) => call.args), [
    ["--verify", "--strict", "--deep", "/Applications/Docker.app/Contents/Resources/bin/docker"],
    ["-dv", "--verbose=4", "/Applications/Docker.app/Contents/Resources/bin/docker"]
  ]);
  assert.deepEqual(supervisor.calls[0]?.environment, {});
});

test("Docker signature policy denies an untrusted executable before daemon access", async () => {
  const supervisor = new FakeSupervisor([
    result(""),
    result("", { stderr: "Identifier=com.attacker.docker\nTeamIdentifier=9BNSXJN65R\n" })
  ]);
  const inspector = new DockerInspectorImpl({
    supervisor,
    executable: "/Applications/Docker.app/Contents/Resources/bin/docker",
    requireCodeSignature: true,
    codeSignatureExpectation: DOCKER_CODE_SIGNATURE_EXPECTATION
  });
  await assert.rejects(
    inspector.status(false, false, { timeoutMs: 10_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(supervisor.calls.length, 2);
});

test("Docker inspect returns bounded sanitized container metadata without env values", async () => {
  const supervisor = new FakeSupervisor([result(JSON.stringify([{
    Id: "abc123",
    Name: "/web",
    State: { Status: "running" },
    Config: { Image: "example/app:latest", Env: ["TOKEN=do-not-return"] },
    NetworkSettings: { Ports: { "8080/tcp": [{ HostIp: "0.0.0.0", HostPort: "18080" }] } },
    Mounts: [{ Source: "/Users/test/.ssh/id_ed25519", Destination: "/root/.ssh/id_ed25519", RW: false }]
  }]))]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  const inspection = await inspector.inspect("container", "abc123", { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(inspection.id, "abc123");
  assert.equal(inspection.name, "/web");
  assert.equal(inspection.state, "running");
  assert.equal(inspection.image, "example/app:latest");
  assert.deepEqual(inspection.ports, [{ protocol: "tcp", containerPort: 8080, hostPort: 18080 }]);
  assert.equal(inspection.mounts[0]?.source, "[REDACTED]");
  assert.equal(JSON.stringify(inspection).includes("TOKEN"), false);
  assert.deepEqual(supervisor.calls[0]?.args, ["inspect", "--type", "container", "abc123"]);
});

test("Docker inspect rejects conflicting native object identities", async () => {
  const supervisor = new FakeSupervisor([result(JSON.stringify([{ Id: "abc123", ID: "different" }]))]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  await assert.rejects(
    inspector.inspect("container", "abc123", { timeoutMs: 10_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
});

test("Docker inspect rejects a different object when the requested target is an ID", async () => {
  const supervisor = new FakeSupervisor([result(JSON.stringify([{
    Id: "def4567890abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    Name: "/web"
  }]))]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  await assert.rejects(
    inspector.inspect("container", "abc123", { timeoutMs: 10_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
  );
});

test("Docker inspect rejects missing object identity even when a name matches", async () => {
  const supervisor = new FakeSupervisor([result(JSON.stringify([{ Name: "/web" }]))]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  await assert.rejects(
    inspector.inspect("container", "web", { timeoutMs: 10_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
});

test("Docker inspect accepts bounded ID prefixes and exact name readback", () => {
  const fullId = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  assert.equal(dockerObjectIdentityMatches("container", fullId.slice(0, 12), fullId, "/web"), true);
  assert.equal(dockerObjectIdentityMatches("container", "web", fullId, "/web"), true);
  assert.equal(dockerObjectIdentityMatches("container", "web", fullId, "/other"), false);
  assert.equal(dockerObjectIdentityMatches("container", "abcdef", "fedcba0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "/abcdef"), false);
  assert.equal(dockerObjectIdentityMatches("container", fullId, fullId.slice(0, 12), "/web"), false);
  assert.equal(dockerObjectIdentityMatches("image", "sha256:" + fullId, "sha256:" + fullId, ""), true);
});

test("Docker inspect rechecks mutable name targets by canonical ID", async () => {
  const fullId = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const supervisor = new FakeSupervisor([
    result(JSON.stringify([{ Id: fullId, Name: "/web" }])),
    result(JSON.stringify([{ Id: fullId, Name: "/web" }]))
  ]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  const inspection = await inspector.inspect("container", "web", { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(inspection.id, fullId);
  assert.deepEqual(supervisor.calls.map((call) => call.args), [
    ["inspect", "--type", "container", "web"],
    ["inspect", "--type", "container", fullId]
  ]);
});

test("Docker inspect rejects a name target replaced between identity observations", async () => {
  const firstId = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const replacementId = "fedcba0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const supervisor = new FakeSupervisor([
    result(JSON.stringify([{ Id: firstId, Name: "/web" }])),
    result(JSON.stringify([{ Id: replacementId, Name: "/web" }]))
  ]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  await assert.rejects(
    inspector.inspect("container", "web", { timeoutMs: 10_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
  );
});

test("Docker logs redact secrets and preserve bounded timestamped lines", async () => {
  const supervisor = new FakeSupervisor([result(
    "2026-09-13T01:02:03.000000000Z token=super-secret-value\nplain line\n",
    { truncated: true, resultClass: "OUTPUT_LIMIT", state: "failed" }
  )]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  const logs = await inspector.logs("abc123", 20, 60, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(logs.entries.length, 2);
  assert.equal(logs.entries[0]?.timestamp, "2026-09-13T01:02:03.000Z");
  assert.equal(logs.entries[0]?.line, "[REDACTED]");
  assert.equal(logs.truncated, true);
  assert.ok(logs.warnings.some((warning) => warning.includes("redacted")));
  assert.deepEqual(supervisor.calls[0]?.args, ["logs", "--timestamps", "--tail", "20", "--since", "60s", "abc123"]);
});

test("Docker status fails closed when the daemon is unavailable", async () => {
  const supervisor = new FakeSupervisor([result("", { resultClass: "EXECUTION_FAILED", state: "failed", exitCode: 1 })]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  const status = await inspector.status(false, true, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.deepEqual(status.daemon, { available: false });
  assert.equal(status.containers.length, 0);
  assert.equal(status.images.length, 0);
  assert.ok(status.warnings.some((warning) => warning.includes("unavailable")));
});

test("Docker status does not convert active cancellation into success", async () => {
  const supervisor = new FakeSupervisor([result("", { resultClass: "CANCELLED", state: "cancelled" })]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  await assert.rejects(
    inspector.status(false, false, { timeoutMs: 10_000, shouldCancel: () => true }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
});

test("real Docker Desktop readback uses the trusted executable exception", {
  skip: process.platform !== "darwin" || process.env.MOPS_REAL_DOCKER !== "1"
}, async () => {
  const supervisor = new ProcessSupervisor({
    maxConcurrent: 2,
    requireRootOwnedExecutable: true,
    trustedUserOwnedExecutablePaths: DOCKER_EXECUTABLE_CANDIDATES,
    allowedEnvironmentKeys: ["DOCKER_CONFIG", "DOCKER_HOST", "HOME"]
  });
  try {
    const inspector = new DockerInspectorImpl({
      supervisor,
      requireCodeSignature: true,
      codeSignatureExpectation: DOCKER_CODE_SIGNATURE_EXPECTATION
    });
    const status = await inspector.status(false, false, { timeoutMs: 15_000, shouldCancel: () => false });
    assert.equal(status.daemon.available, true);
    assert.equal(status.daemon.context, "local");
    assert.ok(status.containers.length > 0);
    assert.deepEqual(status.warnings, []);
    assert.equal(status.truncated, false);
    const first = status.containers[0];
    assert.ok(first);
    const inspection = await inspector.inspect("container", first.id, { timeoutMs: 15_000, shouldCancel: () => false });
    assert.equal(inspection.id, first.id);
    assert.equal(inspection.objectType, "container");
    assert.equal(inspection.truncated, false);
  } finally {
    await supervisor.close();
  }
});

test("Docker target validation rejects traversal-like and unsupported identifiers", () => {
  assert.throws(() => validateDockerObjectRequest("container", "../secret"), (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED");
  assert.throws(() => validateDockerObjectRequest("container", "--format"), (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED");
  assert.throws(() => validateDockerObjectRequest("container", "/var/run/docker.sock"), (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED");
  assert.throws(() => validateDockerObjectRequest("image", "unix:///var/run/docker.sock"), (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED");
  assert.throws(() => validateDockerObjectRequest("plugin" as never, "abc123"), (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED");
  assert.throws(() => validateDockerLogsRequest("abc123", 0, 1), (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED");
  assert.throws(() => validateDockerLogsRequest("--tail", 20, 1), (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED");
});

test("Docker line result parsers require plain known-field records and reject alias ambiguity", () => {
  const accessorRecord: Record<string, unknown> = {};
  Object.defineProperty(accessorRecord, "ID", { enumerable: true, get: () => "accessor-id" });
  assert.equal(parseDockerContainerRecord(accessorRecord), undefined);
  assert.equal(parseDockerContainerRecord({ ID: "abc123", State: "running", unexpected: "authority" }), undefined);
  assert.equal(parseDockerContainerRecord({ ID: "abc123", Id: "different", State: "running" }), undefined);
  assert.deepEqual(parseDockerContainerRecord({ ID: "abc123", Names: "web", State: "running" }), {
    id: "abc123",
    name: "web",
    state: "running"
  });
  assert.deepEqual(parseDockerContainerRecord({ ID: "abc123", Names: "web", State: "running", Platform: "linux/arm64" }), {
    id: "abc123",
    name: "web",
    state: "running"
  });
  assert.equal(parseDockerImageRecord({ ID: "sha256:abc", Repository: "example/app", Tag: "latest", unexpected: true }), undefined);
  assert.deepEqual(parseDockerImageRecord({ ID: "sha256:abc", Repository: "example/app", Tag: "latest" }), {
    id: "sha256:abc",
    name: "example/app",
    tag: "latest"
  });
});

test("Docker logs cap line count and individual line size", async () => {
  const supervisor = new FakeSupervisor([result(`${"x\n".repeat(5_001)}${"y".repeat(9_000)}\n`)]);
  const inspector = new DockerInspectorImpl({ supervisor, executable: "/usr/bin/docker" });
  const logs = await inspector.logs("abc123", 20, 0, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(logs.entries.length, 20);
  assert.equal(logs.truncated, true);
  assert.ok(logs.entries.every((entry) => entry.line.length <= 8_192));
  assert.ok(logs.warnings.some((warning) => warning.includes("lines were capped")));
  assert.ok(logs.warnings.some((warning) => warning.includes("line length was capped")));
});
