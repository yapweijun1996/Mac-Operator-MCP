import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { buildSandboxExecArguments, renderTaskSandboxProfile } from "./sandbox-profile.js";
import { SandboxExecTaskRunner, type TaskIsolationProof } from "./task-runner.js";
import type { ProcessExecutionRequest } from "./process-supervisor.js";
import type { ResolvedTaskProfile } from "./task-profile.js";

function proof(): TaskIsolationProof {
  return {
    schemaVersion: "0.1",
    sandboxProfile: "deny-default-v0.1",
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    processTree: "owned",
    processTreePolicy: "single_process",
    evidenceRef: "test://sandbox-profile"
  };
}

function resolvedProfile(root: string, overrides: Partial<ResolvedTaskProfile> = {}): ResolvedTaskProfile {
  return {
    profile: "tests.echo",
    cwd: root,
    process: {
      executable: "/usr/bin/printf",
      args: ["sandboxed"],
      cwd: root,
      environment: {},
      timeoutMs: 1_000,
      outputCapBytes: 1_024
    },
    filesystemRoots: [root],
    networkPolicy: "none",
    networkAllowlist: [],
    processTreePolicy: "single_process",
    sandboxProfile: "deny-default-v0.1",
    verificationStrategy: "exit_status_and_declared_task_verification",
    ...overrides
  };
}

test("sandbox profile renderer emits a deterministic deny-default no-network policy", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-sbpl-"));
  const root = await realpath(directory);
  try {
    const profile = resolvedProfile(root);
    const rendered = renderTaskSandboxProfile(profile);
    assert.match(rendered, /^\(version 1\)\n\(import "system\.sb"\)\n\(deny default\)\n/u);
    assert.equal(rendered.includes("(allow process-fork)"), false);
    assert.match(rendered, /\(allow process-exec \(literal "\/usr\/bin\/printf"\)\)/u);
    assert.match(rendered, new RegExp(`\\(allow file-write\\* \\(subpath "${escapeRegExp(root)}"\\)\\)`));
    assert.equal(rendered.includes("network-outbound"), false);
    assert.match(rendered, /\(deny file-read\* \(regex #/u);
    assert.deepEqual(buildSandboxExecArguments(profile).slice(0, 2), ["-p", rendered]);
    assert.deepEqual(buildSandboxExecArguments(profile).slice(-1), ["sandboxed"]);
    const groupProfile = renderTaskSandboxProfile({ ...profile, processTreePolicy: "owned_group" });
    assert.match(groupProfile, /\(allow process-fork\)/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("sandbox profile renderer rejects broad roots, cwd escapes, and network allowlists", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-sbpl-deny-"));
  const root = await realpath(directory);
  try {
    assert.throws(
      () => renderTaskSandboxProfile(resolvedProfile(root, { filesystemRoots: ["/"] })),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    assert.throws(
      () => renderTaskSandboxProfile(resolvedProfile(root, { cwd: "/tmp" })),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    const allowlisted = renderTaskSandboxProfile(resolvedProfile(root, {
      networkPolicy: "allowlist",
      networkAllowlist: ["tcp://127.0.0.1:43123"]
    }));
    assert.match(allowlisted, /\(allow network-outbound \(remote tcp "localhost:43123"\)\)/u);
    assert.throws(
      () => renderTaskSandboxProfile(resolvedProfile(root, { networkPolicy: "allowlist", networkAllowlist: ["example.com:443"] })),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "NETWORK_DENIED"
    );
    assert.throws(
      () => renderTaskSandboxProfile(resolvedProfile(root, { networkPolicy: "unexpected" as never })),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("SandboxExecTaskRunner stays unavailable without explicit host evidence and opt-in", async () => {
  const runner = new SandboxExecTaskRunner({ isolationProof: proof() });
  assert.equal(runner.available, false);
  await assert.rejects(
    runner.run(resolvedProfile("/tmp"), { timeoutMs: 1_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("SandboxExecTaskRunner refuses the unevidenced owned-group policy", async () => {
  const runner = new SandboxExecTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: { ...proof(), processTreePolicy: "owned_group" }
  });
  assert.equal(runner.available, false);
  await assert.rejects(
    runner.run({} as ResolvedTaskProfile, { timeoutMs: 1_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("SandboxExecTaskRunner passes only Broker-rendered arguments to the supervisor", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-sbpl-runner-"));
  const root = await realpath(directory);
  let observed: ProcessExecutionRequest | undefined;
  const supervisor = {
    run: async (request: ProcessExecutionRequest) => {
      observed = request;
      return {
        state: "completed" as const,
        resultClass: "SUCCEEDED" as const,
        exitCode: 0,
        signal: null,
        stdout: "sandboxed",
        stderr: "",
        truncated: false,
        durationMs: 2,
        processId: 42,
        processGroupId: 42,
        terminationObserved: true
      };
    }
  };
  try {
    const runner = new SandboxExecTaskRunner({
      enabled: true,
      hostEvidenceAccepted: true,
      isolationProof: proof(),
      supervisor
    });
    if (process.platform !== "darwin") {
      assert.equal(runner.available, false);
      return;
    }
    const result = await runner.run(resolvedProfile(root), { timeoutMs: 500, shouldCancel: () => false });
    assert.equal(result.resultClass, "SUCCEEDED");
    assert.equal(result.verification.status, "verified");
    assert.equal(observed?.executable, "/usr/bin/sandbox-exec");
    assert.equal(observed?.cwd, root);
    assert.deepEqual(observed?.environment, {});
    assert.equal(observed?.timeoutMs, 500);
    assert.equal(observed?.outputCapBytes, 1_024);
    assert.equal(observed?.args[0], "-p");
    assert.equal(observed?.args[2], "/usr/bin/printf");
    assert.equal(observed?.args.includes("/bin/sh"), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("real macOS sandbox runner blocks inherited environment, protected files, and network", {
  skip: process.platform !== "darwin" || process.env.MOPS_REAL_SANDBOX !== "1"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-sbpl-real-"));
  const root = await realpath(directory);
  await writeFile(join(root, "fixture.txt"), "fixture", { mode: 0o600 });
  await mkdir(join(root, "nested"), { mode: 0o700 });
  await writeFile(join(root, "nested", ".env"), "synthetic-secret=redacted", { mode: 0o600 });
  await symlink("/private/etc/passwd", join(root, "passwd-link"));
  const runner = new SandboxExecTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: proof()
  });
  const previousCanary = process.env.MOP_CONTROLLER_SECRET;
  const previousHome = process.env.HOME;
  const previousSshAgent = process.env.SSH_AUTH_SOCK;
  const previousAwsProfile = process.env.AWS_PROFILE;
  process.env.MOP_CONTROLLER_SECRET = "synthetic-controller-canary";
  process.env.HOME = "/synthetic/controller-home";
  process.env.SSH_AUTH_SOCK = "/synthetic/ssh-agent.sock";
  process.env.AWS_PROFILE = "synthetic-profile";
  try {
    const canary = await runner.run({
      ...resolvedProfile(root),
      profile: "tests.canary",
      process: {
        ...resolvedProfile(root).process,
        executable: "/bin/bash",
        args: ["-c", "printf '%s:%s:%s:%s:' \"${MOP_CONTROLLER_SECRET-unset}\" \"${HOME-unset}\" \"${SSH_AUTH_SOCK-unset}\" \"${AWS_PROFILE-unset}\"; if [ -r /private/etc/passwd ]; then printf leaked; else printf denied; fi; printf ':'; if [ -r ./fixture.txt ]; then printf allowed; else printf denied; fi; printf ':'; if [ -r ./nested/.env ]; then printf leaked; else printf denied; fi; if [ -r ./passwd-link ]; then printf ':link-leaked'; else printf ':link-denied'; fi; printf created > ./created.txt"]
      }
    }, { timeoutMs: 2_000, shouldCancel: () => false });
    assert.equal(canary.resultClass, "SUCCEEDED");
    assert.equal(canary.stdout, "unset:unset:unset:unset:denied:allowed:denied:link-denied");
    assert.equal(await readFile(join(root, "created.txt"), "utf8"), "created");

    const allowedServer = await startHttpServer("network-allowed");
    const deniedServer = await startHttpServer("network-denied");
    try {
      const allowedNetwork = await runner.run({
        ...resolvedProfile(root),
        profile: "tests.network-allowlist",
        networkPolicy: "allowlist",
        networkAllowlist: [`tcp://localhost:${allowedServer.port}`],
        process: {
          ...resolvedProfile(root).process,
          executable: "/usr/bin/curl",
          args: ["--silent", "--show-error", "--connect-timeout", "1", `http://localhost:${allowedServer.port}`]
        }
      }, { timeoutMs: 2_000, shouldCancel: () => false });
      assert.equal(allowedNetwork.resultClass, "SUCCEEDED", JSON.stringify(allowedNetwork));
      assert.equal(allowedNetwork.stdout, "network-allowed");

      const deniedNetwork = await runner.run({
        ...resolvedProfile(root),
        profile: "tests.network-denied",
        networkPolicy: "allowlist",
        networkAllowlist: [`tcp://localhost:${allowedServer.port}`],
        process: {
          ...resolvedProfile(root).process,
          executable: "/usr/bin/curl",
          args: ["--silent", "--show-error", "--connect-timeout", "1", `http://localhost:${deniedServer.port}`]
        }
      }, { timeoutMs: 2_000, shouldCancel: () => false });
      assert.notEqual(deniedNetwork.resultClass, "SUCCEEDED");
      assert.equal(deniedNetwork.stdout, "");
    } finally {
      await closeHttpServer(allowedServer.server);
      await closeHttpServer(deniedServer.server);
    }

    const network = await runner.run({
      ...resolvedProfile(root),
      profile: "tests.network",
      process: {
        ...resolvedProfile(root).process,
        executable: "/usr/bin/curl",
        args: ["--connect-timeout", "1", "http://example.com"]
      }
    }, { timeoutMs: 3_000, shouldCancel: () => false });
    assert.notEqual(network.resultClass, "SUCCEEDED");
    assert.equal(network.stdout, "");

    const childAttempt = await runner.run({
      ...resolvedProfile(root),
      profile: "tests.child-denied",
      process: {
        ...resolvedProfile(root).process,
        executable: "/bin/bash",
        args: ["-c", "printf before; /bin/sleep 1; printf after"]
      }
    }, { timeoutMs: 2_000, shouldCancel: () => false });
    assert.equal(childAttempt.resultClass, "EXECUTION_FAILED");
    assert.equal(childAttempt.stdout, "before");
    assert.match(childAttempt.stderr, /fork|Operation not permitted/u);
  } finally {
    if (previousCanary === undefined) delete process.env.MOP_CONTROLLER_SECRET;
    else process.env.MOP_CONTROLLER_SECRET = previousCanary;
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousSshAgent === undefined) delete process.env.SSH_AUTH_SOCK;
    else process.env.SSH_AUTH_SOCK = previousSshAgent;
    if (previousAwsProfile === undefined) delete process.env.AWS_PROFILE;
    else process.env.AWS_PROFILE = previousAwsProfile;
    await rm(directory, { recursive: true, force: true });
  }
});

test("real macOS sandbox runner maps active cancellation to process-group termination", {
  skip: process.platform !== "darwin" || process.env.MOPS_REAL_SANDBOX !== "1"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-sbpl-cancel-"));
  const root = await realpath(directory);
  const runner = new SandboxExecTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: proof()
  });
  let cancelled = false;
  const timer = setTimeout(() => { cancelled = true; }, 100);
  try {
    const result = await runner.run({
      ...resolvedProfile(root),
      profile: "tests.cancel",
      process: {
        ...resolvedProfile(root).process,
        executable: "/bin/sleep",
        args: ["5"]
      }
    }, { timeoutMs: 2_000, shouldCancel: () => cancelled });
    assert.equal(result.state, "cancelled");
    assert.equal(result.resultClass, "CANCELLED");
    assert.equal(result.verification.status, "failed");
  } finally {
    clearTimeout(timer);
    await rm(directory, { recursive: true, force: true });
  }
});

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

async function startHttpServer(body: string): Promise<{ server: ReturnType<typeof createServer>; port: number }> {
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end(body);
  });
  return await new Promise((resolve, reject) => {
    const onError = (error: Error) => {
      server.removeListener("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.removeListener("error", onError);
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("HTTP fixture did not expose a numeric port"));
        return;
      }
      resolve({ server, port: (address as AddressInfo).port });
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(0, "127.0.0.1");
  });
}

async function closeHttpServer(server: ReturnType<typeof createServer>): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}
