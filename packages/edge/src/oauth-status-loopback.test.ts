import assert from "node:assert/strict";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { createServer } from "node:https";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createLoopbackOAuthStatusFetch } from "./oauth-status-loopback.js";

const execFileAsync = promisify(execFile);

test("loopback OAuth status fetch pins issuer host, CA, and fixed local endpoint", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-oauth-status-loopback-"));
  const caKey = join(root, "ca.key");
  const caCert = join(root, "ca.crt");
  const leafKey = join(root, "leaf.key");
  const leafCsr = join(root, "leaf.csr");
  const leafCert = join(root, "leaf.crt");
  const serial = join(root, "ca.srl");
  const extensions = join(root, "leaf.ext");
  let server: ReturnType<typeof createServer> | undefined;
  try {
    await generateCertificateChain({ caKey, caCert, leafKey, leafCsr, leafCert, serial, extensions });
    server = createServer({ cert: await readFile(leafCert), key: await readFile(leafKey) });
    if (!server) throw new Error("Test HTTPS server was not created");
    const activeServer = server;
    let observedHost = "";
    let observedBody = "";
    activeServer.on("request", (request, response) => {
      observedHost = String(request.headers.host ?? "");
      request.setEncoding("utf8");
      request.on("data", chunk => { observedBody += chunk; });
      request.on("end", () => {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ active: true, scopes: ["mac.control.read"] }));
      });
    });
    await new Promise<void>((resolve, reject) => {
      activeServer.once("error", reject);
      activeServer.listen(0, "127.0.0.1", () => resolve());
    });
    const address = activeServer.address();
    assert.ok(address && typeof address !== "string");
    const publicUrl = new URL("https://issuer.example.test/oauth/status");
    const ca = await readFile(caCert);
    const fetchStatus = createLoopbackOAuthStatusFetch({
      publicUrl,
      loopbackUrl: new URL(`https://127.0.0.1:${address.port}/oauth/status`),
      serverName: "issuer.example.test",
      ca
    });
    const response = await fetchStatus(publicUrl, {
      method: "POST",
      headers: { authorization: "Bearer test-status-key", "content-type": "application/json" },
      body: JSON.stringify({ sessionId: "s", subject: "owner" })
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { active: true, scopes: ["mac.control.read"] });
    assert.equal(observedHost, "issuer.example.test");
    assert.equal(observedBody, JSON.stringify({ sessionId: "s", subject: "owner" }));
    await assert.rejects(fetchStatus(new URL("https://other.example.test/oauth/status"), {
      method: "POST",
      headers: { authorization: "Bearer test-status-key", "content-type": "application/json" },
      body: "{}"
    }), /issuer-bound/u);
    assert.throws(() => createLoopbackOAuthStatusFetch({
      publicUrl,
      loopbackUrl: new URL(`https://localhost:${address.port}/oauth/status`),
      serverName: "issuer.example.test",
      ca
    }), /fixed HTTPS IPv4 loopback/u);
  } finally {
    await new Promise<void>(resolve => {
      if (!server?.listening) { resolve(); return; }
      server.close(() => resolve());
    });
    await rm(root, { recursive: true, force: true });
  }
});

async function generateCertificateChain(paths: {
  caKey: string;
  caCert: string;
  leafKey: string;
  leafCsr: string;
  leafCert: string;
  serial: string;
  extensions: string;
}): Promise<void> {
  await execFileAsync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", paths.caKey,
    "-out", paths.caCert, "-days", "1", "-subj", "/CN=Mac Operator Test CA", "-addext", "basicConstraints=critical,CA:TRUE"],
  { cwd: dirname(paths.caKey), env: { PATH: "/usr/bin:/bin" }, timeout: 10_000, maxBuffer: 64 * 1024 });
  await execFileAsync("/usr/bin/openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", paths.leafKey,
    "-out", paths.leafCsr, "-subj", "/CN=issuer.example.test"],
  { cwd: dirname(paths.caKey), env: { PATH: "/usr/bin:/bin" }, timeout: 10_000, maxBuffer: 64 * 1024 });
  await writeFile(paths.extensions, "subjectAltName=DNS:issuer.example.test\n");
  await execFileAsync("/usr/bin/openssl", ["x509", "-req", "-in", paths.leafCsr, "-CA", paths.caCert, "-CAkey", paths.caKey,
    "-CAcreateserial", "-CAserial", paths.serial, "-out", paths.leafCert, "-days", "1", "-extfile", paths.extensions],
  { cwd: dirname(paths.caKey), env: { PATH: "/usr/bin:/bin" }, timeout: 10_000, maxBuffer: 64 * 1024 });
  await chmod(paths.caKey, 0o600);
}

function dirname(path: string): string {
  return path.slice(0, path.lastIndexOf("/"));
}
