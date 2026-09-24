import assert from "node:assert/strict";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { once } from "node:events";
import test from "node:test";
import { connectionDiagnostic, enableConnectionDiagnostics } from "./connection-diagnostics.js";

test("connection diagnostics never include request secrets or unrecognized strings", () => {
  const request = {
    url: "/authorize?code=SECRET&state=SECRET", method: "GET",
    headers: { authorization: "Bearer SECRET", cookie: "SECRET", "user-agent": "ChatGPT SECRET" }
  } as IncomingMessage;
  const response = { statusCode: 303 } as ServerResponse;
  assert.deepEqual(connectionDiagnostic(request, response), {
    path: "/authorize", method: "GET", status: 303, client: "openai", authenticated: true
  });
  request.url = "/SECRET"; request.method = "SECRET"; request.headers["user-agent"] = "SECRET";
  assert.ok(!JSON.stringify(connectionDiagnostic(request, response)).includes("SECRET"));
  Object.assign(request, { originalUrl: "/.well-known/oauth-protected-resource/mcp?secret=SECRET", url: "/" });
  assert.equal(connectionDiagnostic(request, response).path, "/.well-known/oauth-protected-resource/mcp");
  assert.ok(!JSON.stringify(connectionDiagnostic(request, response)).includes("SECRET"));
  Object.assign(request, { originalUrl: "/mcp?token=SECRET", body: { method: "SECRET", params: { protocolVersion: "SECRET", arguments: { password: "SECRET" } } } });
  assert.ok(!JSON.stringify(connectionDiagnostic(request, response)).includes("SECRET"));
});

test("personal diagnostics observe actual completed requests and unsubscribe", async () => {
  const records: string[] = [];
  const original = console.log;
  console.log = value => records.push(String(value));
  const stop = enableConnectionDiagnostics("edge");
  const server = createServer((_req, res) => { res.writeHead(401); res.end(); });
  try {
    server.listen(0, "127.0.0.1"); await once(server, "listening");
    const address = server.address(); assert.ok(address && typeof address === "object");
    await fetch(`http://127.0.0.1:${address.port}/mcp?secret=SECRET`);
    assert.equal(records.length, 2);
    const received = JSON.parse(records[0]!);
    const completed = JSON.parse(records[1]!);
    assert.equal(received.phase, "received");
    assert.equal(completed.phase, "completed");
    assert.equal(completed.status, 401);
    assert.equal(received.requestId, completed.requestId);
    assert.ok(completed.durationMs >= 0);
    assert.ok(!records[0]!.includes("SECRET"));
    stop();
    await fetch(`http://127.0.0.1:${address.port}/mcp`);
    assert.equal(records.length, 2);
  } finally {
    stop(); console.log = original; server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

test("diagnostics correlate Cloudflare requests and record aborted responses without secrets", async () => {
  const records: string[] = [];
  const original = console.log;
  console.log = value => records.push(String(value));
  const stop = enableConnectionDiagnostics("auth");
  const server = createServer((_req, res) => { res.writeHead(200); res.flushHeaders(); });
  try {
    server.listen(0, "127.0.0.1"); await once(server, "listening");
    const address = server.address(); assert.ok(address && typeof address === "object");
    for (const ray of ["a3e651e878f533e2-SIN", "SECRET"]) {
      const req = httpRequest({ host: "127.0.0.1", port: address.port, path: "/authorize?code=SECRET",
        headers: { "cf-ray": ray, authorization: "Bearer SECRET" } });
      req.end();
      await once(req, "response");
      req.destroy();
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    const events = records.map(record => JSON.parse(record));
    assert.deepEqual(events.map(event => event.phase), ["received", "aborted", "received", "aborted"]);
    assert.equal(events[0].ray, "a3e651e878f533e2-SIN");
    assert.equal(events[1].ray, events[0].ray);
    assert.equal(events[2].ray, undefined);
    assert.ok(!records.join("").includes("SECRET"));
  } finally {
    stop(); console.log = original; server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
