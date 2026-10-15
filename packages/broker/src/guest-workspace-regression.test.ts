import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import test from "node:test";
import { workspaceStagerScriptForTesting } from "./container-engine.js";
import { guestFileScriptForTesting } from "./container-task-runner.js";

const require = createRequire(import.meta.url);

// Substitute only the Linux descriptor paths and guest UID; run the shipped programs unchanged.
function run(script: string, root: string, query: unknown, uid = 65532) {
  let stdout = "";
  let stderr = "";
  const fds = new Map<number, string>();
  const translate = (value: unknown): unknown => {
    if (typeof value !== "string") return value;
    if (value === "/workspace") return root;
    const match = /^\/proc\/self\/fd\/(\d+)(.*)$/u.exec(value);
    return match ? fds.get(Number(match[1]))! + match[2] : value;
  };
  const adapter: Record<string, unknown> = { ...fs,
    openSync(path: string, ...args: unknown[]) {
      const actual = translate(path) as string;
      const fd = Reflect.apply(fs.openSync, fs, [actual, ...args]) as number;
      fds.set(fd, actual);
      return fd;
    },
    readlinkSync(path: string) { return fds.get(Number(path.split("/").pop()))!.replace(root, "/workspace"); }
  };
  for (const name of ["readdirSync", "lstatSync", "mkdirSync", "chmodSync", "renameSync", "unlinkSync"] as const) {
    adapter[name] = (path: unknown, ...args: unknown[]) => Reflect.apply(fs[name], fs,
      name === "renameSync" ? [translate(path), translate(args[0])] : [translate(path), ...args]);
  }
  const process = { argv: ["node", JSON.stringify(query)], getuid: () => uid,
    stdout: { write(value: string) { stdout += value; } }, stderr: { write(value: string) { stderr += value; } }, exitCode: 0 };
  runInNewContext(script, { require: (name: string) => name === "fs" ? adapter : require(name), process, Buffer, TextDecoder }, { timeout: 5000 });
  return { stdout, stderr, exitCode: process.exitCode };
}

for (const readonly of [false, true]) {
  test(`shipped stager retains executable scripts and seals modes (readonly=${readonly})`, () => {
    const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "guest-stage-mode-")));
    try {
      const script = workspaceStagerScriptForTesting();
      const uid = readonly ? 0 : 65532;
      assert.equal(run(script, root, { op: "begin", readonly }, uid).exitCode, 0);
      for (const executable of [false, true]) {
        const content = Buffer.from("#!/bin/sh\necho before\n");
        const path = executable ? "run.sh" : "plain.txt";
        const chunk = { path, executable, offset: 0, data: content.toString("base64"), final: true,
          size: content.length, sha256: createHash("sha256").update(content).digest("hex") };
        assert.equal(run(script, root, { op: "chunks", chunks: [chunk] }, uid).exitCode, 0);
        assert.equal(fs.statSync(join(root, path)).mode & 0o7777, executable ? 0o700 : 0o600);
      }
      if (!readonly) {
        assert.equal(run(guestFileScriptForTesting(), root, { op: "edit", path: "run.sh", oldText: "before", newText: "after" }).exitCode, 0);
        assert.equal(fs.statSync(join(root, "run.sh")).mode & 0o7777, 0o700);
      }
      assert.equal(run(script, root, { op: "seal", readonly }, uid).exitCode, 0);
      assert.equal(fs.statSync(join(root, "run.sh")).mode & 0o7777, readonly ? 0o555 : 0o700);
      assert.equal(fs.statSync(join(root, "plain.txt")).mode & 0o7777, readonly ? 0o444 : 0o600);
      assert.equal(execFileSync(join(root, "run.sh"), [], { cwd: root, env: {}, shell: false,
        timeout: 5000, maxBuffer: 8192, encoding: "utf8" }), readonly ? "before\n" : "after\n");
    } finally { fs.chmodSync(root, 0o700); fs.rmSync(root, { recursive: true, force: true }); }
  });
}

for (const character of ["é", "你", "😀"]) {
  test(`shipped guest reader paginates ${character} at the default byte cap`, () => {
    const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "guest-read-page-")));
    try {
      const content = "a".repeat(16383) + character + "tail";
      fs.writeFileSync(join(root, "file.txt"), content);
      const first = run(guestFileScriptForTesting(), root, { op: "read", path: "file.txt" });
      assert.equal(first.exitCode, 0);
      const page = JSON.parse(first.stdout) as { content: string; nextOffset: number };
      assert.equal(page.nextOffset, 16383);
      const second = run(guestFileScriptForTesting(), root, { op: "read", path: "file.txt", offset: page.nextOffset });
      assert.equal(second.exitCode, 0);
      assert.equal(page.content + JSON.parse(second.stdout).content, content);
      assert.equal(JSON.parse(second.stdout).nextOffset, null);
      assert.equal(run(guestFileScriptForTesting(), root, { op: "read", path: "file.txt", offset: 16383, maxBytes: 1 }).exitCode, 1);
      assert.equal(run(guestFileScriptForTesting(), root, { op: "read", path: "file.txt", offset: 16384 }).exitCode, 1);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
}

test("shipped stager rejects malformed execution markers and verifies content before granting execution", () => {
  for (const executable of [undefined, "true", 0, true]) {
    const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "guest-mode-deny-")));
    try {
      const content = Buffer.from("#!/bin/sh\necho safe\n");
      const result = run(workspaceStagerScriptForTesting(), root, { op: "chunks", chunks: [{
        path: "run.sh", executable, offset: 0, data: content.toString("base64"), final: true,
        size: content.length, sha256: "0".repeat(64) }] });
      assert.equal(result.exitCode, 1);
      if (fs.existsSync(join(root, "run.sh"))) assert.equal(fs.statSync(join(root, "run.sh")).mode & 0o111, 0);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test("shipped guest reader rejects malformed UTF-8 and incomplete EOF", () => {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "guest-read-invalid-")));
  try {
    for (const bytes of [[0x61, 0xe0, 0x80, 0x62], [0x61, 0xe2, 0x82]]) {
      fs.writeFileSync(join(root, "file.txt"), Buffer.from(bytes));
      assert.equal(run(guestFileScriptForTesting(), root, { op: "read", path: "file.txt" }).exitCode, 1);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
