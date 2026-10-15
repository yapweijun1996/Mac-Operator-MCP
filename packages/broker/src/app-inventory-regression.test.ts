import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import test from "node:test";
import { AppInventoryInspectorImpl } from "./app-inspector.js";
import { AppControlInspectorImpl } from "./app-control.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

type Node = { kind: "directory" | "link" | "file"; bundleId?: string; version?: string; package?: boolean; canonical?: string; unreadable?: boolean };
const control = { timeoutMs: 5000, shouldCancel: () => false };
function success(stdout = ""): ProcessExecutionResult {
  return { state: "completed", resultClass: "SUCCEEDED", exitCode: 0, signal: null, stdout, stderr: "", truncated: false,
    durationMs: 1, processId: 1, processGroupId: 1, terminationObserved: true };
}

// Run the exact shipped JXA with Foundation/AppKit metadata seams; no app is launched.
function fixture() {
  const nodes = new Map<string, Node>();
  const running: { bundleIdentifier: string; localizedName: string }[] = [];
  const listed: string[] = [];
  const bundles: string[] = [];
  const unwrap = (value: unknown): any => value && typeof value === "object" && "value" in value ? value.value : value;
  const getPath = (value: unknown) => String(unwrap(value));
  function add(path: string, node: Node) {
    nodes.set(path, node);
    const parent = path.slice(0, path.lastIndexOf("/"));
    if (parent && !nodes.has(parent)) add(parent, { kind: "directory" });
  }
  const objc = Object.assign((value: string) => ({ value, get stringByResolvingSymlinksInPath() { return nodes.get(value)?.canonical ?? value; } }), {
    NSHomeDirectory: () => "/Users/owner",
    NSFileType: "NSFileType", NSFileTypeDirectory: "directory", NSFileTypeSymbolicLink: "link",
    NSFileManager: { defaultManager: {
      fileExistsAtPath(value: unknown) { return nodes.has(getPath(value)); },
      contentsOfDirectoryAtPathError(value: unknown) {
        const path = getPath(value);
        listed.push(path);
        if (!nodes.has(path) || nodes.get(path)?.unreadable) throw new Error("unreadable");
        const prefix = path + "/";
        return [...nodes.keys()].filter(entry => entry.startsWith(prefix) && !entry.slice(prefix.length).includes("/")).map(entry => entry.slice(prefix.length));
      },
      attributesOfItemAtPathError(value: unknown) {
        const node = nodes.get(getPath(value));
        if (!node) throw new Error("missing");
        return { objectForKey: () => node.kind };
      }
    } },
    NSBundle: { bundleWithPath(value: unknown) {
      const path = getPath(value);
      bundles.push(path);
      const node = nodes.get(path);
      return node?.bundleId ? { objectForInfoDictionaryKey(key: unknown) {
        if (node.unreadable) throw new Error("metadata unavailable");
        return ({ CFBundleIdentifier: node.bundleId, CFBundleName: "Example", CFBundleShortVersionString: node.version ?? "1.0" } as Record<string, string | undefined>)[getPath(key)] ?? "";
      } } : null;
    } },
    NSWorkspace: { sharedWorkspace: {
      runningApplications: { js: running }, isFilePackageAtPath(value: unknown) { return nodes.get(getPath(value))?.package === true; }
    } }
  });
  const inspector = new AppInventoryInspectorImpl({ async run(request) {
    assert.equal(request.executable, "/usr/bin/osascript");
    assert.deepEqual(request.environment, {});
    const stdout = runInNewContext(request.args[3]!, { ObjC: { import() {}, unwrap }, $: objc }, { timeout: 5000 }) as string;
    return success(stdout);
  } });
  return { add, nodes, running, listed, bundles, inspector };
}

for (const count of [499, 500, 501]) {
  test(`inventory prioritizes a running app among ${count} installed apps and reports omissions`, async () => {
    const f = fixture();
    for (let index = 0; index < count; index++) f.add(`/Applications/App${index}.app`, { kind: "directory", bundleId: `com.example.App${index}` });
    f.running.push({ bundleIdentifier: "com.example.Running", localizedName: "Running" });
    const result = await f.inspector.list(false, true, control);
    assert.equal(result.apps.length, Math.min(count + 1, 500));
    assert.equal(result.apps.some(app => app.bundleId === "com.example.Running" && app.running), true);
    assert.equal(result.truncated, count + 1 > 500);
    assert.equal(result.warnings.length > 0, count + 1 > 500);
    assert.equal(JSON.stringify(result).includes("/Applications"), false);
  });
}

for (const [runningOnly, includeInstalled] of [[true, true], [true, false], [false, false]] as const) {
  test(`running filter precedes installed discovery (${runningOnly}, ${includeInstalled})`, async () => {
    const f = fixture();
    for (let index = 0; index < 501; index++) f.add(`/Applications/App${index}.app`, { kind: "directory", bundleId: `com.example.App${index}` });
    f.running.push({ bundleIdentifier: "com.example.Running", localizedName: "Running" });
    const result = await f.inspector.list(runningOnly, includeInstalled, control);
    assert.deepEqual(result.apps.map(app => app.bundleId), ["com.example.Running"]);
    assert.equal(result.truncated, false);
    assert.deepEqual(result.warnings, []);
    assert.deepEqual(f.listed, []);
  });
}

test("running capacity overflow reports truncation without installed scanning", async () => {
  const f = fixture();
  for (let index = 0; index < 501; index++) f.running.push({ bundleIdentifier: `com.example.App${index}`, localizedName: "Running" });
  const result = await f.inspector.list(true, false, control);
  assert.equal(result.apps.length, 500);
  assert.equal(result.apps.every(app => app.running), true);
  assert.equal(result.truncated, true);
});

test("inventory merges duplicate running and installed metadata at the exact cap", async () => {
  const f = fixture();
  for (let index = 0; index < 500; index++) f.add(`/Applications/App${index}.app`, { kind: "directory", bundleId: `com.example.App${index}`, version: "2.0" });
  f.add("/System/Applications/Duplicate.app", { kind: "directory", bundleId: "com.example.App0" });
  f.running.push({ bundleIdentifier: "com.example.App0", localizedName: "Active" });
  const result = await f.inspector.list(false, true, control);
  assert.equal(result.apps.length, 500);
  assert.equal(result.truncated, false);
  assert.equal(result.apps.find(app => app.bundleId === "com.example.App0")?.version, "2.0");
  assert.equal(result.apps.find(app => app.bundleId === "com.example.App0")?.running, true);
});

test("Utilities and ordinary nested apps are discoverable and open through the fixed bundle command", async () => {
  const f = fixture();
  f.add("/System/Applications/Utilities/Activity Monitor.app", { kind: "directory", bundleId: "com.apple.ActivityMonitor" });
  f.add("/Applications/Direct.app", { kind: "directory", bundleId: "com.example.Direct" });
  f.add("/Applications/Vendor/Tools/Editor.app", { kind: "directory", bundleId: "com.example.Editor" });
  f.add("/Users/owner/Applications/Utilities/Personal.app", { kind: "directory", bundleId: "com.example.Personal" });
  const inventory = await f.inspector.list(false, true, control);
  assert.deepEqual(inventory.apps.map(app => app.bundleId), ["com.apple.ActivityMonitor", "com.example.Direct", "com.example.Editor", "com.example.Personal"]);
  const observed: string[][] = [];
  const controller = new AppControlInspectorImpl(f.inspector, { async run(request) {
    assert.equal(request.executable, "/usr/bin/open");
    assert.equal(request.cwd, "/");
    assert.deepEqual(request.environment, {});
    observed.push([...request.args]);
    f.running.push({ bundleIdentifier: "com.apple.ActivityMonitor", localizedName: "Activity Monitor" });
    return success();
  } });
  const result = await controller.open("bundle:com.apple.ActivityMonitor", undefined, undefined, control);
  assert.equal(result.verified, true);
  assert.deepEqual(observed, [["-b", "com.apple.ActivityMonitor"]]);
});

test("discovery skips symlinks, packages and app internals and deduplicates Utilities roots", async () => {
  const f = fixture();
  f.add("/Applications/Linked.app", { kind: "link", bundleId: "com.example.Linked" });
  f.add("/Applications/Alias/Hidden.app", { kind: "directory", bundleId: "com.example.Alias" });
  f.nodes.set("/Applications/Alias", { kind: "link", canonical: "/outside" });
  f.add("/Applications/Outer.app", { kind: "directory", bundleId: "com.example.Outer" });
  f.add("/Applications/Outer.app/Contents/Helper.app", { kind: "directory", bundleId: "com.example.Helper" });
  f.add("/Applications/Plugin.bundle/Hidden.app", { kind: "directory", bundleId: "com.example.Plugin" });
  f.nodes.get("/Applications/Plugin.bundle")!.package = true;
  f.add("/Applications/Utilities/Utility.app", { kind: "directory", bundleId: "com.example.Utility" });
  const result = await f.inspector.list(false, true, control);
  assert.deepEqual(result.apps.map(app => app.bundleId), ["com.example.Outer", "com.example.Utility"]);
  assert.equal(f.listed.filter(path => path === "/Applications/Utilities").length, 1);
  assert.equal(f.bundles.includes("/Applications/Linked.app"), false);
  assert.equal(f.listed.some(path => path.includes("Outer.app")), false);
});

for (const count of [10000, 10001]) {
  test(`installed discovery reports its inspected-entry boundary (${count})`, async () => {
    const f = fixture();
    for (let index = 0; index < count; index++) f.add(`/Applications/file${index}`, { kind: "file" });
    const result = await f.inspector.list(false, true, control);
    assert.deepEqual(result.apps, []);
    assert.equal(result.truncated, count > 10000);
  });
}

test("nested discovery reports omitted depth while preserving the exact supported depth", async () => {
  const f = fixture();
  f.add("/Applications/d0/d1/d2/d3/Edge.app", { kind: "directory", bundleId: "com.example.Edge" });
  f.add("/Applications/d0/d1/d2/d3/d4/Deep.app", { kind: "directory", bundleId: "com.example.Deep" });
  const result = await f.inspector.list(false, true, control);
  assert.deepEqual(result.apps.map(app => app.bundleId), ["com.example.Edge"]);
  assert.equal(result.truncated, true);
});

test("directory discovery stays bounded and reserves standard Utilities roots", async () => {
  const f = fixture();
  for (let index = 0; index < 150; index++) f.add(`/Applications/vendor${index}`, { kind: "directory" });
  f.add("/System/Applications/Utilities/Activity Monitor.app", { kind: "directory", bundleId: "com.apple.ActivityMonitor" });
  const result = await f.inspector.list(false, true, control);
  assert.ok(f.listed.length <= 128);
  assert.equal(result.apps.some(app => app.bundleId === "com.apple.ActivityMonitor"), true);
  assert.equal(result.truncated, true);
});

test("unreadable metadata is reported as incomplete while missing optional roots are ignored", async () => {
  const f = fixture();
  assert.equal((await f.inspector.list(false, true, control)).truncated, false);
  f.add("/Applications/Unreadable", { kind: "directory", unreadable: true });
  assert.equal((await f.inspector.list(false, true, control)).truncated, true);
  const bundle = fixture();
  bundle.add("/Applications/Unreadable.app", { kind: "directory", bundleId: "com.example.Unreadable", unreadable: true });
  assert.equal((await bundle.inspector.list(false, true, control)).truncated, true);
});

test("explicit Utilities roots cannot traverse a link in an ancestor", async () => {
  const f = fixture();
  f.add("/Applications/Utilities/Hidden.app", { kind: "directory", bundleId: "com.example.Hidden" });
  f.nodes.get("/Applications")!.canonical = "/outside";
  f.nodes.get("/Applications/Utilities")!.canonical = "/outside/Utilities";
  const result = await f.inspector.list(false, true, control);
  assert.deepEqual(result.apps, []);
  assert.deepEqual(f.listed, []);
});
