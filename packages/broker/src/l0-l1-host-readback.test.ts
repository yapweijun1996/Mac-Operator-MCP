import assert from "node:assert/strict";
import { realpathSync } from "node:fs";
import test from "node:test";
import { inspectNetwork } from "./network-inspector.js";
import { inspectProcess, inspectProcesses } from "./process-inspector.js";
import { inspectSystem } from "./system-inspector.js";
import { FilesystemInspector } from "./filesystem-inspector.js";

test("real macOS L0/L1 readback stays metadata-only and bounded", (t) => {
  if (process.platform !== "darwin") {
    t.skip("real host readback requires macOS");
    return;
  }

  const system = inspectSystem(true);
  assert.match(system.osVersion, /^.{1,128}$/u);
  assert.match(system.architecture, /^.{1,128}$/u);
  assert.ok(system.cpuCount >= 1 && system.cpuCount <= 256);
  assert.ok(system.memoryBytes >= 1 && system.memoryBytes <= 1_000_000_000_000);
  assert.ok(system.uptimeSeconds >= 0 && system.uptimeSeconds <= 1_000_000_000);
  assert.ok(system.load);

  const network = inspectNetwork(false);
  assert.ok(network.interfaces.length <= 64);
  assert.equal(network.listeners.length, 0);
  assert.match(network.warnings[0] ?? "", /no active network probe/u);
  assert.ok(network.interfaces.every((item) => item.name.length <= 128 && item.addresses.length <= 32));
  const listenerStatus = inspectNetwork(true);
  assert.ok(listenerStatus.listeners.length <= 256);
  assert.match(listenerStatus.warnings.join(" "), /Listener metadata is unavailable|active network probe/u);

  const inventory = inspectProcesses(16, "pid");
  assert.ok(inventory.processes.length <= 16);
  assert.ok(inventory.processes.every((item) => /^uid:[0-9]+$/u.test(item.owner)));
  const current = inspectProcess(process.pid);
  assert.equal(current.pid, process.pid);
  assert.match(current.owner, /^uid:[0-9]+$/u);
  assert.ok(current.childPids.length <= 256);

  const systemLibrary = realpathSync.native("/System/Library");
  const filesystem = new FilesystemInspector([{
    rootId: "system-library",
    path: systemLibrary,
    metadata: true,
    contentRead: false,
    denyRelativePaths: ["Keychains", "LaunchAgents", "LaunchDaemons"]
  }]);
  const plan = filesystem.planPath(systemLibrary, "metadata");
  const metadata = filesystem.statPlanned(plan, false);
  assert.equal(metadata.path, systemLibrary);
  assert.equal(metadata.type, "directory");
  assert.equal(metadata.isSymlink, false);
  const listing = filesystem.listPlanned(plan, undefined, 8, false);
  assert.equal(listing.rootId, "system-library");
  assert.ok(listing.entries.length <= 8);
  assert.ok(listing.entries.every((entry) => entry.name.length > 0 && entry.name.length <= 256));
  const tree = filesystem.treePlanned(plan, 1, 24);
  assert.equal(tree.rootId, "system-library");
  assert.ok(tree.entries.length <= 24);
  assert.ok(tree.entries.every((entry) => entry.path.startsWith(`${systemLibrary}/`)));
  const storage = filesystem.analyzeStoragePlanned([plan], 5, 1);
  assert.ok(storage.volumes.length >= 1 && storage.volumes.length <= 32);
  assert.ok(storage.volumes.every((volume) => volume.totalBytes >= volume.availableBytes && volume.usedBytes >= 0));
  assert.ok(storage.consumers.length <= 5);
  assert.equal(storage.analyzedRoots[0], systemLibrary);
  assert.equal(storage.truncated, true);
  assert.match(storage.warnings.join(" "), /max_depth/u);
});
