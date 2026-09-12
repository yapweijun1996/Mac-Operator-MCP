import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { PackageInspectorImpl, validatePackageInspectRequest } from "./package-inspector.js";

function control(cancelled = false) {
  return { timeoutMs: 1_000, shouldCancel: () => cancelled };
}

test("package inspector returns bounded npm manifest metadata and lock presence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-package-inspect-"));
  try {
    await writeFile(join(directory, "package.json"), JSON.stringify({
      name: "fixture",
      scripts: { prepare: "echo must-not-run" },
      dependencies: { zod: "^3.0.0" },
      devDependencies: { typescript: "^5.0.0" },
      optionalDependencies: { optional: "1.0.0" }
    }));
    await writeFile(join(directory, "package-lock.json"), "{\"lockfileVersion\":3}");
    const inspector = new PackageInspectorImpl();
    const result = await inspector.inspect(await realpath(directory), "auto", false, control());
    assert.equal(result.manager, "npm");
    assert.deepEqual(result.lockfile, { present: true, path: "package-lock.json" });
    assert.deepEqual(result.dependencies, [
      { name: "zod", version: "^3.0.0", source: "dependencies" },
      { name: "typescript", version: "^5.0.0", source: "devDependencies" },
      { name: "optional", version: "1.0.0", source: "optionalDependencies" }
    ]);
    assert.equal(result.warnings.length, 0);
  } finally {
    await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true }));
  }
});

test("package inspector parses Python requirements without executing setup code", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-package-python-"));
  try {
    await writeFile(join(directory, "requirements.txt"), "requests>=2.0\n# ignored\n-r dev.txt\nuvicorn==0.30.0\n");
    const inspector = new PackageInspectorImpl();
    const result = await inspector.inspect(await realpath(directory), "pip", false, control());
    assert.equal(result.manager, "pip");
    assert.deepEqual(result.dependencies, [
      { name: "requests", version: ">=2.0", source: "requirements.txt" },
      { name: "uvicorn", version: "==0.30.0", source: "requirements.txt" }
    ]);
    assert.equal(result.lockfile.present, false);
  } finally {
    await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true }));
  }
});

test("package inspector records outdated lookup as disabled and never runs a package manager", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-package-outdated-"));
  try {
    await writeFile(join(directory, "Brewfile"), "brew \"jq\", version: \"1.7\"\ncask \"iterm2\"\n");
    const inspector = new PackageInspectorImpl();
    const result = await inspector.inspect(await realpath(directory), "auto", true, control());
    assert.equal(result.manager, "brew");
    assert.deepEqual(result.dependencies, [
      { name: "jq", version: "1.7", source: "Brewfile" },
      { name: "iterm2", version: "", source: "Brewfile" }
    ]);
    assert.deepEqual(result.outdated, []);
    assert.ok(result.warnings.some((warning) => warning.includes("allowlisted registry profile")));
  } finally {
    await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true }));
  }
});

test("package inspector fails closed for symlink roots, manifest links, and invalid inputs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-package-boundary-"));
  const target = join(directory, "target");
  const link = join(directory, "link");
  try {
    await mkdir(target);
    await writeFile(join(target, "package.json"), "{\"dependencies\":{\"safe\":\"1.0.0\"}}");
    await symlink(target, link);
    const inspector = new PackageInspectorImpl();
    await assert.rejects(
      inspector.inspect(resolve(link), "auto", false, control()),
      /non-symlink directory/u
    );
    await import("node:fs/promises").then(({ rm }) => rm(join(target, "package.json")));
    await symlink(join(directory, "other.json"), join(target, "package.json"));
    await assert.rejects(
      inspector.inspect(await realpath(target), "npm", false, control()),
      /manifest symlinks are denied/u
    );
    assert.throws(() => validatePackageInspectRequest("relative", "npm", false), BrokerError);
    assert.throws(() => validatePackageInspectRequest("/tmp/project", "unknown" as never, false), BrokerError);
  } finally {
    await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true }));
  }
});

test("package inspector cancellation is fail-closed before reading metadata", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-package-cancel-"));
  try {
    await writeFile(join(directory, "package.json"), "{\"dependencies\":{\"safe\":\"1.0.0\"}}");
    const inspector = new PackageInspectorImpl();
    await assert.rejects(
      inspector.inspect(await realpath(directory), "npm", false, control(true)),
      /cancelled/u
    );
  } finally {
    await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true }));
  }
});
