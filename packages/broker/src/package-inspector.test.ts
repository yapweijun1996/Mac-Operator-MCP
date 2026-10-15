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

const pythonArrayForms = [
  '[project]\ndependencies = ["requests>=2.31", "flask>=3"]\n',
  "[project]\ndependencies = ['requests>=2.31', 'flask>=3']\n",
  '[project]\ndependencies = [\n "requests>=2.31", "flask>=3",\n]\n',
  '[project]\ndependencies = ["requests>=2.31",\n "flask>=3"]\n',
  '[project] # project metadata\ndependencies = [ # dependencies\n # ignored\n "requests>=2.31", # first\n "flask>=3", # second\n] # end\n',
  '[project]\n"dependencies" = ["requests>=2.31", "flask>=3"]\n'
];
for (const [index, text] of pythonArrayForms.entries()) {
  test(`Python dependency arrays preserve equivalent supported formatting ${index}`, async t => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "package-python-array-")));
    t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })); });
    await writeFile(join(directory, "pyproject.toml"), text);
    const result = await new PackageInspectorImpl().inspect(directory, "pip", false, control());
    assert.deepEqual(result.dependencies, [
      { name: "requests", version: ">=2.31", source: "pyproject.toml" },
      { name: "flask", version: ">=3", source: "pyproject.toml" }
    ]);
    assert.deepEqual(result.warnings, []);
    assert.equal(result.truncated, false);
  });
}

for (const manager of ["pip", "uv", "poetry"] as const) {
  test(`Python project arrays are parsed for ${manager}`, async t => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "package-python-manager-")));
    t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })); });
    await writeFile(join(directory, "pyproject.toml"), '[project]\ndependencies=["flask>=3"]\n');
    const result = await new PackageInspectorImpl().inspect(directory, manager, false, control());
    assert.deepEqual(result.dependencies, [{ name: "flask", version: ">=3", source: "pyproject.toml" }]);
  });
}

test("Python dependency arrays preserve extras, quoted markers, escaped quotes and URL fragments", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "package-python-quotes-")));
  t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })); });
  await writeFile(join(directory, "pyproject.toml"), String.raw`[project]
dependencies = [
  "uvicorn[standard]>=0.30; python_version < '3.13'",
  "flask>=3; os_name == \"posix\"",
  'demo @ https://example.invalid/demo.whl#sha256=abc'
]
`);
  const result = await new PackageInspectorImpl().inspect(directory, "pip", false, control());
  assert.deepEqual(result.dependencies, [
    { name: "uvicorn", version: ">=0.30; python_version < '3.13'", source: "pyproject.toml" },
    { name: "flask", version: '>=3; os_name == "posix"', source: "pyproject.toml" },
    { name: "demo", version: "@ https://example.invalid/demo.whl#sha256=abc", source: "pyproject.toml" }
  ]);
  assert.deepEqual(result.warnings, []);
});

for (const body of ['["flask>=3"', '["flask>=3", 42]', '["flask>=3",, "requests"]',
  '["""flask>=3"""]', '["flask>=3" "requests"]', String.raw`["flask\U0000003e=3"]`]) {
  test(`unsupported or malformed Python arrays report omissions ${body}`, async t => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "package-python-unsupported-")));
    t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })); });
    await writeFile(join(directory, "pyproject.toml"), `[project]\ndependencies=${body}\n`);
    const result = await new PackageInspectorImpl().inspect(directory, "pip", false, control());
    assert.equal(result.dependencies.length, 0);
    assert.ok(result.warnings.some(warning => /Python.*array/u.test(warning)));
  });
}

test("Python arrays support empty content, CRLF, Unicode escapes and later Poetry sections", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "package-python-sections-")));
  t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })); });
  const inspector = new PackageInspectorImpl();
  await writeFile(join(directory, "pyproject.toml"), '[project]\r\ndependencies=[ # empty\r\n]\r\n');
  const empty = await inspector.inspect(directory, "pip", false, control());
  assert.deepEqual(empty.dependencies, []);
  assert.deepEqual(empty.warnings, []);
  await writeFile(join(directory, "pyproject.toml"), String.raw`[project]
dependencies=["flask\u003e=3"]
[tool.poetry.dependencies]
python="^3.12"
requests="^2.31"
[tool.poetry.group.main.dependencies]
uvicorn="^0.30"
`);
  const result = await inspector.inspect(directory, "poetry", false, control());
  assert.deepEqual(result.dependencies, [
    { name: "flask", version: ">=3", source: "pyproject.toml" },
    { name: "requests", version: "^2.31", source: "poetry" },
    { name: "uvicorn", version: "^0.30", source: "poetry" }
  ]);
  assert.deepEqual(result.warnings, []);
});

test("Python array output retains dependency limits and duplicate suppression", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "package-python-cap-")));
  t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })); });
  const values = Array.from({ length: 5001 }, (_, index) => `package${index}>=1`);
  values.unshift(values[0]!);
  await writeFile(join(directory, "pyproject.toml"), `[project]\ndependencies=${JSON.stringify(values)}\n`);
  const result = await new PackageInspectorImpl().inspect(directory, "pip", false, { timeoutMs: 10000, shouldCancel: () => false });
  assert.equal(result.dependencies.length, 5000);
  assert.equal(result.dependencies[0]?.name, "package0");
  assert.equal(result.dependencies.at(-1)?.name, "package4999");
  assert.equal(result.truncated, true);
});

test("Python array parsing checks cancellation inside a populated array", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "package-python-array-cancel-")));
  t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })); });
  await writeFile(join(directory, "pyproject.toml"), `[project]\ndependencies=${JSON.stringify(Array.from({ length: 100 }, (_, index) => `package${index}`))}\n`);
  let checks = 0;
  await assert.rejects(new PackageInspectorImpl().inspect(directory, "pip", false, {
    timeoutMs: 10000, shouldCancel: () => ++checks >= 10
  }), (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED");
  assert.ok(checks >= 10);
});

for (const [label, text] of [["oversized", "#".repeat(512 * 1024 + 1)],
  ["secret", '[project]\ndependencies=["safe"]\n# api_key=supersecretvalue\n']] as const) {
  test(`Python manifest ${label} guard remains fail-closed`, async t => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "package-python-guard-")));
    t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })); });
    await writeFile(join(directory, "pyproject.toml"), text);
    await assert.rejects(new PackageInspectorImpl().inspect(directory, "pip", false, control()),
      (error: unknown) => error instanceof BrokerError && error.errorClass === (label === "oversized" ? "OUTPUT_LIMIT" : "POLICY_DENIED"));
  });
}

test("Python array inspection refuses manifest symlinks", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "package-python-link-")));
  t.after(async () => { await import("node:fs/promises").then(({ rm }) => rm(directory, { recursive: true, force: true })); });
  await writeFile(join(directory, "real.toml"), '[project]\ndependencies=["safe"]\n');
  await symlink(join(directory, "real.toml"), join(directory, "pyproject.toml"));
  await assert.rejects(new PackageInspectorImpl().inspect(directory, "pip", false, control()), /manifest symlinks are denied/u);
});
