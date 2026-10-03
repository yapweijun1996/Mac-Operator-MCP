import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { installGuiApplication, validateGuiApplication } from "../packages/broker/scripts/install-gui-app.mjs";

const supported = process.platform === "darwin";
const run = promisify(execFile);
const options = {
  cwd: resolve("."),
  env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" },
  shell: false,
  timeout: 30_000,
  maxBuffer: 16_384
};
let fixtures;
let renameExecutable;

before(async () => {
  if (!supported) return;
  fixtures = await mkdtemp("/private/tmp/mop-gui-installer-");
  renameExecutable = join(fixtures, "gui_install");
  await run("/usr/bin/clang", ["-Wall", "-Wextra", "-Werror",
    resolve("packages/broker/native/gui_install.c"), "-o", renameExecutable], options);
});
after(async () => {
  if (fixtures) await rm(fixtures, { recursive: true, force: true });
});

async function fixture(t, identifier = "dev.macoperator.personal.gui") {
  const directory = await mkdtemp(join(fixtures, "case-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sourceApp = join(directory, "release", "Mac Operator GUI.app");
  await mkdir(join(sourceApp, "Contents", "MacOS"), { recursive: true });
  await mkdir(join(sourceApp, "Contents", "Resources"));
  await writeFile(join(sourceApp, "Contents", "Resources", "release-marker"), "original release\n");
  await copyFile("/usr/bin/true", join(sourceApp, "Contents", "MacOS", "gui_vision"));
  await writeFile(join(sourceApp, "Contents", "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>${identifier}</string>
<key>CFBundleExecutable</key><string>gui_vision</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>Mac Operator GUI</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>
`);
  await run("/usr/bin/codesign", ["--force", "--sign", "-", sourceApp], options);
  return { sourceApp, applicationsDirectory: join(directory, "Applications"), renameExecutable };
}

test("deployment installs a valid signed GUI bundle when absent", { skip: !supported }, async (t) => {
  const input = await fixture(t);
  const result = await installGuiApplication(input);
  assert.equal(result.action, "installed");
  await validateGuiApplication(result.path);
  assert.deepEqual(await readdir(input.applicationsDirectory), ["Mac Operator GUI.app"]);
  assert.deepEqual(await readFile(join(result.path, "Contents", "MacOS", "gui_vision")),
    await readFile(join(input.sourceApp, "Contents", "MacOS", "gui_vision")));
});

test("repeat deployment preserves the existing GUI identity byte-for-byte", { skip: !supported }, async (t) => {
  const input = await fixture(t);
  const installed = await installGuiApplication(input);
  const executable = join(installed.path, "Contents", "MacOS", "gui_vision");
  const beforeBytes = await readFile(executable);
  const beforeStat = await stat(executable);
  // A fresh release can differ; preserving the current app must not depend on
  // equality with the release artifact or rebuild the owner's ad-hoc identity.
  await writeFile(join(input.sourceApp, "Contents", "Resources", "release-marker"), "new release\n");
  await run("/usr/bin/codesign", ["--force", "--sign", "-", input.sourceApp], options);
  const result = await installGuiApplication(input);
  assert.equal(result.action, "preserved");
  assert.deepEqual(await readFile(executable), beforeBytes);
  assert.equal((await stat(executable)).ino, beforeStat.ino);
  assert.equal((await stat(executable)).mtimeMs, beforeStat.mtimeMs);
  assert.equal(await readFile(join(installed.path, "Contents", "Resources", "release-marker"), "utf8"), "original release\n");
});

test("a valid installed app is preserved even when the release source is absent", { skip: !supported }, async (t) => {
  const input = await fixture(t);
  await installGuiApplication(input);
  await rm(input.sourceApp, { recursive: true });
  assert.equal((await installGuiApplication(input)).action, "preserved");
});

test("missing release GUI artifact fails without publishing a partial app", { skip: !supported }, async (t) => {
  const input = await fixture(t);
  await rm(input.sourceApp, { recursive: true });
  await assert.rejects(installGuiApplication(input), /application directory/u);
  assert.deepEqual(await readdir(input.applicationsDirectory), []);
});

test("wrong GUI bundle identifier fails before installation", { skip: !supported }, async (t) => {
  const input = await fixture(t, "dev.other.application");
  await assert.rejects(installGuiApplication(input), /CFBundleIdentifier is invalid/u);
  assert.deepEqual(await readdir(input.applicationsDirectory), []);
});

test("invalid GUI code signature fails before installation", { skip: !supported }, async (t) => {
  const input = await fixture(t);
  await writeFile(join(input.sourceApp, "Contents", "Resources", "release-marker"), "tampered\n");
  await assert.rejects(installGuiApplication(input), /codesign/u);
  assert.deepEqual(await readdir(input.applicationsDirectory), []);
});

test("an invalid existing GUI bundle is diagnosed and never replaced", { skip: !supported }, async (t) => {
  const input = await fixture(t);
  const installed = await installGuiApplication(input);
  const marker = join(installed.path, "Contents", "do-not-replace");
  await writeFile(marker, "existing invalid installation\n");
  await assert.rejects(installGuiApplication(input));
  assert.equal(await readFile(marker, "utf8"), "existing invalid installation\n");
  assert.deepEqual(await readdir(input.applicationsDirectory), ["Mac Operator GUI.app"]);
});

test("destination and Applications symlinks fail closed", { skip: !supported }, async (t) => {
  const input = await fixture(t);
  await mkdir(input.applicationsDirectory, { mode: 0o700 });
  const destination = join(input.applicationsDirectory, "Mac Operator GUI.app");
  await symlink(input.sourceApp, destination);
  await assert.rejects(installGuiApplication(input), /application directory/u);
  await validateGuiApplication(input.sourceApp);
  await rm(input.applicationsDirectory, { recursive: true });
  await symlink(join(input.sourceApp, "Contents"), input.applicationsDirectory);
  await assert.rejects(installGuiApplication(input), /owner-controlled/u);
});

test("concurrent deployments publish one GUI identity and preserve the winner", { skip: !supported }, async (t) => {
  const input = await fixture(t);
  const results = await Promise.all([installGuiApplication(input), installGuiApplication(input)]);
  assert.deepEqual(results.map((result) => result.action).sort(), ["installed", "preserved"]);
  assert.deepEqual(await readdir(input.applicationsDirectory), ["Mac Operator GUI.app"]);
  await validateGuiApplication(results[0].path);
});

test("atomic publication never nests a staged app inside an existing destination", { skip: !supported }, async (t) => {
  const input = await fixture(t);
  const installed = await installGuiApplication(input);
  await assert.rejects(run(renameExecutable, [input.sourceApp, installed.path], options), (error) => error.code === 73);
  await validateGuiApplication(input.sourceApp);
  await validateGuiApplication(installed.path);
  assert.deepEqual(await readdir(installed.path), ["Contents"]);
});
