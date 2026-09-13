import assert from "node:assert/strict";
import test from "node:test";
import { launchdReadback, normalizeLaunchdServiceConfig, renderLaunchdPlist } from "./launchd.js";

const valid = {
  label: "com.mac-operator.broker",
  program: "/opt/mac-operator/bin/node",
  programArguments: ["/opt/mac-operator/bin/node", "/opt/mac-operator/broker/service-entrypoint.js"],
  workingDirectory: "/opt/mac-operator",
  stdoutPath: "/var/log/mac-operator/broker.out.log",
  stderrPath: "/var/log/mac-operator/broker.err.log"
} as const;

test("launchd renderer emits a bounded unprivileged no-shell plist", () => {
  const plist = renderLaunchdPlist(valid);
  assert.match(plist, /<key>ProgramArguments<\/key>/u);
  assert.match(plist, /<key>ProcessType<\/key><string>Background<\/string>/u);
  assert.match(plist, /<key>AbandonProcessGroup<\/key><false\/>/u);
  assert.doesNotMatch(plist, /EnvironmentVariables|UserName|Shell/u);
  assert.deepEqual(launchdReadback(valid), {
    label: "com.mac-operator.broker",
    program: "/opt/mac-operator/bin/node",
    programArguments: ["/opt/mac-operator/bin/node", "/opt/mac-operator/broker/service-entrypoint.js"],
    workingDirectory: "/opt/mac-operator",
    stdoutPath: "/var/log/mac-operator/broker.out.log",
    stderrPath: "/var/log/mac-operator/broker.err.log",
    runsAsUnprivilegedUser: true,
    usesEnvironmentVariables: false,
    usesShell: false,
    runAtLoad: true,
    keepAlive: true,
    throttleIntervalSeconds: 5
  });
});

test("launchd renderer escapes XML and rejects unsafe command boundaries", () => {
  const escaped = renderLaunchdPlist({
    ...valid,
    programArguments: [valid.program, "--label=a&b<safe>"]
  });
  assert.match(escaped, /a&amp;b&lt;safe&gt;/u);
  assert.throws(() => normalizeLaunchdServiceConfig({ ...valid, program: "node" }), /canonical absolute/u);
  assert.throws(() => normalizeLaunchdServiceConfig({ ...valid, programArguments: ["/bin/sh", "-c", "unsafe"] }), /begin with/u);
  assert.throws(() => normalizeLaunchdServiceConfig({ ...valid, workingDirectory: "/tmp/../tmp" }), /canonical absolute/u);
  assert.throws(() => normalizeLaunchdServiceConfig({ ...valid, stdoutPath: valid.stderrPath }), /must differ/u);
});
