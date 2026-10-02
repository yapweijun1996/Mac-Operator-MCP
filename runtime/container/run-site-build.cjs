"use strict";
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const root = "/workspace/site";
const runtime = "/opt/mac-operator/site/node_modules";
const manifest = JSON.parse(fs.readFileSync(`${root}/package.json`, "utf8"));
if (manifest.scripts?.build !== "tsc -b && vite build") throw new Error("Approved build script changed");
// Keep the pinned packages immutable while Vite writes its bounded task-local cache.
fs.mkdirSync(`${root}/node_modules`);
for (const name of fs.readdirSync(runtime)) {
  if (name === ".vite-temp" || name === ".vite") continue;
  fs.symlinkSync(`${runtime}/${name}`, `${root}/node_modules/${name}`);
}
for (const args of [[`${runtime}/typescript/bin/tsc`, "-b"], [`${runtime}/vite/bin/vite.js`, "build"]]) {
  const result = spawnSync("/usr/local/bin/node", args, {
    cwd: root, env: { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/home/agent", TMPDIR: "/tmp", LANG: "C.UTF-8" },
    stdio: "inherit", timeout: 120_000, shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
