"use strict";

const path = require("node:path");
const { pathToFileURL } = require("node:url");
const sea = require("node:sea");

if (!sea.isSea()) {
  process.stderr.write("Privileged helper requires its single-executable bundle.\n");
  process.exitCode = 1;
} else {
  const runtimeEntry = path.resolve(
    __dirname,
    "../Resources/runtime/packages/broker/dist/privileged-helper-main.js"
  );
  import(pathToFileURL(runtimeEntry).href)
    .then((runtime) => runtime.runEmbeddedPrivilegedHelper())
    .catch(() => {
      process.stderr.write("Privileged helper startup failed closed.\n");
      process.exitCode = 1;
    });
}
