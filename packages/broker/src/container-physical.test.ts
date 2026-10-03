import assert from "node:assert/strict";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runPhysicalContainerValidation } from "./container-physical-validation.js";

test("actual Docker Engine isolates registered tasks, descendants and restart recovery", {
  skip: process.env.MOPS_REAL_CONTAINER !== "1", timeout: 120_000
}, async () => {
  const evidence = await runPhysicalContainerValidation({
    imageId: process.env.MOPS_CONTAINER_IMAGE_ID ?? "sha256:540f2d2753dc5674d05ec0cb7963a1fbb75b77f1fdeaa63c48a3825660aa01c4",
    ...(process.env.MOPS_CONTAINER_ENGINE_ID === undefined ? {} : { engineId: process.env.MOPS_CONTAINER_ENGINE_ID }),
    socketPath: join(homedir(), ".docker", "run", "docker.sock"),
    ...(process.env.MOPS_CONTAINER_EVIDENCE_PATH === undefined ? {} : { evidencePath: process.env.MOPS_CONTAINER_EVIDENCE_PATH })
  });
  assert.ok(evidence.checks.length >= 15); assert.ok(evidence.checks.every(check => check.status === "pass"));
  console.log(JSON.stringify(evidence));
});
