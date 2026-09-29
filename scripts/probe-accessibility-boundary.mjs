import { MacUiInspectorImpl } from "../packages/broker/dist/ui-inspector.js";

const TARGET_APP = "bundle:com.apple.finder";
const MAX_NODES = 50;

if (process.platform !== "darwin") {
  console.log(JSON.stringify({ schemaVersion: "0.1", mechanism: "macos-accessibility-boundary-v1", targetApp: TARGET_APP, status: "unsupported-platform", failClosed: true }));
  process.exitCode = 2;
} else {
  try {
    const result = await new MacUiInspectorImpl().observe(TARGET_APP, undefined, MAX_NODES, {
      timeoutMs: 15_000,
      shouldCancel: () => false
    });
    console.log(JSON.stringify({
      schemaVersion: "0.1",
      mechanism: "macos-accessibility-boundary-v1",
      targetApp: TARGET_APP,
      status: "observed",
      failClosed: true,
      nodeCount: result.nodes.length,
      truncated: result.truncated,
      warningCount: result.warnings.length
    }));
  } catch (error) {
    const permissionDenied = error instanceof Error && error.message === "Accessibility permission is not granted";
    console.log(JSON.stringify({
      schemaVersion: "0.1",
      mechanism: "macos-accessibility-boundary-v1",
      targetApp: TARGET_APP,
      status: permissionDenied ? "permission-denied" : "probe-failed",
      failClosed: permissionDenied
    }));
    if (!permissionDenied) process.exitCode = 1;
  }
}
