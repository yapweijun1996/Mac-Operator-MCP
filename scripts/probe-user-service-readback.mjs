import { readLaunchdJobReadback } from "../packages/broker/dist/launchd-readback.js";

const uid = typeof process.getuid === "function" ? process.getuid() : -1;
if (!Number.isSafeInteger(uid) || uid < 1) {
  throw new Error("A non-root macOS user uid is required");
}

// This is a fixed, read-only probe for the existing owner-domain health agent.
// It never accepts a service id, executable, plist path, or command from input.
const serviceId = `gui/${uid}/com.yapweijun.pm2-health`;
const readback = await readLaunchdJobReadback(serviceId);
console.log(JSON.stringify({
  schemaVersion: "0.1",
  serviceId: readback.serviceId,
  domain: readback.domain,
  label: readback.label,
  type: readback.type,
  state: readback.state,
  pid: readback.pid,
  program: readback.program,
  arguments: readback.arguments,
  plistPath: readback.plistPath,
  lastExitCode: readback.lastExitCode,
  truncated: readback.truncated
}));
