#!/usr/bin/env node
import { resolve, join } from "node:path";
import { loadEdgeServiceStartupConfig } from "../packages/edge/dist/service-startup.js";
import { assertTlsCertificateAuthority, loadProtectedTlsCertificate } from "../packages/edge/dist/tls-material.js";

const root = resolve(process.argv[2] ?? "");

try {
  if (process.argv.length !== 3 || !root || root === "/" || root.includes("\0") || resolve(root) !== root) {
    throw new Error("expected one canonical personal deployment root");
  }
  const config = await loadEdgeServiceStartupConfig(join(root, "personal/edge-service.json"));
  if (config.issuerId !== "mac-operator-auth") throw new Error("snapshot is not an owner OAuth deployment");
  if (!config.oauthStatusLocalUrl || !config.oauthStatusLocalServerName || !config.oauthStatusLocalCaPath) {
    throw new Error("snapshot does not bind the loopback OAuth status channel");
  }
  const ca = await loadProtectedTlsCertificate(config.oauthStatusLocalCaPath, "OAuth status loopback CA");
  try {
    assertTlsCertificateAuthority(ca);
  } finally {
    ca.fill(0);
  }
  console.log(`Personal snapshot preflight passed: sourceRevision=${config.sourceRevision} loopbackStatus=bound`);
} catch (error) {
  const message = error instanceof Error ? error.message.slice(0, 240) : "unknown preflight failure";
  console.error(`Personal snapshot preflight failed: ${message}`);
  process.exitCode = 1;
}
