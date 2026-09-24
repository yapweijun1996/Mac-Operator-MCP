import assert from "node:assert/strict";
import test from "node:test";
import { validateMacOsHostReadinessEvidence } from "./host-readiness.js";

function evidence(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Date.now();
  return {
    schemaVersion: "0.1",
    mechanism: "macos-host-readiness-v1",
    status: "ready",
    failClosed: true,
    capturedAtMs: now,
    readyForRelease: true,
    readyForGui: true,
    persistentServiceVerified: true,
    host: { platform: process.platform, arch: process.arch, ownerUid: process.getuid?.() ?? 0 },
    signing: { status: "read", validIdentityCount: 1, developerIdCount: 1, ready: true },
    gatekeeper: { status: "read", enabled: true },
    accessibility: { status: "observed", failClosed: true },
    launchd: [{ label: "gui/501/com.mac-operator.edge", status: "present", present: true }],
    ...overrides
  };
}

test("host readiness validates release and GUI evidence for the current host", () => {
  const value = validateMacOsHostReadinessEvidence(evidence(), {
    requireRelease: true,
    requireGui: true
  });
  assert.equal(value.readyForRelease, true);
  assert.equal(value.readyForGui, true);
});

test("host readiness rejects stale, cross-host, and inconsistent evidence", () => {
  const now = Date.now();
  assert.throws(
    () => validateMacOsHostReadinessEvidence(evidence({ capturedAtMs: now - 10 * 60 * 1_000 - 1 }), { nowMs: now }),
    /stale/u
  );
  assert.throws(
    () => validateMacOsHostReadinessEvidence(evidence({ host: { platform: process.platform, arch: process.arch, ownerUid: 99999 } })),
    /another host/u
  );
  assert.throws(
    () => validateMacOsHostReadinessEvidence(evidence({ readyForGui: false }), { requireGui: true }),
    /GUI evidence is not ready/u
  );
  assert.throws(
    () => validateMacOsHostReadinessEvidence(evidence({ readyForRelease: false }), { requireRelease: true }),
    /release evidence is not ready/u
  );
});
