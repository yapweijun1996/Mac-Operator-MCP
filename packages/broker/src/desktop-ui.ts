import { BrokerError, canonicalJson, type Scope } from "@mac-operator/contracts";
import type { BrokerPolicy } from "./policy.js";

export const DESKTOP_APP_ID = "bundle:dev.macoperator.desktop";
export const DESKTOP_IDENTITY_PATTERN = /^desktop:[1-9][0-9]{0,9}:[a-f0-9]{64}:[1-9][0-9]{0,9}:[1-9][0-9]{0,15}$/u;

/** The native display route has no caller-defined policy input. */
export function desktopDeniedApplications(policy: BrokerPolicy, principalId: string, scopes: readonly Scope[]): readonly string[] {
  if (!scopes.length || scopes.some(scope => !["mac.ui.observe", "mac.ui.control"].includes(scope) ||
      !policy.targetRules.some(rule => rule.effect === "allow" && rule.principalId === principalId && rule.scope === scope &&
        rule.target.kind === "app_window" && rule.target.reference === "desktop" && rule.targetConstraint === undefined))) {
    throw new BrokerError("POLICY_DENIED", "Desktop surfaces require an explicit signed desktop application domain");
  }
  const denied = new Set<string>();
  for (const rule of policy.targetRules) {
    if (rule.effect !== "deny" || rule.principalId !== principalId ||
        !["mac.app.control", "mac.ui.observe", "mac.ui.control"].includes(rule.scope) ||
        !["app", "app_window"].includes(rule.target.kind)) continue;
    if (rule.target.reference === "desktop") throw new BrokerError("POLICY_DENIED", "Desktop access is denied by application policy");
    for (const reference of rule.targetConstraint?.references ?? [rule.target.reference]) {
      const prefix = rule.target.kind === "app" ? "bundle:" : "window:bundle:";
      if (reference.startsWith(prefix)) denied.add(reference.slice(prefix.length).toLowerCase());
    }
  }
  const applications = [...denied].sort();
  desktopManifest(applications);
  return applications;
}

export function desktopManifest(applications: readonly string[] | undefined): string {
  if (applications === undefined) throw new BrokerError("POLICY_DENIED", "Desktop observation requires Broker-owned application policy");
  const manifest = canonicalJson(applications);
  if (applications.length > 128 || applications.some(value => !/^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u.test(value)) ||
      Buffer.byteLength(manifest, "utf8") > 4096) {
    throw new BrokerError("POLICY_DENIED", "Desktop application policy exceeds the native transport boundary");
  }
  return manifest;
}

export function assertGuiIdentityContext(appId: string, identity: string | undefined): void {
  if ((appId === DESKTOP_APP_ID) !== (identity !== undefined && DESKTOP_IDENTITY_PATTERN.test(identity))) {
    throw new BrokerError("VERIFICATION_FAILED", "Native GUI identity does not match the requested application surface");
  }
}

export function desktopDisplayHint(identity: string): string {
  if (!DESKTOP_IDENTITY_PATTERN.test(identity)) throw new BrokerError("VERIFICATION_FAILED", "Desktop display identity is malformed");
  return `display:${identity.split(":")[1]}`;
}
