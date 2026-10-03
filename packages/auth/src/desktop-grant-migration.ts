import { canonicalJson } from "@mac-operator/contracts";
import type { BrokerPolicy } from "@mac-operator/broker";
import type { RecordValue } from "./contracts.js";
import type { AuthStore } from "./store.js";
import type { GuiAccess } from "./w1-policy.js";

/** Select consent for a verified policy revision that preserves every signed GUI rule. */
export function desktopGrantsForUnchangedGuiPolicy(store: AuthStore, guiAccess: GuiAccess | undefined,
  principalId: string, prior: Pick<BrokerPolicy, "version" | "targetRules">,
  next: Pick<BrokerPolicy, "version" | "targetRules">): RecordValue<"desktop_grant">[] {
  if (guiAccess !== "desktop") return [];
  const guiScopes = new Set(["mac.app.control", "mac.ui.observe", "mac.ui.control"]);
  const guiRules = (policy: Pick<BrokerPolicy, "targetRules">) => policy.targetRules.filter(rule => guiScopes.has(rule.scope));
  if (canonicalJson(guiRules(prior)) !== canonicalJson(guiRules(next))) {
    throw new Error("Desktop consent cannot migrate across changed GUI authority");
  }
  return store.desktopGrants().filter(grant => !grant.revoked && grant.principalId === principalId &&
    grant.policyVersion === prior.version);
}
