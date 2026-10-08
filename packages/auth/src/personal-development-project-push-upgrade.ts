import { canonicalJson } from "@mac-operator/contracts";
import type { SignedPolicyBundle } from "@mac-operator/broker";
import { migratePersonalDevelopmentConfig } from "./personal-development-project-add-upgrade.js";
import type { PersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";

const PUSH_SCOPE = "mac.git.push";

/**
 * Offline opt-in that removes projects from `gitPushDeniedProjects`, so the signed policy gains exactly one `mac.git.push`
 * project rule per released project. The project list and every other runtime setting must stay unchanged, and no other
 * rule, tool, scope, filesystem root or kill switch may differ. Keep a complete stopped-state backup for rollback.
 */
export async function upgradePersonalDevelopmentProjectPush(root: string, packageRoot: string, sourceRevision: string,
  nextRuntimeConfigPath: string): Promise<{ revision: number; pushEnabledProjects: string[]; backup: string }> {
  const result = await migratePersonalDevelopmentConfig(root, packageRoot, sourceRevision, nextRuntimeConfigPath, {
    name: "development_project_push", assertRuntime: assertRuntimePushReleaseOnly, assertPolicy: assertOnlyPushRulesAdded });
  return { revision: result.revision, pushEnabledProjects: result.changedProjects, backup: result.backup };
}

/** The replacement may only shrink the push denial list; projects, profiles, engine and entries stay as installed. */
export function assertRuntimePushReleaseOnly(installed: PersonalDevelopmentRuntimeConfig, next: PersonalDevelopmentRuntimeConfig): string[] {
  const { gitPushDeniedProjects: deniedBefore, ...restBefore } = installed;
  const { gitPushDeniedProjects: deniedAfter, ...restAfter } = next;
  if (canonicalJson(restBefore) !== canonicalJson(restAfter)) throw new Error("Push release would change runtime configuration beyond the denial list");
  const released = deniedBefore.filter(project => !deniedAfter.includes(project));
  if (released.length === 0 || deniedAfter.some(project => !deniedBefore.includes(project)) ||
      released.length !== deniedBefore.length - deniedAfter.length) throw new Error("Push release must only remove projects from the denial list");
  return released;
}

type PolicyPayload = SignedPolicyBundle["payload"];

/** The new document may differ only by project-scoped `mac.git.push` allow rules for the released projects. */
export function assertOnlyPushRulesAdded(before: PolicyPayload, after: PolicyPayload, _installed: PersonalDevelopmentRuntimeConfig,
  _next: PersonalDevelopmentRuntimeConfig, released: string[]): void {
  const { revision: _a, issued_at_ms: _b, target_rules: rulesBefore, ...restBefore } = before;
  const { revision: _c, issued_at_ms: _d, target_rules: rulesAfter, ...restAfter } = after;
  if (canonicalJson(restBefore) !== canonicalJson(restAfter)) throw new Error("Push release would change authority other than push rules");
  const content = (rule: PolicyPayload["target_rules"][number]): string => { const { rule_id: _id, ...rest } = rule; return canonicalJson(rest); };
  const counts = new Map<string, number>();
  for (const rule of rulesBefore) counts.set(content(rule), (counts.get(content(rule)) ?? 0) + 1);
  const added: PolicyPayload["target_rules"] = [];
  for (const rule of rulesAfter) {
    const remaining = counts.get(content(rule)) ?? 0;
    if (remaining > 0) counts.set(content(rule), remaining - 1); else added.push(rule);
  }
  if ([...counts.values()].some(remaining => remaining !== 0)) throw new Error("Push release would remove or change existing target rules");
  const expected = new Set(released);
  if (added.length !== released.length || added.some(rule => rule.effect !== "allow" || rule.scope !== PUSH_SCOPE || rule.target_constraint !== undefined ||
      rule.target.kind !== "project" || !expected.delete(rule.target.reference)) || expected.size !== 0) {
    throw new Error("Push release must add exactly one push rule per released project");
  }
}
