import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import type { PolicyDocument } from "@mac-operator/broker";
import { READ_SCOPES } from "./contracts.js";

export function r1FilesystemRoots(): PolicyDocument["filesystem_roots"] {
  return [
    { root_id: "owner-home", path: realpathSync(homedir()), metadata: true, content_read: true, write: false, deny_relative_paths: [] },
    { root_id: "system-metadata", path: "/", metadata: true, content_read: false, write: false, deny_relative_paths: [] }
  ];
}

export function buildR1TargetRules(
  principalId: string,
  filesystemRoots: PolicyDocument["filesystem_roots"],
  projectRoot: string
): PolicyDocument["target_rules"] {
  type ReadScope = (typeof READ_SCOPES)[number];
  type Target = PolicyDocument["target_rules"][number]["target"];
  const rules: PolicyDocument["target_rules"] = [];
  let sequence = 0;
  const allow = (scope: ReadScope, target: Target, references?: readonly string[]) => {
    rules.push({
      rule_id: `owner-r1-${sequence++}`,
      effect: "allow",
      principal_id: principalId,
      scope,
      target,
      ...(references === undefined ? {} : { target_constraint: { mode: "finite_set", references: [...references] } })
    });
  };
  for (const scope of ["mac.control.read", "mac.policy.explain", "mac.system.read", "mac.network.read"] as const) {
    allow(scope, { kind: "host", reference: "broker" });
  }
  for (const scope of ["mac.files.read", "mac.files.search", "mac.files.hash", "mac.project.read", "mac.storage.read"] as const) {
    for (const root of filesystemRoots) allow(scope, { kind: "path", reference: root.root_id });
  }
  for (const scope of ["mac.git.read", "mac.package.read"] as const) {
    allow(scope, { kind: "project", reference: projectRoot });
  }
  allow("mac.process.read", { kind: "process", reference: "all" });
  allow("mac.service.read", { kind: "service", reference: "system/com.apple.logd" });
  allow("mac.log.read", { kind: "log_source", reference: "system" });
  allow("mac.app.read", { kind: "app_set", reference: "all" });
  allow("mac.job.read", { kind: "job", reference: "owned" });
  allow("mac.docker.read", { kind: "docker_runtime", reference: "local" });
  allow("mac.docker.read", { kind: "docker_object", reference: "all" });
  return rules;
}
