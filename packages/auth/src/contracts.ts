import { z } from "zod";
import { READ_SCOPES, D1_SCOPES, G1_SCOPES, W1_SCOPES, D1_ADDITIONAL_SCOPES, G1_GUI_SCOPES,
  O1_SCOPES, V2_CODING_SCOPES, ownerTerminalOAuthContext } from "@mac-operator/contracts";
export { READ_SCOPES, D1_ADDITIONAL_SCOPES, W1_ADDITIONAL_SCOPES, W1_READ_SCOPES, W1_SCOPES,
  G1_GUI_SCOPES, G1_SCOPES, O1_SCOPES, V2_SCOPES, V2_CODING_SCOPES, D1_SCOPES } from "@mac-operator/contracts";
export const OAUTH_SCOPES = [...D1_SCOPES, ...G1_GUI_SCOPES, "mac.terminal.exec", "mac.agent.read", "mac.agent.run", "mac.audit.read"] as const;
export type GrantProfile = "r1" | "w1" | "g1" | "o1" | "d1" | "v2";
export function scopesForGrantProfile(profile: GrantProfile): readonly string[] {
  return profile === "v2" ? V2_CODING_SCOPES : profile === "o1" ? O1_SCOPES : profile === "d1" ? D1_SCOPES : profile === "g1" ? G1_SCOPES : profile === "w1" ? W1_SCOPES : READ_SCOPES;
}
export const READ_TOOLS = [
  "mac_app_list", "mac_capabilities", "mac_directory_tree", "mac_docker_inspect", "mac_docker_logs",
  "mac_docker_status", "mac_find_files", "mac_git_branch_list", "mac_git_diff", "mac_git_log",
  "mac_git_status", "mac_hash_file", "mac_health", "mac_job_status", "mac_list_directory", "mac_log_tail",
  "mac_network_status", "mac_package_inspect", "mac_policy_explain", "mac_process_inspect", "mac_process_list",
  "mac_project_discover", "mac_project_summary", "mac_read_file", "mac_recent_files", "mac_search_text",
  "mac_service_status", "mac_stat_path", "mac_storage_analysis", "mac_system_summary"
] as const;
export const W1_READ_TOOLS = READ_TOOLS.filter(tool => !tool.startsWith("mac_docker_"));
export const W1_TOOLS = [
  ...W1_READ_TOOLS,
  "mac_write_file_atomic", "mac_apply_patch", "mac_git_stage", "mac_git_commit", "mac_job_cancel"
] as const;
export const G1_GUI_TOOLS = ["mac_app_open", "mac_app_focus", "mac_ui_observe", "mac_ui_action", "mac_ui_type"] as const;
export const G1_TOOLS = [...W1_TOOLS, ...G1_GUI_TOOLS] as const;
export const O1_TOOLS = [...G1_TOOLS, "mac_terminal_exec", "mac_terminal_session"] as const;
export const V2_TOOLS = [...O1_TOOLS, "mac_task_run", "mac_git_worktree_create", "mac_git_worktree_list", "mac_git_worktree_remove",
  "mac_git_branch_create", "mac_codex_preflight", "mac_codex_run", "mac_test_run", "mac_build_run", "mac_pr_prepare", "mac_execution_audit"] as const;
export const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u);
const hash = z.string().regex(/^[a-f0-9]{64}$/u);
const time = z.number().int().nonnegative().safe();
const scopes = z.array(z.enum(OAUTH_SCOPES)).min(1).max(OAUTH_SCOPES.length).refine(value => new Set(value).size === value.length);
const httpsUrl = z.string().max(2048).refine(value => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.hash;
  } catch { return false; }
});
const redirectUrl = z.union([httpsUrl, z.string().max(2048).refine(value => {
  try {
    const url = new URL(value);
    // Native clients may use a pinned IPv4 loopback callback; registration still requires an exact allowlist match.
    return url.protocol === "http:" && url.hostname === "127.0.0.1" && Number(url.port) >= 1024 &&
      Number(url.port) <= 65535 && !url.username && !url.password && !value.includes("?") && !value.includes("#") && url.href === value;
  } catch { return false; }
})]);

export const configSchema = z.object({
  version: z.literal(1),
  issuer: httpsUrl.refine(value => new URL(value).href === value && ["/", "/terminal/"].includes(new URL(value).pathname) && !new URL(value).search),
  resource: httpsUrl,
  issuerId: z.literal("mac-operator-auth"),
  principalId: id,
  keyId: id,
  port: z.number().int().min(1024).max(65535),
  allowedRedirectUris: z.array(redirectUrl).min(1).max(16),
  grantProfile: z.enum(["r1", "w1", "g1", "o1", "d1", "v2"]).default("r1"),
  guiAccess: z.enum(["browsers", "desktop"]).optional(),
  ownerTerminalConnection: z.boolean().optional()
}).strict().refine(value => value.resource === new URL("mcp", value.issuer).href &&
  (new URL(value.issuer).pathname === "/" || (value.grantProfile === "o1" && value.ownerTerminalConnection !== true)) &&
  (value.ownerTerminalConnection !== true || value.grantProfile === "v2") &&
  (value.guiAccess !== "desktop" || ["g1", "o1", "v2"].includes(value.grantProfile)));
export type AuthConfig = z.infer<typeof configSchema>;
export function ownerTerminalAuthConfig(config: AuthConfig): AuthConfig {
  if (config.grantProfile !== "v2" || config.ownerTerminalConnection !== true) throw new Error("Separate owner terminal consent is not enabled");
  const { ownerTerminalConnection: _enabled, ...base } = config;
  const context = ownerTerminalOAuthContext(new URL(config.issuer));
  return configSchema.parse({ ...base, issuer: context.issuer.href, resource: context.resource.href, grantProfile: "o1" });
}

export const recordSchemas = {
  account: z.object({ username: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/u), salt: hash, passwordHash: hash, principalId: id }).strict(),
  client: z.object({ id, name: z.string().min(1).max(100), redirectUris: z.array(redirectUrl).min(1).max(8), expiresAt: time, resource: httpsUrl.optional() }).strict(),
  transaction: z.object({ clientId: id, redirectUri: redirectUrl, state: z.string().min(1).max(512), challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/u), scopes, expiresAt: time, resource: httpsUrl.optional() }).strict(),
  session: z.object({ transactionId: hash, csrf: hash, authenticated: z.boolean(), expiresAt: time }).strict(),
  approval_session: z.object({ guiGrantId: z.string().regex(/^gui-session:[a-f0-9-]{36}$/u).optional(), requestId: z.string().regex(/^[A-Za-z0-9._:@/+-]{1,128}$/u), csrf: hash, authenticated: z.boolean(), expiresAt: time }).strict(),
  browser_grant: z.object({ id: z.string().regex(/^gui-session:[a-f0-9-]{36}$/u), principalId: id, sessionId: id,
    appId: z.enum(["bundle:com.google.Chrome", "bundle:com.apple.Safari"]), policyVersion: id,
    consentRequestId: id, createdAt: time, revoked: z.boolean() }).strict(),
  desktop_grant: z.object({ id: z.string().regex(/^gui-session:[a-f0-9-]{36}$/u), principalId: id,
    policyVersion: id, consentRequestId: id, createdAt: time, revoked: z.boolean() }).strict(),
  code: z.object({ clientId: id, redirectUri: redirectUrl, challenge: z.string(), scopes, grantId: id, principalId: id, expiresAt: time, resource: httpsUrl.optional() }).strict(),
  grant: z.object({ clientId: id, principalId: id, scopes, expiresAt: time, revoked: z.boolean(), resource: httpsUrl.optional() }).strict(),
  refresh: z.object({ clientId: id, grantId: id, expiresAt: time, consumed: z.boolean() }).strict()
};
export type Kind = keyof typeof recordSchemas;
export type RecordValue<K extends Kind> = z.infer<(typeof recordSchemas)[K]>;
