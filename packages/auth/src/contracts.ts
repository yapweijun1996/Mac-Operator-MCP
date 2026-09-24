import { z } from "zod";

/** R1 is the owner-only bounded read profile; mutation and GUI-control scopes stay excluded. */
export const READ_SCOPES = [
  "mac.control.read", "mac.policy.explain", "mac.system.read", "mac.storage.read",
  "mac.process.read", "mac.log.read", "mac.network.read", "mac.service.read",
  "mac.package.read", "mac.files.read", "mac.files.search", "mac.files.hash",
  "mac.project.read", "mac.git.read", "mac.docker.read", "mac.app.read", "mac.job.read"
] as const;
export const D1_ADDITIONAL_SCOPES = ["mac.files.write", "mac.project.write", "mac.git.write", "mac.service.control", "mac.task.run", "mac.job.cancel"] as const;
export const W1_ADDITIONAL_SCOPES = ["mac.files.write", "mac.project.write", "mac.git.write", "mac.job.cancel"] as const;
export const W1_READ_SCOPES = READ_SCOPES.filter(scope => scope !== "mac.docker.read");
export const W1_SCOPES = [...W1_READ_SCOPES, ...W1_ADDITIONAL_SCOPES] as const;
export const D1_SCOPES = [...READ_SCOPES, ...D1_ADDITIONAL_SCOPES] as const;
export const OAUTH_SCOPES = D1_SCOPES;
export type GrantProfile = "r1" | "w1" | "d1";
export function scopesForGrantProfile(profile: GrantProfile): readonly string[] {
  return profile === "d1" ? D1_SCOPES : profile === "w1" ? W1_SCOPES : READ_SCOPES;
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

export const configSchema = z.object({
  version: z.literal(1),
  issuer: httpsUrl.refine(value => new URL(value).href === value && new URL(value).pathname === "/" && !new URL(value).search),
  resource: httpsUrl,
  issuerId: z.literal("mac-operator-auth"),
  principalId: id,
  keyId: id,
  port: z.number().int().min(1024).max(65535),
  allowedRedirectUris: z.array(httpsUrl).min(1).max(16),
  grantProfile: z.enum(["r1", "w1", "d1"]).default("r1")
}).strict().refine(value => value.resource === new URL("/mcp", value.issuer).href);
export type AuthConfig = z.infer<typeof configSchema>;

export const recordSchemas = {
  account: z.object({ username: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/u), salt: hash, passwordHash: hash, principalId: id }).strict(),
  client: z.object({ id, name: z.string().min(1).max(100), redirectUris: z.array(httpsUrl).min(1).max(8), expiresAt: time }).strict(),
  transaction: z.object({ clientId: id, redirectUri: httpsUrl, state: z.string().min(1).max(512), challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/u), scopes, expiresAt: time }).strict(),
  session: z.object({ transactionId: hash, csrf: hash, authenticated: z.boolean(), expiresAt: time }).strict(),
  approval_session: z.object({ requestId: z.string().regex(/^[A-Za-z0-9._:@/+-]{1,128}$/u), csrf: hash, authenticated: z.boolean(), expiresAt: time }).strict(),
  code: z.object({ clientId: id, redirectUri: httpsUrl, challenge: z.string(), scopes, grantId: id, principalId: id, expiresAt: time }).strict(),
  grant: z.object({ clientId: id, principalId: id, scopes, expiresAt: time, revoked: z.boolean() }).strict(),
  refresh: z.object({ clientId: id, grantId: id, expiresAt: time, consumed: z.boolean() }).strict()
};
export type Kind = keyof typeof recordSchemas;
export type RecordValue<K extends Kind> = z.infer<(typeof recordSchemas)[K]>;
