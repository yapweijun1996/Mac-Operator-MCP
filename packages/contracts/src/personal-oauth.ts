/** Personal OAuth profiles are shared by Auth consent and Edge discovery. */
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
export const G1_GUI_SCOPES = ["mac.app.control", "mac.ui.observe", "mac.ui.control"] as const;
export const G1_SCOPES = [...W1_SCOPES, ...G1_GUI_SCOPES] as const;
export const O1_SCOPES = [...G1_SCOPES, "mac.terminal.exec"] as const;
export const V2_SCOPES = [...O1_SCOPES, "mac.task.run", "mac.agent.read", "mac.agent.run", "mac.audit.read"] as const;
export const V2_CODING_SCOPES = V2_SCOPES.filter(scope => scope !== "mac.terminal.exec");
export const D1_SCOPES = [...READ_SCOPES, ...D1_ADDITIONAL_SCOPES] as const;

export const OWNER_TERMINAL_PREFIX = "/terminal";
export function ownerTerminalOAuthContext(primaryIssuer: URL): { issuer: URL; resource: URL } {
  if (primaryIssuer.protocol !== "https:" || primaryIssuer.pathname !== "/" || primaryIssuer.search ||
      primaryIssuer.hash || primaryIssuer.username || primaryIssuer.password) throw new Error("Root-bound personal issuer required");
  return { issuer: new URL(`${OWNER_TERMINAL_PREFIX}/`, primaryIssuer),
    resource: new URL(`${OWNER_TERMINAL_PREFIX}/mcp`, primaryIssuer) };
}
