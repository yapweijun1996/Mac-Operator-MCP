const escapeHtml = (value: string): string => value.replace(/[&<>"']/gu, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);
import type { ApprovalBrowserPreview } from "./approval-browser-bridge.js";

function page(title: string, content: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title} · Mac Operator</title><link rel="stylesheet" href="/oauth/style.css"></head><body><main><div class="brand">MAC OPERATOR <span>PRIVATE ACCESS</span></div><h1>${title}</h1>${content}<footer>Your password stays with Mac Operator. ChatGPT receives a limited access token.</footer></main></body></html>`;
}

export function loginPage(csrf: string, failed = false): string {
  return page("Sign in to your Mac", `<p>Sign in to review this connection request.</p>${failed ? '<p role="alert" class="error">Unable to sign in. Check your credentials and try again.</p>' : ""}<form method="post" action="/oauth/login"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" maxlength="64" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="1024" required><button type="submit">Sign in</button></form>`);
}

export function expiredRequestPage(): string {
  return page("Start a new connection", "<p>This request has expired or has already been submitted.</p><p>Return to ChatGPT, open Mac Operator MCP, and start the sign-in flow again. Do not resubmit this page.</p>");
}

export function consentPage(csrf: string, clientName: string, redirect: string, system: boolean, developer = false): string {
  const boundary = developer
    ? "<li>Controlled developer operations may be requested; each mutation requires separate Broker owner approval.</li><li>No unrestricted shell, root access, credential access, arbitrary scripts, or GUI control is granted.</li>"
    : "<li>No file access, command execution or Mac control is granted.</li>";
  return page("Review this connection", `<p><strong>${escapeHtml(clientName)}</strong> is requesting access. This name is supplied by the client.</p><p class="destination">Return address: ${escapeHtml(redirect)}</p><ul><li>Check connection health</li><li>List available capabilities</li>${system ? "<li>Read system version, CPU, memory, uptime and load</li>" : ""}${boundary}</ul><form method="post" action="/oauth/consent"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><div class="actions"><button name="decision" value="allow">Allow connection</button><button name="decision" value="deny" class="secondary">Cancel</button></div></form>`);
}

export function approvalLoginPage(csrf: string, failed = false): string {
  return page("Approve a Mac operation", `<p>Sign in as the owner to review one bounded operation. Login alone never approves it.</p>${failed ? '<p role="alert" class="error">Unable to sign in. Check your credentials and try again.</p>' : ""}<form method="post" action="/approval/login"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" maxlength="64" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="1024" required><button type="submit">Continue</button></form>`);
}

export function approvalReviewPage(csrf: string, preview: ApprovalBrowserPreview, failed = false): string {
  const rows = ([
    ["Request", preview.requestId], ["Principal", preview.requestingPrincipalId], ["Tool", preview.tool],
    ["Contract", preview.contractVersion], ["Target", `${preview.targetKind}: ${preview.targetRef}`],
    ["Payload digest", preview.payloadDigest], ["Policy", preview.policyVersion],
    ["Approval class", preview.approvalClass], ["Unattended", String(preview.unattended)],
    ["Expires", new Date(preview.expiresAtMs).toISOString()]
  ] as Array<[string, string]>).map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd class="value">${escapeHtml(value)}</dd>`).join("");
  return page("Review Mac operation", `${failed ? '<p role="alert" class="error">Approval could not be completed. The request is still protected and may have expired.</p>' : ""}<p>Confirm only if this exact bounded operation is expected. The raw payload is not displayed or accepted from the browser.</p><dl>${rows}</dl><form method="post" action="/approval/decision"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><div class="actions"><button name="decision" value="allow">Approve operation</button><button name="decision" value="deny" class="secondary">Decline</button></div></form>`);
}

export function approvalResultPage(approved: boolean, approvalId?: string): string {
  return page(approved ? "Operation approved" : "Operation declined", approved
    ? `<p>The exact preview was approved and bound in the Broker.</p><p class="destination">Approval ID: ${escapeHtml(approvalId ?? "unavailable")}</p>`
    : "<p>No approval was issued. The pending preview remains protected and will expire automatically.");
}

export const stylesheet = `:root{font-family:system-ui,sans-serif;color:#192b35;background:#eef3f3;color-scheme:light}*{box-sizing:border-box}body{margin:0;padding:64px 20px}main{max-width:520px;margin:auto;padding:36px;background:#fff;border:1px solid #d3dfdf;border-radius:20px;box-shadow:0 12px 40px #173b3910}.brand{font-size:12px;font-weight:750;letter-spacing:2px;color:#21635a}.brand span{display:block;margin-top:6px;font-size:10px;color:#647570}h1{font-size:30px;line-height:1.2;margin:32px 0 16px}p,li{line-height:1.6}label{display:block;font-weight:600;margin:20px 0 8px}input:not([type=hidden]){width:100%;padding:12px;border:1px solid #a8b8b4;border-radius:8px;font:inherit}button{margin-top:24px;padding:13px 16px;border:1px solid #21635a;border-radius:8px;background:#21635a;color:white;font:inherit;font-weight:600;cursor:pointer}form>button{width:100%}.actions{display:flex;gap:12px;flex-wrap:wrap}.secondary{background:white;color:#21635a}input:focus-visible,button:focus-visible{outline:3px solid #e2ae45;outline-offset:3px}footer{margin-top:28px;padding-top:20px;border-top:1px solid #e1e7e5;color:#61736b;font-size:12px;line-height:1.6}.error{color:#a02222}.destination{font-size:12px;overflow-wrap:anywhere}.value{font-family:ui-monospace,monospace;overflow-wrap:anywhere}dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:10px 16px;padding:16px 0}dt{font-weight:650}dd{margin:0}@media(max-width:480px){body{padding:24px 12px}main{padding:24px}h1{font-size:26px}}`;
