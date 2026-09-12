# Mac-Operator-MCP Security

Status: Locked architecture baseline
Version: 0.1
Source: KBID `mac-operator-mcp`, item `2ea82306-ed68-4ad2-b647-1a5937107320`

## Security objective

Grant broad Mac-operating capability without granting the model direct possession of credentials, unrestricted root, arbitrary public exposure, or silent privilege expansion.

## Core invariants

1. Local Broker is the final authorization authority; remote client claims are never sufficient by themselves.
2. Default deny for unknown tools, scopes, paths, apps, networks, and privileged operations.
3. No unrestricted root shell, no persistent root MCP server, and no model-visible sudo credential.
4. Keychain material, SSH private keys, browser password databases, cloud credentials, API tokens, signing keys, and similar secrets are deny zones by default.
5. A tool may report that a protected object exists without revealing its protected content.
6. Every child process gets an explicit cwd, minimal env allowlist, timeout, output cap, and applicable filesystem/network restrictions.
7. Destructive or privilege-changing operations require explicit policy plus precondition validation; model intent alone cannot authorize them.

## Identity and transport

Use authenticated HTTPS/OAuth or equivalent for the remote MCP Edge. Bind the Local Broker only to loopback or a protected Unix socket. Edge-to-Broker requests must be authenticated and replay-resistant. Tokens and scopes are short-lived or revocable where practical. Detailed principal, session, key lifecycle, replay persistence, concurrency, and version-negotiation decisions remain open and are tracked through ADRs.

## Filesystem policy

`FILESYSTEM_POLICY.md` is authoritative. Canonicalize paths before policy checks and defend against symlink, traversal, mount, and target-swap escapes. Deny rules win. Read and write scopes are independent. Generic tools never return secret bytes in results, diagnostics, audit, or errors.

## Command and process policy

Prefer structured task profiles. Generic process execution, if ever introduced, remains policy checked and depends on proven isolation. Block privilege escalation, credential-helper extraction, unrestricted Docker-socket access, arbitrary launchd persistence, and bypasses of Broker path or network policy.

## GUI and app policy

Accessibility and Automation permissions are powerful host capabilities. Scope app control independently by target application and action family. Protect sensitive dialogs, password prompts, security and privacy settings, credential surfaces, and secure input targets.

## Privileged helper

The helper exposes only versioned allowlisted operations with strict input schemas and local caller authentication. It does not accept arbitrary command strings. Every privileged result requires verification and audit evidence.

## Audit and privacy

Record actor or principal reference, tool, normalized target reference, policy decision, timestamps, duration, result class, and bounded redacted evidence. Never log tokens, secret contents, raw Keychain data, or sensitive environment values. Storage, integrity, retention, access, and outage behavior remain open decisions.

## Recovery and kill switches

Stopping or locking the Broker and revoking connector credentials remove remote execution authority according to the request and job lifecycle contract. Maintain emergency disables for mutating, GUI, and privileged capabilities. Failed mutation verification returns `VERIFICATION_FAILED`, never success.

## Explicitly excluded from v0.1

`run_shell`, `sudo_shell`, raw Keychain reads, SSH private-key reads, raw Docker socket proxying, arbitrary AppleScript/JXA execution, generic click-anywhere, credential autofill, Git push, force reset, destructive disk operations, and security-setting bypass.

## Security evidence rule

This document records requirements and locked decisions, not proof. Each released capability must map its requirements and threats to tasks, tests, exact-revision evidence, and a release gate in `VERIFICATION.md`.
