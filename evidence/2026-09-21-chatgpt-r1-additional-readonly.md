# ChatGPT R1 Additional Read-Only Acceptance

Date: 2026-09-21
Profile: `R1` (`Mac Operator MCP R1 Read Only`)
Client surface: ChatGPT composer using the connected primary account
Endpoint: `https://mac.yapweijun1996.com/mcp`

## Visible results

The same live ChatGPT session completed the following additional R1 calls:

### `mac_app_list`

- Input: `running_only=true`, `include_installed=false`
- Result: 60 running application entries; complete and not truncated
- Installed-application enumeration was excluded
- No app launch, focus, or modification was requested

### `mac_project_summary`

- Input: the exact project root, `include_tree=true`, `tree_depth=1`
- Result: bounded VCS/manifest/language metadata and a shallow directory tree
- Result was verified and not truncated
- No file contents or secrets were exposed

### `mac_git_branch_list`

- Input: the exact project root, `include_remote=false`
- Result: current local `main` branch with `origin/main` upstream
- Remote branch enumeration was excluded
- Result was verified and complete

### `mac_git_log`

- Input: the exact project root, `limit=5`, `ref=HEAD`
- Result: bounded commit metadata with malformed records omitted
- No Git state was modified

## Service evidence

PM2 recorded fresh authenticated transport sequences for these completed calls:

- `/token`: HTTP 200
- `/oauth/status`: HTTP 200
- MCP `tools/call`: HTTP 200
- MCP protocol: `2026-07-28`

The subsequent `mac_package_inspect` prompt encountered ChatGPT's expired
connection screen before a tool result. It is not counted as a successful
acceptance and requires the owner to complete the visible OAuth sign-in before
testing again. No credentials or tokens are recorded here.
