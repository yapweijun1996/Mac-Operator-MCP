# ChatGPT R1 Representative Read-Only Acceptance

Date: 2026-09-21
Profile: `R1` (`Mac Operator MCP R1 Read Only`)
Client surface: ChatGPT composer using the connected primary account
Endpoint: `https://mac.yapweijun1996.com/mcp`

## Visible results

The following representative R1 calls completed in ChatGPT with bounded
read-only inputs and outputs:

### `mac_process_list`

- Input: `limit=10`, `sort=pid`
- Result: 10 PID-sorted process rows with bounded process, executable, CPU,
  memory, and numeric-owner metadata
- Result was truncated at the requested limit
- No command arguments or environment values were requested

### `mac_network_status`

- Input: `include_listeners=false`
- Result: bounded local interface metadata
- Listeners were excluded
- Active probing was not performed
- Result was complete and not truncated

### `mac_project_discover`

- Input: the project root, `types=["node"]`, `max_results=10`
- Result: five Node project markers, including the root and package markers
- No file contents or secrets were read
- Result was complete and not truncated

### `mac_git_status`

- Input: the exact project root, `include_untracked=false`
- Result: branch/status metadata for `main`, with a dirty working tree, zero
  staged paths, 15 unstaged paths, zero conflicts, and untracked paths
  excluded
- No staging, commit, reset, or file modification was requested

### `mac_docker_status`

- Input: `include_images=false`, `include_storage=false`
- Result: Docker daemon available, version `29.1.3`, local context
- No images, storage, or dynamic Docker objects were enumerated
- Result was verified and complete

## Service evidence

For each of the five calls, fresh PM2 logs recorded the corresponding
authenticated transport sequence without recording tokens or credentials:

- `/token`: HTTP 200
- `/oauth/status`: HTTP 200
- MCP `tools/call`: HTTP 200
- MCP protocol: `2026-07-28`

No mutation, GUI action, privileged action, active network probe, Docker state
change, Git write, or system-content read was requested. Conclusion: the R1
ChatGPT path is operational for the representative process, network, project,
Git, and Docker read-only contracts.
