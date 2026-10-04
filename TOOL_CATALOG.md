# Mac-Operator-MCP Tool Catalog

Status: Locked planned surface
Version: 0.1
Source: KBID `mac-operator-mcp`, item `65554efe-6a0a-404c-af6a-7670777944b4`

## Control and Broker introspection

1. [`mac_capabilities`](tool-contracts/mac_capabilities.json) — enabled capabilities, scopes, and host permission state.
2. [`mac_health`](tool-contracts/mac_health.json) — bounded Local Broker health and version (Edge and helper status are not reported; see `mac_capabilities`).
3. [`mac_policy_explain`](tool-contracts/mac_policy_explain.json) — non-executing policy decision for a proposed action.

## L0 Observe

4. [`mac_system_summary`](tool-contracts/mac_system_summary.json) — macOS, CPU, memory, uptime, and load summary.
5. [`mac_storage_analysis`](tool-contracts/mac_storage_analysis.json) — capacity and bounded storage-consumer analysis.
6. [`mac_process_list`](tool-contracts/mac_process_list.json) — bounded process inventory.
7. [`mac_process_inspect`](tool-contracts/mac_process_inspect.json) — safe details for one normalized process.
8. [`mac_log_tail`](tool-contracts/mac_log_tail.json) — bounded sanitized output from an allowlisted log source.
9. [`mac_network_status`](tool-contracts/mac_network_status.json) — interfaces, listeners, and connectivity metadata.
10. [`mac_service_status`](tool-contracts/mac_service_status.json) — approved service state inspection.

## L1 Files and Projects

11. [`mac_list_directory`](tool-contracts/mac_list_directory.json) — bounded directory listing.
12. [`mac_stat_path`](tool-contracts/mac_stat_path.json) — safe metadata for one canonical path.
13. [`mac_find_files`](tool-contracts/mac_find_files.json) — bounded filename/path discovery.
14. [`mac_search_text`](tool-contracts/mac_search_text.json) — bounded content search excluding secret zones.
15. [`mac_read_file`](tool-contracts/mac_read_file.json) — bounded file read with secret denial.
16. [`mac_hash_file`](tool-contracts/mac_hash_file.json) — checksum without returning content.
17. [`mac_recent_files`](tool-contracts/mac_recent_files.json) — recent allowed files using metadata only.
18. [`mac_project_discover`](tool-contracts/mac_project_discover.json) — project discovery under approved roots.
19. [`mac_project_summary`](tool-contracts/mac_project_summary.json) — safe structure and manifest summary.
20. [`mac_directory_tree`](tool-contracts/mac_directory_tree.json) — depth and entry-bounded tree.

## L2 Developer Read and Execute

21. [`mac_git_status`](tool-contracts/mac_git_status.json) — read-only repository status.
22. [`mac_git_diff`](tool-contracts/mac_git_diff.json) — bounded sanitized diff.
23. [`mac_git_log`](tool-contracts/mac_git_log.json) — bounded commit history.
24. [`mac_git_branch_list`](tool-contracts/mac_git_branch_list.json) — local and locally-known remote branch metadata.
25. [`mac_task_run`](tool-contracts/mac_task_run.json) — approved named task profile only.
26. [`mac_job_status`](tool-contracts/mac_job_status.json) — bounded status/output for a Broker-owned job.
27. [`mac_job_cancel`](tool-contracts/mac_job_cancel.json) — cancel a Broker-owned cancellable job.
28. [`mac_package_inspect`](tool-contracts/mac_package_inspect.json) — package manifest and lock inspection.
29. [`mac_docker_status`](tool-contracts/mac_docker_status.json) — bounded Docker runtime and storage status.
30. [`mac_docker_inspect`](tool-contracts/mac_docker_inspect.json) — sanitized metadata for one Docker object.
31. [`mac_docker_logs`](tool-contracts/mac_docker_logs.json) — bounded sanitized container logs.

## L2 Controlled Writes

32. [`mac_apply_patch`](tool-contracts/mac_apply_patch.json) — bounded patch under an approved project root.
33. [`mac_write_file_atomic`](tool-contracts/mac_write_file_atomic.json) — atomic file create or replace under an approved root.
34. [`mac_git_stage`](tool-contracts/mac_git_stage.json) — stage explicit approved paths only.
35. [`mac_git_commit`](tool-contracts/mac_git_commit.json) — local commit from preconditioned staged content.

## L3/L4 Apps and GUI

36. [`mac_app_list`](tool-contracts/mac_app_list.json) — installed/running app inventory.
37. [`mac_app_open`](tool-contracts/mac_app_open.json) — launch an allowlisted app or approved target.
38. [`mac_app_focus`](tool-contracts/mac_app_focus.json) — focus an approved app/window.
39. [`mac_ui_observe`](tool-contracts/mac_ui_observe.json) — bounded application snapshot or explicitly delegated desktop display screenshot.
40. [`mac_ui_action`](tool-contracts/mac_ui_action.json) — one supported action on a fresh approved element or display/window visual reference.
41. [`mac_ui_type`](tool-contracts/mac_ui_type.json) — bounded input to an approved non-secure target.
42. [`mac_service_control`](tool-contracts/mac_service_control.json) — owner-domain LaunchAgent lifecycle with fixed actions and readback.

## L5 Privileged

43. [`mac_priv_service_control`](tool-contracts/mac_priv_service_control.json) — allowlisted service operation through the helper.
44. [`mac_priv_package_install`](tool-contracts/mac_priv_package_install.json) — approved package identity/version installation.
45. [`mac_priv_power`](tool-contracts/mac_priv_power.json) — tightly scoped reboot or shutdown.

## Excluded interfaces

V0.1 does not provide `run_shell`, `sudo_shell`, raw Keychain or SSH private-key reads, raw Docker socket proxying, arbitrary launchd persistence, arbitrary AppleScript/JXA execution, generic click-anywhere, credential autofill, Git push, force reset, destructive disk operations, or security-setting bypass.

## Tool delivery waves

The catalog groups tools into five delivery waves: `wave_1` control and Broker introspection (tools 1-3), `wave_2` L0/L1 inspection (tools 4-20), `wave_3` L2 developer operations and controlled writes (tools 21-35), `wave_4` app, GUI, and owner-domain service control (tools 36-42), and `wave_5` privileged helper operations (tools 43-45). These waves sequence capability delivery; they are not roadmap lifecycle phases. Contracts remain planned authority until implementation, verification, release gates, and explicit enablement pass.

## V2 development gateway (disabled by default)

These additive source contracts do not enable the live personal deployment. Production coding-agent execution remains gated on accepted isolation and credential-free inference.

| Tool | Purpose |
| --- | --- |
| [mac_git_worktree_create](tool-contracts/mac_git_worktree_create.json) | Create one Broker-owned isolated worktree using a task-bound idempotency key. |
| [mac_git_worktree_list](tool-contracts/mac_git_worktree_list.json) | List only Broker-owned worktrees for one authorized project. |
| [mac_git_worktree_remove](tool-contracts/mac_git_worktree_remove.json) | Remove a clean Broker-owned worktree with ownership checks and read-back verification; never delete the primary repository. |
| [mac_git_branch_create](tool-contracts/mac_git_branch_create.json) | Create a task branch together with a Broker-owned worktree without switching the primary working copy. |
| [mac_codex_preflight](tool-contracts/mac_codex_preflight.json) | Inspect coding-agent and project readiness without executing a development task or returning credentials. |
| [mac_codex_run](tool-contracts/mac_codex_run.json) | Submit a bounded coding-agent job in one authorized isolated worktree; enforce filesystem, process, secret, Git, and explicit network boundaries. |
| [mac_test_run](tool-contracts/mac_test_run.json) | Submit one approved existing test profile as a bounded Broker-managed worktree job; never accept an arbitrary shell command. |
| [mac_build_run](tool-contracts/mac_build_run.json) | Submit one approved existing build profile as a bounded Broker-managed worktree job; never accept an arbitrary shell command. |
| [mac_git_push](tool-contracts/mac_git_push.json) | Reserved high-risk push boundary, denied until a separate explicit approval workflow is supported; never force-push. |
| [mac_pr_prepare](tool-contracts/mac_pr_prepare.json) | Prepare a bounded review summary from changed paths, commits, and managed-job test evidence without publishing a pull request. |
| [mac_execution_audit](tool-contracts/mac_execution_audit.json) | Read bounded redacted audit events for an authorized project; never expose sensitive file contents or credentials. |

## Personal owner terminal mode

- [mac_terminal_exec](tool-contracts/mac_terminal_exec.json): explicit opt-in owner-account shell and CLI execution; separate from isolated task profiles.
- [mac_terminal_session](tool-contracts/mac_terminal_session.json): explicit opt-in interactive PTY shell session (start, write, read, stop) as the owner; same scope and delegation as `mac_terminal_exec`.
