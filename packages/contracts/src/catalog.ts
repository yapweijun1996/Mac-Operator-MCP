export const PLANNED_TOOL_NAMES = [
  "mac_app_focus", "mac_app_list", "mac_app_open", "mac_apply_patch", "mac_capabilities",
  "mac_directory_tree", "mac_docker_inspect", "mac_docker_logs", "mac_docker_status",
  "mac_find_files", "mac_git_branch_list", "mac_git_commit", "mac_git_diff", "mac_git_log",
  "mac_git_stage", "mac_git_status", "mac_hash_file", "mac_health", "mac_job_cancel",
  "mac_job_status", "mac_list_directory", "mac_log_tail", "mac_network_status",
  "mac_package_inspect", "mac_policy_explain", "mac_priv_package_install", "mac_priv_power",
  "mac_priv_service_control", "mac_process_inspect", "mac_process_list", "mac_project_discover",
  "mac_project_summary", "mac_read_file", "mac_recent_files", "mac_search_text",
  "mac_service_status", "mac_stat_path", "mac_storage_analysis", "mac_system_summary",
  "mac_terminal_exec", "mac_service_control", "mac_task_run", "mac_ui_action", "mac_ui_observe", "mac_ui_type", "mac_write_file_atomic"
] as const;

export type PlannedToolName = (typeof PLANNED_TOOL_NAMES)[number];
