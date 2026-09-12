# Mac-Operator-MCP Tool Contract Standard

Status: Locked repo contract standard
Version: 0.1
Source: KBID `mac-operator-mcp`, item `757447f2-9ec8-4dd2-ae2c-21bce481e487`

## Purpose

Every model-facing tool is a capability request, never direct authority. The Edge authenticates the caller; the Broker independently authorizes, normalizes, executes, verifies, redacts, and audits the request.

## Mandatory contract fields

Each contract declares `tool_name`, capability level, safety class, required scopes, normalized target type, timeout, output cap, network policy, filesystem policy, secret policy, approval policy, idempotency, structured postcondition verification, audit class, `tool_delivery_wave`, and implementation status.

## Audit-class taxonomy

Every contract has exactly one primary `audit_class`. The class is deterministic from the tool's externally observable authority and is used to select audit retention, review routing, and release evidence requirements. It does not grant authority and does not replace scope or policy evaluation.

| Class | Meaning | Review and evidence profile |
|---|---|---|
| `observe` | Host, broker, policy, process, network, service, or health observation that does not read arbitrary file content. | Bounded result, privacy review, operational retention. |
| `filesystem_read` | Filesystem metadata, content, discovery, hashing, or project inspection. | Path authorization, secret-zone review, content redaction evidence. |
| `developer_read` | Read-only Git, package, Docker, or developer-state inspection. | Repository/metadata redaction review and bounded-output evidence. |
| `execution` | Broker-owned bounded task or job execution and lifecycle control. | Resource, timeout, cancellation, reconciliation, and sandbox evidence. |
| `filesystem_write` | Controlled file creation, replacement, or patching. | Approval, precondition, readback/hash, and crash-window evidence. |
| `git_write` | Explicit staging or local commit. | Path allowlist, staged-content, identity, and commit evidence. |
| `app_control` | Allowlisted application inventory, launch, or focus. | App identity, focus, permission, and re-observation evidence. |
| `gui_control` | Accessibility observation or bounded UI action/input. | Fresh-target, sensitive-target, focus, and re-observation evidence. |
| `privileged` | Separate-helper service, package, or power operation. | Helper authentication, allowlist, approval, readback, and independent review. |

## Postcondition-verification schema

`postcondition_verification` is an object, never a boolean or free-form string:

```json
{
  "required": true,
  "strategy": "readback_hash",
  "failure_class": "VERIFICATION_FAILED"
}
```

`required` is `true` for mutations and privileged actions and `false` for read-only observations. `strategy` names the semantic verification procedure; it is not a claim that the procedure has been implemented or passed. `failure_class` is the stable result classification when required verification cannot establish the declared postcondition. Read-only contracts still declare a bounded result-validation strategy so that response-shape validation is explicit.

Canonical strategies include `bounded_result_validation`, `bounded_tree_result_validation`, `capability_state_result_validation`, `component_health_result_validation`, `policy_decision_result_validation`, `bounded_system_result_validation`, `bounded_storage_result_validation`, `bounded_process_result_validation`, `sanitized_log_result_validation`, `bounded_network_result_validation`, `service_state_result_validation`, `canonical_metadata_result_validation`, `bounded_content_result_validation`, `digest_result_validation`, `safe_project_result_validation`, `sanitized_diff_result_validation`, `package_metadata_result_validation`, `sanitized_docker_result_validation`, `exit_status_and_declared_task_verification`, `job_result_validation`, `job_state_termination_verification`, `changed_paths_and_hash_readback`, `readback_hash`, `staged_diff_hash`, `commit_id_parent_and_staged_precondition`, `app_inventory_result_validation`, `launch_state_and_target_reobservation`, `focused_app_window_reobservation`, `accessibility_snapshot_validation`, `accessibility_reobservation`, `focused_target_and_input_postcondition`, `service_state_readback`, `installed_version_verification`, and `handoff_acceptance_and_scheduled_state`.

## Lifecycle naming

`roadmap_phase` describes project lifecycle progression (`Phase 0` through `Phase 7`) in `ROADMAP.md`. Individual tool contracts use `tool_delivery_wave` (`wave_1` through `wave_5`) for capability sequencing. The legacy materialization field `phase` is migrated to `tool_delivery_wave`; it is not retained as a canonical contract key.

## Request and result envelopes

The Edge generates or propagates `request_id`. Tool arguments contain task data only. Caller identity, scopes, credentials, and authority overrides are transport context and are not model-editable fields. The common result is `{ok, request_id, tool, result_class, data?, warnings?, truncated?, verification?, duration_ms}` with stable errors defined in `SPEC.md`.

## Contract envelope versus functional tool schemas

The repository JSON Schema validates the contract envelope: identity, capability, policy, budget, lifecycle, audit, delivery wave, provenance, and summary fields. All 44 contracts also provide per-tool functional `input_schema` and `output_schema` objects with bounded fields, explicit types, and strict model-controlled input properties. These schemas define the planned API surface; runtime compatibility, authorization enforcement, postcondition behavior, and host safety remain separate evidence gates under `MOP-004`, `MOP-007`, and `MOP-085`.

## Safety and execution rules

Deny beats allow. Secret zones are not relaxed by broader filesystem scope. Read, write, process, network, GUI, destructive, and privileged authority remain independent. Inputs never accept hidden authorization overrides, sudo passwords, bearer tokens, arbitrary environment injection, raw privileged commands, or interfaces excluded by `SECURITY.md`.

Child processes use explicit cwd, environment allowlist, timeout, output cap, filesystem policy, and network policy. Mutations require preconditions and postcondition verification. Privileged tools require explicit trusted policy and remain disabled until their release gates pass.

## Audit and versioning

Audit principal reference, tool, normalized target reference, policy decision, start and end, duration, result class, and bounded redacted evidence. Never audit secrets or credentials. Tool names remain stable after public use. Breaking contract or authority changes require a reviewed version transition.

## Materialization rule

The 44 KB contracts are preserved under `tool-contracts/` with KB provenance and structured fields. Documentation does not mark them implemented or enabled. The repository resolves the two standard fields deterministically from each tool's declared semantics; this closes schema completeness only and does not constitute runtime verification. `source.source_text` remains immutable provenance and may contain the legacy KB wording.
