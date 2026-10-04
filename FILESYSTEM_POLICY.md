# Mac-Operator-MCP Filesystem Policy

Status: Locked architecture baseline
Version: 0.1
Source: KBID `mac-operator-mcp`, item `fabad579-3f3d-4d08-a963-43b7b986b76b`

## Objective

Allow near-whole-Mac discovery without turning broad filesystem visibility into unrestricted content or write authority. The Broker owns path normalization and authorization. Full Disk Access or another macOS permission only makes an OS operation technically possible; it never overrides this policy.

## Locked precedence

Evaluate every filesystem request in this order:

`HARD_DENY > SENSITIVE_OPT_IN > WRITE_ROOT > READ_ROOT > METADATA_DISCOVERY > DEFAULT_DENY`

A broader allow never overrides a narrower deny. Read and write authority are independent.

## Access classes

- F0 `HARD_DENY`: generic tools never expose content or writes. Existence may be exposed only when explicitly useful and non-sensitive.
- F1 `SENSITIVE_OPT_IN`: private user data requires a dedicated scope and purpose-built adapter.
- F2 `METADATA_ONLY`: path, type, size, timestamp, and storage metadata may be inspected; contents are not returned.
- F3 `CONTENT_READ`: bounded read, search, and hash are permitted within configured read roots, subject to deny and file-type rules.
- F4 `CONTROLLED_WRITE`: atomic write, patch, and stage operations require configured write roots and write scopes.
- F5 `PRIVILEGED_TARGET`: generic file tools never mutate system targets; only an approved privileged-helper operation may do so.

## Default discovery surface

The host root `/` may be used for bounded metadata discovery. Discovery skips or sharply bounds dynamic and special trees such as `/dev`, `/private/var/run`, `/System/Volumes` internals, device, socket, and pseudo-filesystem surfaces. `/Volumes` is metadata-only by default. Removable, network, and Time Machine volumes require explicit per-volume policy before content access.

## Default read roots

- `$HOME` is content-readable except F0, F1, `~/Library` restrictions, and configured deny patterns.
- `~/Library` is metadata-only by default; selected subpaths require specific allow rules.
- `/Applications` is metadata/read-only where required for app discovery.
- `/Library`, `/System`, `/usr`, `/bin`, `/sbin`, `/private`, `/etc`, and package-manager or system locations are metadata-only unless a narrower read adapter requires access.
- Projects outside explicit read roots remain metadata-only until policy grants content access.

## Default write roots

Do not make all of `$HOME` writable. Use explicit user-owned project/workspace roots and the Broker workspace, such as configurable roots under `$HOME/Developer`, `$HOME/Projects`, or `$HOME/Documents/GitHub`. A discovered project outside a write root remains read-only. Generic writes to application, system, package-manager, LaunchAgent, LaunchDaemon, or login-item locations are denied and require a dedicated contract.

## F0 secret zones

Generic read, search, diff, and write tools deny secret content from:

- `~/Library/Keychains/**` and Keychain material.
- Private material under `~/.ssh/**` and `~/.gnupg/**`.
- Cloud-provider credentials and authentication caches.
- Docker, Kubernetes, Git, package-manager, and network credential files.
- Private keys, signing credentials, and provisioning secrets.
- Opaque signing and credential containers by filename (`.key`, `.p8`, `.p12`,
  `.pfx`, `.ppk`, `.jks`, `.keystore`, and provisioning-profile suffixes).
- `.env`, `.env.*`, vault files, and policy-classified credential files.
- Browser login, cookie, session, credential-vault, and token stores.
- macOS account, authorization, TCC, and privacy databases.

Path denial is primary. Content redaction is defense in depth and is never the only secret boundary.

## F1 private-data zones

Mail, Messages, browser history and profile content, Photos libraries, personal chat databases, and similar private stores are blocked from generic reads and searches. They require an explicit scope and purpose-built adapter with a narrow result contract.

## Path normalization and anti-escape rules

1. Reject NUL bytes, malformed paths, and unsupported encodings.
2. Expand only Broker-defined tokens; never perform shell expansion.
3. Convert to an absolute canonical target before authorization.
4. Resolve symlinks for every existing path segment and authorize the resolved target.
5. For new targets, authorize the canonical parent and create with no-follow or race-resistant semantics where available.
6. Deny traversal, mount escape, alias indirection, and symlink chains outside the authorized root.
7. Revalidate target identity before mutation and prefer descriptor/handle-based operations.
8. Generic tools accept only supported regular files and directories. Special files require a dedicated adapter.

## Read limits

Every read, search, list, and tree operation has byte, result, depth, and time budgets. Large files require bounded ranges. Binary content defaults to metadata or hash. Search excludes deny zones before opening files.

## Write semantics

`mac_write_file_atomic` and `mac_apply_patch` operate only in F4 roots. Prefer a bounded temporary file in the same directory, deliberate mode handling, appropriate synchronization, atomic rename, and hash/readback verification. Existing-file replacement should support an expected SHA-256. Never follow a final symlink. Failed verification returns `VERIFICATION_FAILED`.

## Git interaction

Git read tools inherit filesystem read policy. `mac_git_diff` redacts secret-like output and refuses F0 paths. The implemented Git write boundary is disabled by default: `mac_git_stage` accepts only bounded explicit literal paths in an authorized project and cannot stage denied, secret, `.git`, symlink, or target-swapped files; `mac_git_commit` commits only staged content after an optional staged-diff/hash precondition. Both mutations run as Broker-owned Jobs with approval, intent, idempotency, lease, timeout/output budgets, and postcondition readback. Commands use a fixed `/usr/bin/git` argv with hooks, fsmonitor, optional locks, signing, replacement objects, and network integrations disabled; push, reset, remote mutation, shell expansion, and arbitrary Git subcommands are not exposed. Unknown or failed readback never becomes success. Real-Mac temporary-repository and controlled-write release evidence remain required before enablement.

## External, removable, and network volumes

Default access is metadata-only. Content access requires a stable volume identity and allowed root. Revalidate identity after remount. Network-share reads require separate enablement; writes are disabled in v0.1.

## Configuration model

Versioned authority configuration contains discovery, read, and write roots; hard-deny and sensitive-opt-in zones; volume rules; limits; and policy version. Ordinary filesystem tools cannot modify this configuration.

## Required adversarial tests

Cover traversal, symlink escape and swap, case and Unicode normalization, relevant hardlink edges, hidden files, deny-inside-allow precedence, project outside write root, secret patterns, `.env`, browser credentials, SSH keys, removable-volume remount, special files, oversized operations, precondition mismatch, atomic-write crash recovery, and audit redaction.

## Initial decision

V0.1 uses broad metadata discovery, broad user-space read with explicit privacy and secret exclusions, and narrow explicit project/workspace write roots. Generic whole-home and system writes remain unavailable.

## Current implementation evidence

The filesystem-worker boundary is covered by a real multi-root fixture: two
independent authorized plans are searched together, overlap is rejected at the
fixed concurrency cap, and a later request succeeds after the worker exits.
The companion cancellation test records that `CANCELLED` is returned before a
terminated worker releases its capacity slot. These tests verify bounded
dispatch and capacity recovery without widening root authority; they do not
prove production-scale exhaustion or kernel-level I/O interruption.

Broker integration also runs a real filesystem worker against a mode-`0500`
parent and verifies that a pre-commit worker failure leaves the mutation Job
`UNKNOWN`, with an unavailable postcondition rather than a false success.
A separate controlled test-only worker URL and fault adapter drive the same
real worker boundary through atomic rename and force a post-rename `ENOSPC`; the
committed target is read back while the Job remains `UNKNOWN`. Production
construction omits the override and retains the fixed worker/native paths.

The fault-test-only native module also injects deterministic `ENOSPC` before
temporary-file write and `fsync` boundaries, and after atomic rename before
parent-directory `fsync`. Create and replace fixtures fail closed, preserve the
existing target on pre-commit errors, and expose the committed target without
the temporary artifact in the post-rename ambiguous window. This is error-path
evidence only; physical disk-full, remount, and restart recovery remain open.

The prototype implements `mac_stat_path` metadata, a bounded regular-file `mac_read_file` slice, descriptor-backed `mac_hash_file` SHA-256/SHA-512 hashing without returning content, bounded descriptor-backed `mac_list_directory` metadata pagination, and depth/entry-bounded `mac_directory_tree` traversal. Signed policy supplies independent metadata/content-read/write root flags and relative deny zones; hashing has its own `mac.files.hash` scope while listing and trees require a metadata-authorized content-read root. A macOS native adapter opens the root and target with no-follow protection where applicable, captures the canonical root path and `dev`/`fsid` volume identity in each Broker path plan, revalidates it before and after operations, compares target/parent `f_fsid` and filesystem type in addition to `st_dev`, returns device/inode evidence, and reapplies deny zones to the opened target or each returned child. Content reads and hashes use verified descriptors, require a local volume and single-link inode, use non-blocking opens for untrusted FIFO targets, authorize the canonical path before I/O, reject final symlinks/non-regular files, enforce range/size/encoding limits, and verify inode/link/size/mtime/ctime stability afterward. Directory listing is lexicographically paginated with a bounded `limit + 1` candidate set, filters hidden/protected entries before result construction, rejects directory identity changes after enumeration, represents Unix sockets and FIFOs as `other`, denies observed character/block devices at the local-volume boundary, and skips entries on another volume. Directory trees recurse only into descriptor-opened directories, inherit the same protected-entry and volume filters, cap depth at 8 and entries at 5,000, and report truncation. Metadata/search/tree pressure fixtures exercise bounded 600-entry inputs and reject oversized budgets before traversal. Broker-owned secret-zone and returned-content signature rules cannot be weakened by signed configuration. Tests cover traversal, symlink escape, deny aliases, hardlinks, post-authorization mutation, representative secret paths/content, root symlink rejection, root `/` containment, metadata/content/hash/list/tree target-change rejection, protected-entry filtering, bounded tree depth/truncation, Unix-socket/FIFO generic-tool denial, character/block-device and pseudo-device volume denial, bounded listing/tree/search pressure, plan/native volume-identity changes, and metadata/content symlink target-swap races.

Filesystem calls execute in Broker-owned worker threads with empty environment/arguments, bounded V8 memory and stack, a fixed concurrency cap, deadlines, cancellation polling, and runtime-validated messages. A timed-out or cancelled worker is asked to terminate and retains its capacity slot until exit; the focused cancellation test verifies that a later request is accepted only after that exit. A real multi-root worker test verifies independent root plans are carried together without widening authority. This protects the Broker event loop and limits thread accumulation, but it is not process isolation, a filesystem/network sandbox, or proof that a kernel-blocked syscall can be interrupted immediately.

The prototype now includes a disabled `mac_write_file_atomic` path for explicitly signed write roots. It uses same-directory temporary files, `fsync`, atomic rename, create-only exclusion, expected identity/hash preconditions, secret-content denial, descriptor readback hashing, an explicit idempotency key, and a Broker-owned Job Ledger record whose `job_id` is queryable through `mac_job_status`. Running or unresolved write jobs reconcile to `UNKNOWN` after restart rather than being reported successful. Each write job persists only a bounded non-secret descriptor (root, path, byte count, desired digest, preconditions, and the exact generated temporary filename); status can probe the current postcondition as `matches`, `mismatch`, or `unavailable`, but deliberately leaves the job `UNKNOWN` because a crash-window actor cannot be attributed. An explicit restart-recovery hook can clean only that recorded temporary file after the host proves the prior Broker instance no longer owns active workers; it uses descriptor-relative identity checks and never performs a filename-prefix scan. A 500-iteration hostile create/symlink target race confirms `RENAME_EXCL` does not replace an attacker target and leaves an outside canary unchanged. A test-only fault-instrumented native module now kills child processes with `SIGKILL` after selected temporary-file `fsync` and `rename` boundaries, confirming no partial target contents; remount durability, process ownership, and legacy jobs without a recorded temporary name remain open. Broad default discovery, exhaustive crash-injection/partial-mutation evidence, removable-volume remount identity, Unicode/case compatibility, configurable and split-range secret classification, enforceable syscall timeout/cancellation, the complete special-file/F0/F1 corpus, and production root configuration remain release-gate work. The read and write slices are implemented locally but not released or production-enabled.

## Managed worktree storage

Broker-managed development worktrees live outside every ordinary root: ordinary read, list, search and write tools are denied there even for the owning principal (`POLICY_DENIED`, reason code `MANAGED_WORKTREE_PATH` for the caller's own active worktree). Only the managed development tools (`mac_codex_run`, the Git tools, `mac_test_run`, `mac_build_run`) act on a worktree. The reason code only changes the message for the owner of the worktree; no allow or deny decision changed.
