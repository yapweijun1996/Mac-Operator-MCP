# Child-Process Sandbox Research Contract

Status: Planned; blocks `mac_task_run`
Task: MOP-086

## Research question

What isolation can the supported physical Mac enforce for project-controlled commands while keeping Broker and controller credentials, denied filesystem targets, denied networks, host processes, Docker authority, and persistence mechanisms outside child reach?

## Target matrix

Record exact Mac hardware, macOS version/build, runtime, user identity, OS permissions, candidate isolation mechanism, and known platform deprecations for every experiment.

## Required experiments

- Read allowed fixture and write only to an explicit scratch root.
- Deny Keychain, SSH, browser, cloud, package, Git credential, Broker, and Edge secret canaries.
- Verify inherited environment and file descriptors contain no controller credentials.
- Deny traversal, symlink/mount escape, and alternate path spelling.
- Deny configured network destinations and prove permitted network profiles separately.
- Prevent arbitrary Docker socket, launchd persistence, privilege escalation, and process detachment.
- Own and terminate the full process tree on cancellation or timeout.
- Test native binaries, shell scripts, Node, Python, package scripts, Git hooks, and spawned grandchildren.
- Test restart, crash, and cleanup of artifacts and processes.

## Evaluation criteria

For each dimension, report `ENFORCED`, `PARTIAL`, `UNAVAILABLE`, or `UNKNOWN`, with commands, expected behavior, observed behavior, artifact hashes, and limitations. A successful happy path is insufficient.

## Decision outputs

Choose the supported sandbox, restrict `mac_task_run` profiles to proven guarantees, move execution into a stronger isolation boundary, or remove the capability. Document residual risk in ADR-0006 and update the tool contract before enablement.
