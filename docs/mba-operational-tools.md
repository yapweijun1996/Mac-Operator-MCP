# MBA operational tool enablement

## Explicit owner opt-in

O1 and V2 retain their existing default tool and scope sets. An operator can add
`mac_docker_status`, `mac_docker_inspect`, and `mac_docker_logs` through the
protected `dockerReadAccess` configuration. This grants Docker reads only; it
cannot create containers, select another daemon, or expose Docker credentials.
The offline migration requires an existing root O1 or V2 installation:

```sh
node packages/auth/dist/personal-service.js docker-read <state-root> <source-revision> --enable
```

Stop the service and take a consistent private state backup first. The migration
verifies and signs a new exact policy revision, preserves unrelated targets,
filesystem roots, kill switches and GUI grants, and is idempotent. Existing OAuth
grants keep their original scopes. A fresh connection and owner consent are
required to obtain `mac.docker.read`; refreshing an old token cannot add it.
The independent `/terminal/` connection does not inherit Docker consent.

## Development runtime on a different Mac

Follow the [V2 operator runbook](MAC_OPERATOR_V2_RUNBOOK.md) before enabling the
development profile. Runtime evidence must bind this Mac's actual Engine ID,
immutable image ID, pinned Codex executable and provider version. Evidence from
another Mac is insufficient. Physical validation accepts an explicit
`MOPS_CONTAINER_ENGINE_ID` alongside `MOPS_CONTAINER_IMAGE_ID`; both are checked
against the real Engine. Worker processes do not inherit parent execution flags.

A full macOS build cannot be substituted by a Linux task. Before registering a
repository build, verify the actual approved command against that repository's
filtered snapshot and container resource budget. The initial MBA probe of this
MCP repository failed because source scanning omitted files and TypeScript hit
the default heap limit. That probe is not evidence of a successful project build.
Do not relax secret filtering or claim complete V2 acceptance from synthetic
build fixtures alone. Host-native builds remain available through the separately
authorized owner terminal.

Codex file tools accept workspace-relative paths. The workspace root listing uses
an empty string, and `public.txt` addresses a file; absolute host paths and
`/workspace/public.txt` remain denied. Real read-only and workspace-write
acceptance must verify imported changes and the unchanged primary repository.

## Availability is more than signed policy

With Docker opt-in, O1 enables 42 tool implementations and V2 enables 53. Ordinary
V2 coding OAuth still excludes the two owner-terminal tools. Use the independent
owner-terminal connection when enabling that profile; never silently expand old
OAuth grants. GUI readiness continues to use the installed application's
LaunchServices identity and its existing TCC permissions. Runtime provisioning
must not rebuild or reinstall that application.

`mac_git_push` remains a planned contract without a supported push executor or
separate approval workflow. Privileged operations and service control likewise
require their own configured, authenticated executors and operation targets.
Changing enablement flags cannot implement those tools or validate their
postconditions. Their absence must remain visible in capability diagnostics.
