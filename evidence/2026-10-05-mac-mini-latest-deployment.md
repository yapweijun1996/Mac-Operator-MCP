# Mac mini latest deployment — 2026-10-05

Status: DONE. GitHub main and local HEAD matched
`5fbc317a841d60669b95114a50c536b5a99b33ae` before deployment.

## Installed runtime and recovery

PM2 `mac-operator-personal` runs
`~/Library/Application Support/MacOperator/releases/personal-20261005-5fbc317`.
Protected state remains `~/Library/Application Support/MacOperator-o1-20261001a`.
The previous `personal-20261003-v2-i` release remains intact.

The service was already failing before deployment, with about 3,000 restarts.
An isolated startup diagnostic proved that the Docker image inspection returned
404: the pinned task image had been removed. The approved Engine identity and
Codex executable digest/version still matched. No recoverable image, local
archive or build cache was found. The retained original Dockerfile and locked
site dependencies were rebuilt as `mac-operator-yap-runtime:recovery-20261005`.
Its actual Docker image ID is
`sha256:90e9d231f56d358dd792b928da7a1da4ce1349306e91dacaa83d9a73defa5b25`.
Docker Desktop's containerd image ID is the manifest digest returned by
`docker image inspect`, rather than the BuildKit config digest.

Fresh physical and Codex acceptance evidence was combined into sixteen
explicitly mapped required checks under
`MacOperator/prepared/recovery-20261005-5fbc317`. Only after acceptance passed
were the runtime image/evidence references updated. The registered test
manifest digest was refreshed after confirming its script was unchanged;
command argv, profiles, projects, signed policy, keys and OAuth scopes were
preserved. The unsigned Edge package root, contract root and revision now bind
the new release. PM2 configuration was saved, with bounded restart settings.

The existing signed GUI app was preserved. Production LaunchServices readback
passed installation, identity, Accessibility and Screen Recording. This rollout
does not replace the installed native GUI bundle with newly built bytes.

## Verification

- Native build, TypeScript, style and all 58 tool contracts passed.
- Full regression after the test correction: 2,004 passed, 19 opt-in skipped,
  zero failures (2,023 total), using test concurrency 4.
- One integration assertion still expected a pre-spawn failed Git job to be
  `unknown`; current intended behavior is `failed`. Only that assertion was
  corrected in `packages/auth/src/auth.test.ts`. This local test change is
  uncommitted and is not a production runtime modification.
- The initial unrestricted parallel suite had two Git clone timeouts; both
  passed in targeted reruns and the final complete suite.
- Actual rebuilt-image physical isolation: 17/17 checks passed, including
  secret/symlink filtering, no host mounts/network/privilege, readonly access,
  process deadlines, cancellation, restart recovery and concurrent isolation.
- Actual Codex readonly/write, registered test/task/build, local synthetic
  commit/review and audit: passed, 21 successful calls; primary repository
  contents, HEAD and index remained unchanged. Temporary worktrees and branches
  were removed after retaining the synthetic commit patch.
- The first Codex probe tried reading a historical test file with sensitive
  fixture representations and returned `CODEX_TOOL_FAILED`. A minimal benign
  fixture in a separate owned worktree passed; sensitive content protections
  were retained.
- Personal snapshot preflight passed with bound loopback OAuth status.
- Public V2 OAuth: 29 tools for the verification read grant, 26 actual reads,
  and rejection after grant revocation passed.
- Independent owner-terminal OAuth: 44 discovered tools, 26 actual reads,
  31-second shell, local CLI, network, write/read, idempotency, Job readback,
  timeout and active-command cancellation on revocation passed.
- Final existing Codex connector `mac_health` returned `healthy`; PM2 remained
  online with zero restarts after 211 seconds.
- These public verifier invocations explicitly set `MOPS_VERIFY_PROJECT_ROOT`
  to the authorized repository. The initial default used the immutable release
  directory and correctly failed protected control-state access.

Read-only V2 verification does not exercise every coding operation through
public OAuth; the fresh coding acceptance used the actual private Broker,
Docker Engine and native Codex controller. The formal Developer ID/notarized
installer is outside this personal deployment's scope.

## Recovery material

Complete stopped-state and PM2 backup:
`MacOperator/backups/before-personal-20261005-5fbc317`.
It includes `state`, `dump.pm2`, `rollback.ecosystem.json`, and the rebuilt
`recovery-image.tar`. Protected evidence and new PM2 configuration are under
`MacOperator/prepared/recovery-20261005-5fbc317`.

A source rollback must retain the newly accepted image/evidence binding:
stop the service, back up current state, restore the prior unsigned Edge
configuration, start `rollback.ecosystem.json`, and save PM2. Restoring the
entire old state alone restores its missing-image reference and therefore
cannot recover the original outage. The rebuilt image archive restores only
the new image identity; it is not the deleted old image.

KB recall was used. External KB write preview was rejected by automatic approval
review because it contained internal operational details; no memory write was
performed. Deployment evidence remains local.
