# Git push (`mac_git_push`)

`mac_git_push` is part of the owner V2 profile. It needs the `mac.git.push` scope and a project that the
signed policy already allows; there is no separate per-session switch to flip.

## What one call does

Input: `project_root` (a managed task worktree), `remote` (always `origin`), `branch_name`,
`expected_commit` and `idempotency_key`. The tool pushes exactly `expected_commit` to
`refs/heads/<branch_name>` with no `+` refspec, so a non-fast-forward is rejected by the remote.
It then reads the remote branch back; the call succeeds only if the remote ref equals `expected_commit`.
Pushing is never automatic: nothing pushes after a commit. An agent must make this call as part of an
authorized task instruction.

## Guards that always apply

| Guard | Behavior |
| --- | --- |
| Scope and project allowlist | Needs `mac.git.push` on an allowed project target rule. |
| Approval | A delegated single-use approval bound to the exact request digest, issued only for an owned managed worktree. |
| Destination | `origin` must have exactly one push URL, `https://github.com/<owner>/<repo>`, without credentials in the URL. |
| Force | Never. No `+` refspec, no `--force`, no delete. A diverged remote branch is left unchanged. |
| Protected branches | `main`, `master`, `trunk`, `develop`, `development`, `production`, `prod`, `stable`, `release/*`, `hotfix/*` are denied. |
| Exact binding | The current branch and HEAD must equal `branch_name` and `expected_commit` before and after the network preflight. |
| Hooks and transports | Repository hooks, push options and per-URL transport config stay inert. |
| Audit | Normal Broker intent, job and result records; evidence has remote, branch, commit and whether the push changed the remote. |

## NO_PUSH

A repository or branch opts out of agent pushes with any of:

```bash
git config macoperator.nopush true                      # whole repository (shared by its worktrees)
git config --add macoperator.nopushbranch <branch>      # one branch, repeatable
touch NO_PUSH                                           # file in the checkout root
```

The call then fails with `POLICY_DENIED: NO_PUSH ...` before any remote contact.

## Rollback

Remove `mac_git_push` from `V2_TOOLS` and `mac.git.push` from `V2_SCOPES`, rebuild, re-sign the V2 policy and
restart. Existing OAuth grants that already carry `mac.git.push` become inert because the tool is no longer enabled.
