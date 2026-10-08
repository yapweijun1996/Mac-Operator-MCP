#!/bin/zsh
# One-off manual cutover of the personal Mac Operator service to a release that includes mac_git_push.
# Usage: scripts/deploy-git-push-release.zsh <built-release-dir> <full-commit-id>
# Stages the release, proves it opens the live state, backs up state, re-signs the V2 policy, restarts under PM2,
# checks health and that mac_git_push stays enabled across a second restart. Any failure restores the old state and release.
set -euo pipefail
BUILT="${1:?built release dir}"; REV="${2:?full commit id}"
[[ "$REV" =~ '^[0-9a-f]{40}$' ]] || { echo "revision must be a full commit id" >&2; exit 2; }
MAC="$HOME/Library/Application Support/MacOperator"
STATE="$HOME/Library/Application Support/MacOperator-g1-20260925a"
EDGE="$STATE/personal/edge-service.json"
CFG="$MAC/v2-provisioning/orbstack-refresh-20261007/development-runtime-production.json"
REL="$MAC/releases/personal-$(date +%Y%m%d)-${REV:0:7}"
PM2=/opt/homebrew/bin/pm2; NODE=/opt/homebrew/bin/node
STAMP="$(date +%Y%m%d-%H%M%S)"; BACKUP="$MAC/backups/git-push-before-$STAMP"
SERVICE=mac-operator-personal
PREVIOUS="$($NODE -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).packageRoot)' "$EDGE")"
PRIOR_EDGE="$(mktemp)"; cp -p "$EDGE" "$PRIOR_EDGE"
STOPPED=0
start_service() { # $1 release
  "$PM2" delete $SERVICE >/dev/null 2>&1 || true
  "$PM2" start "$NODE" --name $SERVICE --interpreter none --kill-timeout 15000 --max-restarts 3 --restart-delay 5000 \
    --cwd "$1" -- "$1/packages/auth/dist/personal-service.js" start "$STATE" >/dev/null
}
healthy() {
  sleep 25
  $NODE -e '
    const { execFileSync } = require("child_process"); const fs = require("fs");
    const edge = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const svc = JSON.parse((t => t.slice(t.indexOf("[")))(execFileSync(process.argv[2], ["jlist"]).toString())).find(p => p.name === process.argv[3]);
    (async () => {
      for (let i = 0; i < 6; i++) {
        let status = 0; try { status = (await fetch(edge.resourceServerUrl, { method: "POST", signal: AbortSignal.timeout(10000) })).status; } catch {}
        if (svc && svc.pm2_env.status === "online" && svc.pm2_env.restart_time === 0 && status === 401) process.exit(0);
        await new Promise(r => setTimeout(r, 10000));
      }
      process.exit(1);
    })();' "$EDGE" "$PM2" $SERVICE
}
push_enabled() {
  $NODE -e '
    const b = JSON.parse(require("fs").readFileSync(process.argv[1] + "/personal/policy.json", "utf8"));
    const t = Object.fromEntries(b.payload.tool_enablement.map(x => [x.tool, x.enabled]));
    const g = b.payload.principal_grants.every(x => x.scopes.includes("mac.git.push"));
    process.exit(t.mac_git_push === true && g ? 0 : 1);' "$STATE"
}
rollback() {
  rc=$?; trap - ERR
  echo "FAILED (exit $rc)" >&2
  if [[ "$STOPPED" != 1 ]]; then
    echo "service was not stopped; nothing to restore (staged release left at $REL for inspection)" >&2
    exit $rc
  fi
  echo "restoring previous state and release" >&2
  "$PM2" stop $SERVICE >/dev/null 2>&1 || true
  if [[ "$STOPPED" == 1 && -d "$BACKUP/state" ]]; then
    mv "$STATE" "$STATE.failed-$STAMP"; cp -a "$BACKUP/state" "$STATE"
  fi
  cp -p "$PRIOR_EDGE" "$EDGE" 2>/dev/null || true
  start_service "$PREVIOUS" || true
  exit $rc
}
trap rollback ERR

echo "1/8 stage release $REL"
if [[ -e "$REL" ]]; then
  [[ "$(<"$REL/SOURCE-REVISION")" == "$REV" ]] || { echo "release dir exists with another revision: $REL" >&2; exit 2; }
  echo "   reusing the already staged release"
else
  mkdir -m 700 "$REL.tmp"
  rsync -a --exclude .git --exclude '*.log' "$BUILT"/ "$REL.tmp/"
  print -r -- "$REV" > "$REL.tmp/SOURCE-REVISION"
  mv "$REL.tmp" "$REL"
fi

echo "2/8 preflight: new build opens a private copy of the live state"
$NODE --input-type=module -e '
  const { preflightState } = await import(process.argv[1] + "/scripts/auto-deploy/preflight.mjs");
  const r = preflightState({ packageRoot: process.argv[2], stateRoot: process.argv[3], nodePath: process.argv[4] });
  if (!r.ok) { console.error(r.why); process.exit(1); }' "$PWD" "$REL" "$STATE" "$NODE"

echo "3/8 refuse to cut over while Jobs are queued or running"
JOBS="$($NODE --no-warnings -e 'const {DatabaseSync}=require("node:sqlite"); const d=new DatabaseSync(process.argv[1],{readOnly:true}); console.log(d.prepare("SELECT COUNT(*) AS n FROM jobs WHERE state IN (?, ?)").get("queued","running").n)' "$STATE/personal/broker.sqlite")"
[[ "$JOBS" == 0 ]] || { echo "$JOBS active jobs; retry later" >&2; exit 3; }

echo "4/8 stop service and back up state to $BACKUP"
mkdir -p -m 700 "$BACKUP"
"$PM2" stop $SERVICE >/dev/null; STOPPED=1; sleep 4
cp -Rp "$STATE" "$BACKUP/state"
[[ -f "$HOME/.pm2/dump.pm2" ]] && cp -p "$HOME/.pm2/dump.pm2" "$BACKUP/dump.pm2" || true

echo "5/8 point Edge at the new release"
$NODE -e '
  const fs=require("fs"); const [p,rel,rev]=process.argv.slice(1);
  const c=JSON.parse(fs.readFileSync(p,"utf8")); c.packageRoot=rel; c.contractsDirectory=rel+"/tool-contracts"; c.sourceRevision=rev;
  fs.writeFileSync(p+".tmp", JSON.stringify(c,null,2)+"\n",{mode:0o600}); fs.renameSync(p+".tmp",p);' "$EDGE" "$REL" "$REV"

echo "6/8 re-sign the V2 policy with the new tool and scope set"
"$NODE" "$REL/packages/auth/dist/personal-service.js" git-push "$STATE" "$REV" --enable >"$BACKUP/upgrade.out" 2>"$BACKUP/upgrade.err"
push_enabled

echo "7/8 start new release and check health"
start_service "$REL"
healthy

echo "8/8 restart once more: capability must persist"
"$PM2" restart $SERVICE >/dev/null
sleep 5
push_enabled
"$PM2" save >/dev/null
trap - ERR
echo "OK: $SERVICE runs $REV from $REL; backup at $BACKUP"
echo "Next: reconnect ChatGPT/Claude once to receive the mac.git.push scope, then run mac_capabilities."
