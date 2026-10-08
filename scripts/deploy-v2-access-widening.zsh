#!/bin/zsh
# Owner-approved widening of the default /mcp connection on the personal Mac Operator service:
#   1. development-project-push: release Git push for the projects named in the replacement runtime config,
#   2. docker-read: enable the read-only Docker tools,
#   3. owner-terminal-scope: add mac.terminal.exec to the default /mcp consent.
# Never enables root, sudo, privileged package install, service control or the destructive/privileged kill switches.
# Usage: scripts/deploy-v2-access-widening.zsh <built-release-dir> <full-commit-id> <replacement-runtime-config>
# Stages the release, proves it opens the live state, backs up state, runs the migrations, restarts under PM2, checks health
# and that the signed policy survives a second restart. Any failure restores the old state and release.
set -euo pipefail
BUILT="${1:?built release dir}"; REV="${2:?full commit id}"; NEXT="${3:?replacement runtime config}"
[[ "$REV" =~ '^[0-9a-f]{40}$' ]] || { echo "revision must be a full commit id" >&2; exit 2; }
MAC="$HOME/Library/Application Support/MacOperator"
STATE="$HOME/Library/Application Support/MacOperator-g1-20260925a"
EDGE="$STATE/personal/edge-service.json"
REL="$MAC/releases/personal-$(date +%Y%m%d)-${REV:0:7}"
PM2=/opt/homebrew/bin/pm2; NODE=/opt/homebrew/bin/node
STAMP="$(date +%Y%m%d-%H%M%S)"; BACKUP="$MAC/backups/v2-widening-before-$STAMP"
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
policy_ok() { # live policy: push rules for every project in the replacement config, Docker tools on, no extra tools or kill-switch change
  $NODE -e '
    const fs = require("fs"); const [live, backup, next] = process.argv.slice(1);
    const read = p => JSON.parse(fs.readFileSync(p, "utf8"));
    const now = read(live + "/personal/policy.json").payload, old = read(backup + "/personal/policy.json").payload;
    const cfg = read(next);
    const pushed = new Set(now.target_rules.filter(r => r.scope === "mac.git.push").map(r => r.target.reference));
    const oldTools = new Set(old.tool_enablement.filter(t => t.enabled).map(t => t.tool));
    const nowTools = new Set(now.tool_enablement.filter(t => t.enabled).map(t => t.tool));
    const extra = [...nowTools].filter(t => !oldTools.has(t));
    const dockerOnly = extra.every(t => t.startsWith("mac_docker_")) && extra.length > 0;
    const ok = now.revision === old.revision + 2 && cfg.developmentProjects.every(p => pushed.has(p)) && dockerOnly &&
      JSON.stringify(now.kill_switches) === JSON.stringify(old.kill_switches) && now.kill_switches.destructive === true && now.kill_switches.privileged === true &&
      !nowTools.has("mac_priv_package_install") && !nowTools.has("mac_priv_power") && !nowTools.has("mac_priv_service_control") && !nowTools.has("mac_service_control");
    process.exit(ok ? 0 : 1);' "$STATE" "$BACKUP/state" "$NEXT"
}
scopes_ok() { # advertised /mcp consent includes terminal and Docker read, and /terminal/mcp stays absent
  $NODE -e '
    const e = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    process.exit(e.oauthScopes.includes("mac.terminal.exec") && e.oauthScopes.includes("mac.docker.read") && !e.ownerTerminalConnection ? 0 : 1);' "$EDGE"
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
cp -p "$NEXT" "$BACKUP/next-runtime.json"
[[ -f "$HOME/.pm2/dump.pm2" ]] && cp -p "$HOME/.pm2/dump.pm2" "$BACKUP/dump.pm2" || true

echo "5/8 point Edge at the new release"
$NODE -e '
  const fs=require("fs"); const [p,rel,rev]=process.argv.slice(1);
  const c=JSON.parse(fs.readFileSync(p,"utf8")); c.packageRoot=rel; c.contractsDirectory=rel+"/tool-contracts"; c.sourceRevision=rev;
  fs.writeFileSync(p+".tmp", JSON.stringify(c,null,2)+"\n",{mode:0o600}); fs.renameSync(p+".tmp",p);' "$EDGE" "$REL" "$REV"

echo "6/8 release push, enable Docker read, add the terminal scope to /mcp"
SVC="$REL/packages/auth/dist/personal-service.js"
"$NODE" "$SVC" development-project-push "$STATE" "$REV" "$NEXT" --enable >"$BACKUP/push.out" 2>"$BACKUP/push.err"
"$NODE" "$SVC" docker-read "$STATE" "$REV" --enable >"$BACKUP/docker.out" 2>"$BACKUP/docker.err"
"$NODE" "$SVC" owner-terminal-scope "$STATE" "$REV" --enable >"$BACKUP/terminal.out" 2>"$BACKUP/terminal.err"
policy_ok; scopes_ok

echo "7/8 start new release and check health"
start_service "$REL"
healthy

echo "8/8 restart once more: authority must persist"
"$PM2" restart $SERVICE >/dev/null
sleep 5
policy_ok; scopes_ok
"$PM2" save >/dev/null
trap - ERR
echo "OK: $SERVICE runs $REV from $REL; backup at $BACKUP"
echo "Next: reconnect the /mcp connector once so the new token receives the widened scopes."
