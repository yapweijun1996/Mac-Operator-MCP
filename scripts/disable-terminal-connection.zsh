#!/bin/zsh
# Manual, owner-approved removal of the independent owner terminal connection (/terminal/mcp) on the current release.
# Stops the service, backs up the two protected configs, removes only the paired ownerTerminalConnection opt-in,
# restarts, requires 401 on /mcp and 404 on /terminal/mcp, and restores the configs on failure.
set -euo pipefail
MAC="$HOME/Library/Application Support/MacOperator"
STATE="$HOME/Library/Application Support/MacOperator-g1-20260925a"
EDGE="$STATE/personal/edge-service.json"; AUTH="$STATE/auth/auth-config.json"
PM2=/opt/homebrew/bin/pm2; NODE=/opt/homebrew/bin/node; SERVICE=mac-operator-personal
BACKUP="$MAC/backups/terminal-connection-disable-$(date +%Y%m%d-%H%M%S)"
REL="$($NODE -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).packageRoot)' "$EDGE")"
STOPPED=0
start_service() {
  "$PM2" delete $SERVICE >/dev/null 2>&1 || true
  "$PM2" start "$NODE" --name $SERVICE --interpreter none --kill-timeout 15000 --max-restarts 3 --restart-delay 5000 \
    --cwd "$1" -- "$1/packages/auth/dist/personal-service.js" start "$STATE" >/dev/null
}
check() { # expects /mcp 401 and /terminal/mcp 404, service online
  sleep 25
  for i in 1 2 3 4 5 6; do
    a=$(curl -s -o /dev/null -w "%{http_code}" -X POST https://mac.yapweijun1996.com/mcp || true)
    b=$(curl -s -o /dev/null -w "%{http_code}" -X POST https://mac.yapweijun1996.com/terminal/mcp || true)
    st=$("$PM2" jlist 2>/dev/null | $NODE -e 'const t=require("fs").readFileSync(0,"utf8");console.log(JSON.parse(t.slice(t.indexOf("["))).find(p=>p.name===process.argv[1]).pm2_env.status)' $SERVICE)
    [[ "$a" == 401 && "$b" == 404 && "$st" == online ]] && return 0
    sleep 10
  done
  return 1
}
rollback() {
  rc=$?; trap - ERR; echo "FAILED (exit $rc); restoring configs" >&2
  if [[ "$STOPPED" == 1 ]]; then
    "$PM2" stop $SERVICE >/dev/null 2>&1 || true
    cp -p "$BACKUP/edge-service.json" "$EDGE"; cp -p "$BACKUP/auth-config.json" "$AUTH"
    start_service "$REL" || true
  fi
  exit $rc
}
trap rollback ERR
JOBS="$($NODE --no-warnings -e 'const {DatabaseSync}=require("node:sqlite"); const d=new DatabaseSync(process.argv[1],{readOnly:true}); console.log(d.prepare("SELECT COUNT(*) AS n FROM jobs WHERE state IN (?, ?)").get("queued","running").n)' "$STATE/personal/broker.sqlite")"
[[ "$JOBS" == 0 ]] || { echo "$JOBS active jobs; retry later" >&2; exit 3; }
mkdir -p -m 700 "$BACKUP"
"$PM2" stop $SERVICE >/dev/null; STOPPED=1; sleep 4
cp -p "$EDGE" "$BACKUP/edge-service.json"; cp -p "$AUTH" "$BACKUP/auth-config.json"
$NODE -e '
  const fs=require("fs");
  for (const p of process.argv.slice(1)) { const c=JSON.parse(fs.readFileSync(p,"utf8")); delete c.ownerTerminalConnection;
    fs.writeFileSync(p+".tmp",JSON.stringify(c,null,2)+"\n",{mode:0o600}); fs.renameSync(p+".tmp",p); }' "$EDGE" "$AUTH"
start_service "$REL"; check
"$PM2" restart $SERVICE >/dev/null; check
"$PM2" save >/dev/null
trap - ERR
echo "OK: /terminal/mcp removed; /mcp unchanged; backup at $BACKUP"
