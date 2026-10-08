#!/bin/zsh
# Manual, owner-approved enablement of the independent owner terminal connection (/terminal/mcp) on the current release.
# Usage: scripts/enable-terminal-connection.zsh
# Refuses while Jobs are queued/running, stops the service, backs up the full state, runs the offline `terminal-connection`
# opt-in, restarts under PM2, requires 401 on /mcp and /terminal/mcp, restarts once more, and restores the backup on failure.
set -euo pipefail
MAC="$HOME/Library/Application Support/MacOperator"
STATE="$HOME/Library/Application Support/MacOperator-g1-20260925a"
EDGE="$STATE/personal/edge-service.json"
PM2=/opt/homebrew/bin/pm2; NODE=/opt/homebrew/bin/node
SERVICE=mac-operator-personal
STAMP="$(date +%Y%m%d-%H%M%S)"; BACKUP="$MAC/backups/terminal-connection-before-$STAMP"
REL="$($NODE -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).packageRoot)' "$EDGE")"
REV="$($NODE -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).sourceRevision)' "$EDGE")"
[[ "$REV" =~ '^[0-9a-f]{7,64}$' && -f "$REL/packages/auth/dist/personal-service.js" ]] || { echo "current release is not usable" >&2; exit 2; }
STOPPED=0
start_service() {
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
    const terminal = edge.resourceServerUrl.replace(/\/mcp$/u, "/terminal/mcp");
    const probe = async url => { try { return (await fetch(url, { method: "POST", signal: AbortSignal.timeout(10000) })).status; } catch { return 0; } };
    (async () => {
      for (let i = 0; i < 6; i++) {
        const [a, b] = [await probe(edge.resourceServerUrl), await probe(terminal)];
        if (svc && svc.pm2_env.status === "online" && a === 401 && b === 401) process.exit(0);
        await new Promise(r => setTimeout(r, 10000));
      }
      process.exit(1);
    })();' "$EDGE" "$PM2" $SERVICE
}
rollback() {
  rc=$?; trap - ERR
  echo "FAILED (exit $rc)" >&2
  if [[ "$STOPPED" == 1 ]]; then
    "$PM2" stop $SERVICE >/dev/null 2>&1 || true
    [[ -d "$BACKUP/state" ]] && { mv "$STATE" "$STATE.failed-$STAMP"; cp -a "$BACKUP/state" "$STATE"; }
    start_service "$REL" || true
  fi
  exit $rc
}
trap rollback ERR

echo "1/6 refuse to proceed while Jobs are queued or running"
JOBS="$($NODE --no-warnings -e 'const {DatabaseSync}=require("node:sqlite"); const d=new DatabaseSync(process.argv[1],{readOnly:true}); console.log(d.prepare("SELECT COUNT(*) AS n FROM jobs WHERE state IN (?, ?)").get("queued","running").n)' "$STATE/personal/broker.sqlite")"
[[ "$JOBS" == 0 ]] || { echo "$JOBS active jobs; retry later" >&2; exit 3; }
echo "2/6 stop service and back up state to $BACKUP"
mkdir -p -m 700 "$BACKUP"
"$PM2" stop $SERVICE >/dev/null; STOPPED=1; sleep 4
cp -Rp "$STATE" "$BACKUP/state"
[[ -f "$HOME/.pm2/dump.pm2" ]] && cp -p "$HOME/.pm2/dump.pm2" "$BACKUP/dump.pm2" || true
echo "3/6 enable the independent terminal connection (V2 consent unchanged)"
"$NODE" "$REL/packages/auth/dist/personal-service.js" terminal-connection "$STATE" "$REV" --enable >"$BACKUP/upgrade.out" 2>"$BACKUP/upgrade.err"
echo "4/6 start and check /mcp and /terminal/mcp"
start_service "$REL"; healthy
echo "5/6 restart once more: configuration must persist"
"$PM2" restart $SERVICE >/dev/null; healthy
echo "6/6 save"
"$PM2" save >/dev/null
trap - ERR
echo "OK: /terminal/mcp enabled on $REL ($REV); backup at $BACKUP"
echo "Next: add a separate connector for https://mac.yapweijun1996.com/terminal/mcp and complete owner terminal consent."
