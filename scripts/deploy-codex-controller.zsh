#!/bin/zsh
# Owner-approved cutover of the pinned Codex controller (CLI version, executable digest and acceptance evidence).
# Usage: scripts/deploy-codex-controller.zsh <built-release-dir> <full-commit-id> <replacement-runtime-config>
# The replacement runtime config may differ from the installed one only in codexExecutable, codexExecutableSha256,
# codexVersion, evidencePath and evidenceSha256. No policy, scope, key or kill-switch change is made.
# Stages the release, proves it opens a private copy of the live state, backs up state, swaps the runtime config,
# restarts under PM2, checks health and persistence across a second restart. Any failure restores the old state and release.
set -euo pipefail
BUILT="${1:?built release dir}"; REV="${2:?full commit id}"; NEXT="${3:?replacement runtime config}"
[[ "$REV" =~ '^[0-9a-f]{40}$' ]] || { echo "revision must be a full commit id" >&2; exit 2; }
MAC="$HOME/Library/Application Support/MacOperator"
STATE="$HOME/Library/Application Support/MacOperator-g1-20260925a"
EDGE="$STATE/personal/edge-service.json"
REL="$MAC/releases/personal-$(date +%Y%m%d)-${REV:0:7}"
PM2=/opt/homebrew/bin/pm2; NODE=/opt/homebrew/bin/node
STAMP="$(date +%Y%m%d-%H%M%S)"; BACKUP="$MAC/backups/codex-controller-before-$STAMP"
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
config_ok() { # only the five Codex fields may differ; policy bytes must be identical to the backup
  $NODE -e '
    const fs = require("fs"); const [live, backup, next] = process.argv.slice(1);
    const read = p => JSON.parse(fs.readFileSync(p, "utf8"));
    const now = read(live + "/personal/development-runtime.json"), old = read(backup + "/personal/development-runtime.json"), want = read(next);
    const FIELDS = ["codexExecutable", "codexExecutableSha256", "codexVersion", "evidencePath", "evidenceSha256"];
    const strip = c => Object.fromEntries(Object.entries(c).filter(([k]) => !FIELDS.includes(k)));
    const same = JSON.stringify(strip(now)) === JSON.stringify(strip(old)) && JSON.stringify(now) === JSON.stringify(want);
    const policy = fs.readFileSync(live + "/personal/policy.json", "utf8") === fs.readFileSync(backup + "/personal/policy.json", "utf8");
    process.exit(same && policy && now.codexVersion !== old.codexVersion ? 0 : 1);' "$STATE" "$BACKUP/state" "$NEXT"
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

$NODE --input-type=module -e '
  const { loadPersonalDevelopmentRuntimeConfig } = await import(process.argv[1] + "/packages/auth/dist/personal-development-runtime.js");
  loadPersonalDevelopmentRuntimeConfig(process.argv[2]);' "$REL" "$NEXT" || { echo "replacement runtime config or its evidence is invalid for this release" >&2; exit 2; }

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

echo "6/8 swap the runtime config to the new Codex controller pin"
$NODE -e '
  const fs=require("fs"); const [src,dst]=process.argv.slice(1);
  fs.writeFileSync(dst+".tmp", fs.readFileSync(src), {mode:0o600}); fs.renameSync(dst+".tmp", dst);' "$NEXT" "$STATE/personal/development-runtime.json"
config_ok

echo "7/8 start new release and check health"
start_service "$REL"
healthy

echo "8/8 restart once more: authority must persist"
"$PM2" restart $SERVICE >/dev/null
sleep 5
config_ok
"$PM2" save >/dev/null
trap - ERR
echo "OK: $SERVICE runs $REV from $REL; backup at $BACKUP"
echo "Next: run mac_codex_preflight from ChatGPT; supported_models must now include gpt-6-luna and gpt-6.1-sol."
