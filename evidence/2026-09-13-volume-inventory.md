# macOS volume inventory evidence

Status: PASS for read-only host inventory; physical/removable remount testing
remains OPEN because no eligible removable or secondary volume is mounted.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64 Mac mini
- Source commit: `92137e2226b4e9dedec7420548b605a65d3ec4a9`
- Working tree before this evidence document: clean after the source commit
- Host mutation: none; no mount, unmount, erase, repartition, or write operation

## Read-only observations

`diskutil list` reports only the internal physical `disk0` backing the APFS
containers and volumes. The mounted filesystem table contains only internal
APFS/system surfaces plus `devfs` and the home autofs map. `/Volumes` contains
only the system-provided `Macintosh HD -> /` symlink; no removable, network, or
secondary user volume is available for a remount exercise.

The absence of an eligible target is an environment fact, not a policy waiver.
The Broker continues to require captured volume identity and pre/post native
identity checks, and no capability was enabled.

## Verification

- Commands: `diskutil list`, `mount`, `ls -la /Volumes`, and `df -P` — completed read-only.
- Result: internal APFS only; no eligible removable/secondary volume found.
- Boundary check: `git diff --check` — passed.

## Remaining limits

This inventory does not prove behavior across an unmount/remount cycle,
network-share replacement, Time Machine media, or a removable filesystem. A
future run requires an explicitly approved disposable volume and a separate
rollback/readback procedure; this evidence intentionally performs none of
those actions.
