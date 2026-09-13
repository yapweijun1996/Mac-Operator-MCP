# Service Instance Lock Process Evidence

Status: Implemented real-process ownership evidence

## Scope

This slice verifies the Broker's owner-only runtime-root instance lock against
an actual second process. It does not install launchd, open the Broker socket,
or enable any capability.

## Procedure and result

- On the physical Darwin arm64 host, a child Node process acquired a unique
  temporary `broker.instance.lock` and held the descriptor open without a
  cooperative release path.
- The parent attempted `BrokerServiceInstanceLock.acquire` on the same path;
  native PID/start-time observation identified the child as live and returned
  stable `ALREADY_ACTIVE`.
- The child was terminated, the parent waited for its exit, and a second
  acquire reclaimed the lock only after the recorded identity was proven
  stale. The parent closed the new lock and removed the temporary directory.

## Verification

- Focused service-instance-lock suite: 5/5 passed, including the real
  non-cooperating owner test.
- The lock remained owner-only and target-bound; no broad unlink, recursive
  cleanup, service install, privilege change, or secret access occurred.

This strengthens startup serialization evidence but does not prove launchd
singleton enforcement, filesystem remount durability, or crash recovery across
every filesystem boundary.
