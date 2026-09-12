# Incident Response

Status: Draft

## Trigger examples

Suspected credential disclosure, forged/replayed request, policy bypass, unexpected file mutation, sandbox escape, raw Docker authority, unauthorized UI action, helper misuse, audit tampering, uncontrolled process, or failed revocation.

## Response order

1. Activate the smallest reliable kill switch; use global disable when scope is uncertain.
2. Revoke affected principals, sessions, approvals, and component credentials.
3. Preserve bounded logs, request/job/audit records, policy versions, component versions, and source revision without collecting secret contents.
4. Determine affected targets, active work, mutation outcomes, and rollback safety.
5. Reconcile every `RUNNING` or `UNKNOWN` operation.
6. Repair, rotate credentials, verify boundaries, and complete regression evidence.
7. Re-enable only the reviewed capability set and record the decision.

## Severity

Use the threat-model impact and likelihood scale. Suspected secret exposure, root/helper bypass, Broker authorization bypass, uncontrolled active execution, or audit integrity loss is P0 until bounded by evidence.
