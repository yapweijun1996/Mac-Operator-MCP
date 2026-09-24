# Privileged Helper Cross-UID Socket Boundary

## Finding

The helper command listener is owned by root, while its Broker client runs as
the logged-in non-root user. A root-owned `0600` socket is not reachable by the
Broker. Giving write access to the Broker's primary GID fixes reachability but
also lets every member of that shared group reach the native accept boundary.
macOS `connect(2)` requires write access to the named socket and search access
on each parent directory component ([Apple `connect(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/connect.2.html)).

## Change

- Production Launchd-bound helper factories now pin the socket ACL to the
  captured Broker UID; callers cannot override it through `serverOptions`.
- The immediate helper socket directory is root:root `0711` with no extended
  ACL; ancestors must be traversable by the Broker and have no untrusted
  writes. The root helper checks extended ACLs before binding.
- The native listener creates a root:wheel socket with mode `0600` and one
  non-inheritable user ACE for the Broker. It grants `write` (the macOS UDS
  connect right) and `readsecurity` so the Broker can independently verify
  that ACL; it grants no group access or socket data-read permission.
- ACL principals are macOS GUIDs, not numeric UIDs. The native layer resolves
  the Broker UID with `mbr_uid_to_uuid` and verifies the persisted ACE maps
  back to the same UID. ACL readback requires exactly one allow ACE, the exact
  permission mask, and no inheritance flags.
- Native peer authorization remains unchanged: exact UID/GID and captured
  Broker PID/start-time are checked before request bytes reach the helper
  protocol. HMAC authentication, durable replay admission, and live Broker
  authority polling remain additional gates.
- Package readback requires root UID/GID, mode `0600`, and the exact Broker UID
  ACL. Broker and Broker-owned authority sockets retain exact mode `0600`.

## Verification

On macOS `26.2` / APFS with Node.js `v25.5.0`:

- `npm run typecheck` — passed.
- `npm run build:native --workspace @mac-operator/broker` — passed; native
  addon built and code-signature verification succeeded.
- Focused peer-credential, helper-runtime, package, and IPC tests — passed,
  64/64, including setting and reading back a per-user ACL on a temporary UDS.
- `npm run lint` — passed (821 tracked files).
- `npm test` — passed, 1,188/1,203 with 15 skips and no failures; this includes
  native fault-injection tests and the repository test suite.

The tests run as the current non-root owner and verify native ACL creation,
exact UID/permission readback, mode `0600`, and parent-chain checks. They do not
establish that a different UID is denied or that the Broker connects to a
root-owned socket under the root LaunchDaemon: no root service was installed
or started. The additional `ACL_READ_SECURITY` right is limited to reading the
socket's ACL metadata. A separate-user denial test and local-connect
availability test remain open.

## Status

This closes the source-level shared-group exposure and encodes an exact-user
socket ACL, but host acceptance remains incomplete. The helper
executable/release package, Developer ID signing and notarization, root-owned
directory provisioning, real cross-UID acceptance/denial, and root-domain
installation/readback remain open. Project completion audit remains partial
at 92%: 2/29 requirements pass, 23 remain open, and 4 are blocked.
