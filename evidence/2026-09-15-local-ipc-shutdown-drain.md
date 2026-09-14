# Local IPC Shutdown Drain Evidence

Date: 2026-09-15
Source commit: `13972d1`
Host: physical Darwin arm64 development host

## Implemented boundary

The Node Unix-socket implementations for the Broker, Approval, Authority
Control, Broker Status, Policy Signer, and Privileged Helper now track accepted
sockets and destroy them before waiting for server close. This makes shutdown
bounded for idle or incomplete peers instead of waiting for a request timeout.
Native peer IPC already owns and drains its accepted socket set; this change
brings the Node fallback channels to the same lifecycle boundary.

## Verification

- Cross-channel IPC focused suite: 29/29 pass.
- The Broker regression holds an authenticated idle socket open and proves
  `close()` drains it.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  575/575 pass, 0 skipped, 0 failed.

## Remaining boundary

This closes accepted-socket cleanup during local service shutdown. It does not
prove production launchd installation, remote deployment, or active Job
termination beyond each service's existing Broker-owned cancellation rules.

## Rollback

Revert commit `13972d1`; the prior server-close behavior and socket timeout
fallback remain unchanged.
