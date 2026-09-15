# Physical regression after privileged Broker dispatch

- Source revision: `1f7451b`
- Command: `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1 node --test --test-timeout=120000 <all built tests except broker.test.js and persistence.test.js>`
- Result: 602 tests passed, 0 failed, 0 skipped.
- Native fault-injection build completed before the run.

The run exercised the existing physical sandbox, credential-canary,
fork/`setsid`, TCP/UDP, Keychain ACL, temporary LaunchAgent install/readback,
IPC, filesystem race, guest, Edge, and adapter boundary tests after the
privileged Broker dispatch changes. The existing long-running
`broker.test.js`/`persistence.test.js` process was left untouched.

This evidence only establishes regression safety. It does not claim that a
real service control, package install, reboot, shutdown, root process,
Developer ID signature, or production privileged adapter was executed.
