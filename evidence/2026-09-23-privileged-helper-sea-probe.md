# Privileged Helper SEA Packaging Probe

Date: 2026-09-23

Status: PASS for a local packaging feasibility probe only. This is not a
production helper artifact or release acceptance.

## Runtime and provenance

- Host: macOS arm64.
- Runtime: official Node.js v24.21.0 Darwin arm64 archive.
- Official archive: `https://nodejs.org/dist/v24.21.0/node-v24.21.0-darwin-arm64.tar.gz`.
- Official SEA workflow reference:
  `https://nodejs.org/download/release/v24.18.0/docs/api/single-executable-applications.html`.
- Archive SHA-256: `bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057`.
- The archive hash matched its entry in the separately downloaded official
  `SHASUMS256.txt` over HTTPS. The detached PGP signature was not verified
  because neither `gpg` nor `gpgv` is installed on this host; this evidence
  does not claim cryptographic release-signature verification.
- Injector: `postject@1.0.0-alpha.6`, invoked through `npm exec` and pinned in
  the probe command. npm reported package integrity
  `sha512-b9Eb8h2eVqNE8edvKdwqkrY6O7kAwmI8kcnBv1NScolYJbo59XUF0noFq+lxbC1yN20bmC0WBEbDC5H/7ASb0A==`.

## Probe and result

The probe compiled `peer_credentials.node` against the same Node 24.21.0
headers used to build the executable. It then generated the Node 24 SEA
preparation blob, embedded the addon as an asset, injected the blob into a
temporary copy of the runtime, and applied a local ad-hoc signature so macOS
could execute the test artifact.

The executable passed these checks:

- `node:sea` reports SEA mode.
- The embedded native addon's SHA-256 matches the expected bytes.
- The native addon reports the exact Node 24.21.0 runtime and arm64 platform.
- Native process identity returns the executable process PID and a valid
  start-time identity.
- Built-in SQLite successfully executes `SELECT 1`.
- An injected `NODE_OPTIONS=--trace-warnings` does not change `process.execArgv`
  because the SEA configuration uses `execArgvExtension: "none"`.

The focused probe command returned exit status 0. TypeScript typecheck and the
repository style check also passed. The pre-existing generated native addon
was restored after the cross-version build; its SHA-256 remained
`6737113a80155f2e1957ae7213a72d5b273353fdce01b3928b5610720bd6f51a`.
Run the probe with a Node.js 24 binary first in `PATH`; the command rejects
other major versions before rebuilding the native addon.

## Limits

- Node SEA is documented as active development; this only proves a narrow
  macOS arm64 packaging path.
- The complete privileged-helper entrypoint, bundled application dependency
  graph, protected runtime configuration, and LaunchDaemon template are not
  produced by this probe.
- The test artifact has only an ad-hoc signature. Developer ID signing,
  notarization, Gatekeeper acceptance, root-domain installation, reboot
  persistence, live helper readback, rollback, and capability acceptance were
  not tested.
- No root service was installed or started, and no host service state was
  changed. Temporary runtime and executable files were removed after testing.

## Rollback

Remove this evidence note and its progress/ADR references, along with the
`probe:privileged-helper-sea` command and probe script. No host installation
was performed.
