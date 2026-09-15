# Contract-policy parity evidence

- Source revision: `20b5d9b`
- Working tree: clean at capture
- Contract version: `0.1`
- Policy version: `policy-0.1`
- Host profile: Darwin `25.2.0`, arm64; local development checkout
- Procedure: build the Broker, load all `tool-contracts/mac_*.json` files,
  materialize `createDefaultPolicy`, and compare the complete 44-tool set for
  required scopes, Broker-normalized target type, timeout, output cap,
  approval policy, and mutation safety.
- Focused command: `node --test packages/broker/dist/contract-policy-parity.test.js`
- Result: 1 test passed, 0 failed.
- Corrections: six default-policy drifts were fixed. Health, capabilities, and
  policy-explain timeouts now match their contract budgets; capabilities,
  read-file, and job-status output caps now match; `mac_project_summary` keeps
  its documented `project_root` caller label while the Broker authorizes the
  descriptor-backed `path` target it actually plans.
- Scope: this verifies source/default-policy consistency only. Signed custom
  policy loading, network/filesystem/secret/audit metadata parity, native
  descriptor execution, production enablement, and installed-host evidence
  remain separate gates.
