# Credential Loader Buffer Evidence

- Source revision: `43fec85`
- Date: 2026-09-15
- Scope: Broker file and native-Keychain credential adapters

## Decision

File-backed key loading now clears the raw file-read buffer after copying or
parsing the returned key. Native Keychain reads clear the adapter-returned
secret after making the caller-owned copy, and write/delete calls clear their
defensive native argument buffers in `finally` blocks. Public key-source and
digest behavior is unchanged.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 652 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Focused credentials and keyring suite: 28 total, 27 passed, 1 explicit
  physical-Keychain skip, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Production Keychain cross-process memory evidence, physical
erasure limits, and release enablement remain open.
