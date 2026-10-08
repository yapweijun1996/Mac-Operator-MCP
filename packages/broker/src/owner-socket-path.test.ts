import assert from "node:assert/strict";
import { chmod, chown, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { validateGroupSocketParentChain, validateOwnerSocketParentChain } from "./owner-socket-path.js";

test("owner socket parent validation rejects ancestor symlinks and missing directories", async () => {
  const directory = await mkdtemp(join(tmpdir(), "owner-socket-path-"));
  try {
    const realRoot = join(directory, "r");
    const realRun = join(realRoot, "u");
    await mkdir(realRun, { recursive: true, mode: 0o700 });
    const aliasRoot = join(directory, "a");
    await symlink(realRoot, aliasRoot);
    await assert.rejects(
      validateOwnerSocketParentChain(join(aliasRoot, "u", "socket.sock"), process.getuid?.() ?? 501),
      /parent chain|unsafe/u
    );
    await assert.rejects(
      validateOwnerSocketParentChain(join(directory, "missing", "socket.sock"), process.getuid?.() ?? 501),
      /unavailable/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("group socket parent validation permits only the exact peer traversal directory", async () => {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  const directory = await mkdtemp(join(tmpdir(), "group-socket-path-"));
  const runDirectory = join(directory, "run");
  try {
    await mkdir(runDirectory, { mode: 0o700 });
    await chown(runDirectory, uid, gid);
    await chmod(runDirectory, 0o710);
    const socketPath = join(runDirectory, "helper.sock");
    await validateGroupSocketParentChain(socketPath, uid, uid, gid);
    await chmod(runDirectory, 0o750);
    await assert.rejects(
      validateGroupSocketParentChain(socketPath, uid, uid, gid),
      /permissions do not match/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
