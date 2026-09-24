import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, realpath, rename, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const probePath = join(repositoryRoot, "scripts/probe-host-readiness.mjs");
const targetPath = process.argv[2];

if (typeof targetPath !== "string" || !isAbsolute(targetPath) || resolve(targetPath) !== targetPath || targetPath.includes("\0")) {
  console.error("Usage: npm run record:host-readiness -- /absolute/path/host-readiness.json");
  process.exitCode = 2;
} else {
  try {
    const parent = await realpath(dirname(targetPath));
    const parentStat = await lstat(parent);
    const uid = process.getuid?.();
    if (!parentStat.isDirectory() || uid === undefined || parentStat.uid !== uid || (parentStat.mode & 0o077) !== 0) {
      throw new Error("host readiness evidence parent must be an owner-only directory");
    }

    const result = spawnSync(process.execPath, [probePath], {
      cwd: repositoryRoot,
      env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" },
      encoding: "utf8",
      maxBuffer: 64 * 1024,
      timeout: 15_000,
      shell: false,
      windowsHide: true
    });
    const line = `${result.stdout ?? ""}`.trim().split("\n").at(-1) ?? "";
    const evidence = JSON.parse(line);
    if (evidence === null || typeof evidence !== "object" || Array.isArray(evidence) ||
        evidence.mechanism !== "macos-host-readiness-v1" || typeof evidence.capturedAtMs !== "number") {
      throw new Error("host readiness probe returned malformed evidence");
    }

    const targetStat = await readTargetStat(targetPath);
    if (targetStat !== undefined && (!targetStat.isFile() || targetStat.isSymbolicLink() || targetStat.uid !== uid)) {
      throw new Error("host readiness evidence target must be an owner-only regular file");
    }
    const tempPath = join(parent, `.${basename(targetPath)}.tmp-${process.pid}`);
    try {
      const handle = await open(tempPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(evidence)}\n`, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      await chmod(tempPath, 0o600);
      await rename(tempPath, targetPath);
    } finally {
      await unlink(tempPath).catch(() => undefined);
    }
    process.stdout.write(`${JSON.stringify({
      schemaVersion: "0.1",
      mechanism: "record-macos-host-readiness-v1",
      path: targetPath,
      status: evidence.status,
      readyForRelease: evidence.readyForRelease,
      readyForGui: evidence.readyForGui,
      persistentServiceVerified: evidence.persistentServiceVerified
    })}\n`);
    process.exitCode = result.status === 0 ? 0 : 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "host readiness evidence recording failed");
    process.exitCode = 1;
  }
}

async function readTargetStat(path) {
  try {
    return await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}
