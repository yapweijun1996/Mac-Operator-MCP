import { randomUUID } from "node:crypto";
import { closeSync, constants, linkSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const PUBLICATION_GRACE_MS = 30_000;

/** The kernel transaction serializes recovery and is released even after SIGKILL. Never unlink its database file. */
export function acquireDeploymentLock(lockDirectory) {
  const parent = dirname(lockDirectory);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const parentStat = lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || parentStat.uid !== process.getuid() ||
      (parentStat.mode & 0o077) !== 0 || realpathSync.native(parent) !== parent) throw new Error("Auto-deploy lock parent is not protected and canonical");
  const guardPath = `${lockDirectory}.sqlite`;
  try { closeSync(openSync(guardPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)); }
  catch (error) { if (error.code !== "EEXIST") throw error; }
  const guardStat = lstatSync(guardPath);
  if (!guardStat.isFile() || guardStat.isSymbolicLink() || guardStat.nlink !== 1 ||
      guardStat.uid !== process.getuid() || (guardStat.mode & 0o777) !== 0o600) throw new Error("Auto-deploy kernel lock is not a protected regular file");
  const database = new DatabaseSync(guardPath, { timeout: 0 });
  try { database.exec("BEGIN IMMEDIATE"); }
  catch (error) {
    database.close();
    if (error.errcode === 5 || error.errcode === 6) return null;
    throw error;
  }
  const releaseGuard = () => { try { database.exec("ROLLBACK"); } finally { database.close(); } };
  let retained = false;
  try {
    if (!sameIdentity(guardStat, lstatSync(guardPath))) throw new Error("Auto-deploy kernel lock identity changed");
    const previous = existingDirectory(lockDirectory);
    if (previous) {
      const entries = readdirSync(lockDirectory);
      if (entries.length === 0) {
        // Old versions could die between mkdir and PID publication. rmdir
        // refuses an initializer that publishes its PID during this check.
        if (Date.now() - previous.mtimeMs < PUBLICATION_GRACE_MS) return null;
      } else {
        if (entries.length !== 1 || entries[0] !== "pid") throw new Error("Auto-deploy lock contains unexpected evidence");
        const pidPath = join(lockDirectory, "pid");
        const pidStat = lstatSync(pidPath);
        if (!pidStat.isFile() || pidStat.isSymbolicLink() || pidStat.uid !== process.getuid() ||
            pidStat.size < 1 || pidStat.size > 32) throw new Error("Auto-deploy lock PID is malformed");
        const text = readFileSync(pidPath, "utf8").trim();
        if (!/^[1-9][0-9]{0,9}$/u.test(text) || Number(text) > 2_147_483_647) throw new Error("Auto-deploy lock PID is invalid");
        try { process.kill(Number(text), 0); return null; }
        catch (error) { if (error.code !== "ESRCH") return null; }
        if (!sameIdentity(previous, lstatSync(lockDirectory)) || !sameIdentity(pidStat, lstatSync(pidPath)) ||
            readFileSync(pidPath, "utf8").trim() !== text) throw new Error("Auto-deploy lock ownership changed");
        unlinkSync(pidPath);
      }
      if (!sameIdentity(previous, lstatSync(lockDirectory))) throw new Error("Auto-deploy lock ownership changed during recovery");
      try { rmdirSync(lockDirectory); }
      catch (error) { if (["ENOTEMPTY", "EEXIST", "ENOENT"].includes(error.code)) return null; throw error; }
    }
    try { mkdirSync(lockDirectory, { mode: 0o700 }); }
    catch (error) { if (error.code === "EEXIST") return null; throw error; }
    const identity = lstatSync(lockDirectory);
    const temporary = join(parent, `.auto-deploy-pid-${randomUUID()}`);
    try {
      // Publish a complete PID atomically; a crash before link leaves an empty,
      // recoverable directory rather than an unparseable partial PID file.
      writeFileSync(temporary, String(process.pid), { mode: 0o600, flag: "wx", flush: true });
      linkSync(temporary, join(lockDirectory, "pid"));
    } finally {
      try { unlinkSync(temporary); } catch (error) { if (error.code !== "ENOENT") throw error; }
    }
    const pidIdentity = lstatSync(join(lockDirectory, "pid"));
    if (!sameIdentity(identity, lstatSync(lockDirectory))) throw new Error("Auto-deploy lock ownership changed during publication");
    retained = true;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      try {
        if (!sameIdentity(identity, lstatSync(lockDirectory)) || !sameIdentity(pidIdentity, lstatSync(join(lockDirectory, "pid"))) ||
            readFileSync(join(lockDirectory, "pid"), "utf8") !== String(process.pid)) throw new Error("Auto-deploy lock ownership changed before release");
        unlinkSync(join(lockDirectory, "pid"));
        rmdirSync(lockDirectory);
      } finally { releaseGuard(); }
    };
  } finally { if (!retained) releaseGuard(); }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function existingDirectory(path) {
  let stat;
  try { stat = lstatSync(path); } catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o022) !== 0) {
    throw new Error("Auto-deploy lock directory ownership is invalid");
  }
  return stat;
}
