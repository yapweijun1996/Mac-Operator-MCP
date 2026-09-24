import { spawn } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SANDBOX_EXECUTABLE = "/usr/bin/sandbox-exec";
const CAT_EXECUTABLE = "/bin/cat";
const TOUCH_EXECUTABLE = "/usr/bin/touch";
const PERL_EXECUTABLE = "/usr/bin/perl";
const MARKER = "mac-operator-sandbox-probe\n";
const MAX_CHILD_OUTPUT_BYTES = 64 * 1024;
const CHILD_TIMEOUT_MS = 5_000;

if (process.platform !== "darwin") {
  console.error("The Seatbelt boundary probe requires macOS.");
  process.exitCode = 2;
} else {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-sandbox-probe-"));
  const taskRoot = await realpath(directory);
  const protectedDirectory = await mkdtemp(join(tmpdir(), "mac-operator-sandbox-protected-"));
  const protectedRoot = await realpath(protectedDirectory);
  try {
    const allowedReadPath = join(taskRoot, "allowed-read.txt");
    const deniedReadPath = join(protectedRoot, "denied-read.txt");
    const allowedWritePath = join(taskRoot, "allowed-write.txt");
    const deniedWritePath = join(protectedRoot, "denied-write.txt");
    await writeFile(allowedReadPath, MARKER, { mode: 0o600 });
    await writeFile(deniedReadPath, MARKER, { mode: 0o600 });

    const readProfile = renderProfile({
      executable: CAT_EXECUTABLE,
      readRoots: [taskRoot],
      protectedRoots: [protectedRoot]
    });
    const writeProfile = renderProfile({
      executable: TOUCH_EXECUTABLE,
      readRoots: [taskRoot],
      writeRoots: [taskRoot],
      protectedRoots: [protectedRoot]
    });

    const allowedRead = await runSandbox(readProfile, CAT_EXECUTABLE, [allowedReadPath]);
    const deniedRead = await runSandbox(readProfile, CAT_EXECUTABLE, [deniedReadPath]);
    const allowedWrite = await runSandbox(writeProfile, TOUCH_EXECUTABLE, [allowedWritePath]);
    const deniedWrite = await runSandbox(writeProfile, TOUCH_EXECUTABLE, [deniedWritePath]);

    const processProfile = renderProfile({
      executable: PERL_EXECUTABLE,
      readRoots: [taskRoot],
      writeRoots: [taskRoot],
      protectedRoots: [protectedRoot]
    });
    const forkChildMarker = join(taskRoot, "fork-child-marker");
    const hostileForkScript = [
      "use strict;",
      "use POSIX qw(setsid);",
      "my $marker = shift;",
      "my $pid = fork();",
      "if (!defined $pid) { print qq(fork-denied\\n); exit 42; }",
      "if ($pid == 0) { setsid(); open(my $fh, chr(62), $marker) or die $!; print $fh $$; close($fh); exit 0; }",
      "waitpid($pid, 0); print qq(fork-succeeded\\n);"
    ].join(" ");
    const forkAttempt = await runSandbox(processProfile, PERL_EXECUTABLE, ["-e", hostileForkScript, forkChildMarker]);

    const allowedWriteExists = await exists(allowedWritePath);
    const deniedWriteExists = await exists(deniedWritePath);
    const forkChildCreated = await exists(forkChildMarker);
    const result = {
      schemaVersion: "0.1",
      mechanism: "sandbox-exec-seatbelt-v1",
      taskRoot,
      read: {
        allowed: allowedRead.code === 0 && !allowedRead.timedOut && !allowedRead.outputOverflow && allowedRead.stdout === MARKER,
        denied: deniedRead.code !== 0 && !deniedRead.timedOut && !deniedRead.outputOverflow && deniedRead.stdout !== MARKER
      },
      write: {
        allowed: allowedWrite.code === 0 && !allowedWrite.timedOut && !allowedWrite.outputOverflow && allowedWriteExists,
        denied: deniedWrite.code !== 0 && !deniedWrite.timedOut && !deniedWrite.outputOverflow && !deniedWriteExists
      },
      processTree: {
        forkDenied: forkAttempt.code === 42 && !forkAttempt.timedOut && !forkAttempt.outputOverflow && forkAttempt.stdout === "fork-denied\n",
        detachedChildMarkerAbsent: !forkChildCreated
      },
      raw: {
        allowedReadExit: allowedRead.code,
        deniedReadExit: deniedRead.code,
        allowedWriteExit: allowedWrite.code,
        deniedWriteExit: deniedWrite.code,
        outputBounded: [allowedRead, deniedRead, allowedWrite, deniedWrite].every((run) => !run.outputOverflow),
        timeoutBounded: [allowedRead, deniedRead, allowedWrite, deniedWrite, forkAttempt].every((run) => !run.timedOut)
      }
    };
    console.log(JSON.stringify(result));
    if (!result.read.allowed || !result.read.denied || !result.write.allowed || !result.write.denied ||
        !result.processTree.forkDenied || !result.processTree.detachedChildMarkerAbsent) {
      process.exitCode = 1;
    }
  } finally {
    await rm(taskRoot, { recursive: true, force: true });
    await rm(protectedRoot, { recursive: true, force: true });
  }
}

function renderProfile({ executable, readRoots, writeRoots = [], protectedRoots }) {
  const lines = [
    "(version 1)",
    '(import "system.sb")',
    "(deny default)",
    `(allow process-exec (literal ${quote(executable)}))`,
    `(allow file-read* (literal ${quote(executable)}))`,
    '(allow file-read* (subpath "/System/Library"))',
    '(allow file-read* (subpath "/usr/lib"))',
    '(allow file-read* (subpath "/usr/share"))'
  ];
  for (const root of readRoots) lines.push(`(allow file-read* (subpath ${quote(root)}))`);
  for (const root of writeRoots) lines.push(`(allow file-write* (subpath ${quote(root)}))`);
  for (const root of protectedRoots) {
    lines.push(`(deny file-read* (subpath ${quote(root)}))`);
    lines.push(`(deny file-write* (subpath ${quote(root)}))`);
  }
  return `${lines.join("\n")}\n`;
}

function quote(value) {
  return `"${value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}

function runSandbox(profile, executable, args) {
  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    let outputOverflow = false;
    let timer;
    let stdout = "";
    let stderr = "";
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      resolve({ ...value, stdout, stderr, timedOut, outputOverflow });
    };
    const child = spawn(SANDBOX_EXECUTABLE, ["-p", profile, executable, ...args], {
      cwd: "/tmp",
      env: {},
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    const append = (current, chunk) => {
      const next = `${current}${chunk}`;
      if (Buffer.byteLength(next, "utf8") > MAX_CHILD_OUTPUT_BYTES) {
        outputOverflow = true;
        try { child.kill("SIGKILL"); } catch { /* child may already be closed */ }
        return next.slice(0, MAX_CHILD_OUTPUT_BYTES);
      }
      return next;
    };
    child.stdout.on("data", (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on("data", (chunk) => { stderr = append(stderr, chunk); });
    child.once("close", (code, signal) => finish({ code, signal }));
    child.once("error", () => finish({ code: null, signal: null }));
    timer = setTimeout(() => {
      timedOut = true;
      try { child.kill("SIGKILL"); } catch { /* child may already be closed */ }
    }, CHILD_TIMEOUT_MS);
  });
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}
