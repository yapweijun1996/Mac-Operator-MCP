import { createConnection } from "node:net";
import { MacOsPeerCredentialVerifier, capturePeerProcessIdentity } from "./peer-credentials.js";
import { inspectProcess } from "./process-inspector.js";

/** Native-verified identity of the process that currently owns a container-engine socket. */
export interface ContainerEnginePeerIdentity {
  uid: number;
  gid: number;
  pid: number;
  startTimeMicros: number;
  /** Executable path of the daemon, or undefined when the OS does not report one. */
  executable: string | undefined;
}

export type ContainerEnginePeerProbe = (socketPath: string, expectedUid: number) => Promise<ContainerEnginePeerIdentity>;

const CONNECT_TIMEOUT_MS = 5_000;

/**
 * Connects once to the engine socket, lets the native adapter read the kernel peer credentials
 * (the peer UID must equal expectedUid) and returns the daemon's PID, start time and executable.
 * Used both when the Broker first pins the engine and when it revalidates after an engine restart,
 * so the two paths cannot drift apart. No request bytes are sent.
 */
export const captureContainerEnginePeer: ContainerEnginePeerProbe = async (socketPath, expectedUid) => {
  const socket = createConnection(socketPath);
  let peer;
  try {
    await new Promise<void>((ok, fail) => {
      socket.setTimeout(CONNECT_TIMEOUT_MS, () => fail(new Error("Engine peer connection timed out")));
      socket.once("connect", ok);
      socket.once("error", fail);
    });
    peer = new MacOsPeerCredentialVerifier({ expectedUid }).verify(socket);
  } finally { socket.destroy(); }
  // The identity is read on both sides of the executable lookup so a PID that exits and is reused
  // in between cannot lend its executable path to a different process.
  const before = capturePeerProcessIdentity(peer.pid);
  // An unreadable executable only disables restart revalidation; it must not break the first pin.
  let executable: string | undefined;
  try { executable = inspectProcess(peer.pid).executable; } catch { executable = undefined; }
  const after = capturePeerProcessIdentity(peer.pid);
  if (before.pid !== after.pid || before.startTimeMicros !== after.startTimeMicros) throw new Error("Engine peer process changed while it was inspected");
  return { uid: peer.uid, gid: peer.gid, pid: before.pid, startTimeMicros: before.startTimeMicros,
    executable: executable === undefined || executable === "unknown" ? undefined : executable };
};
