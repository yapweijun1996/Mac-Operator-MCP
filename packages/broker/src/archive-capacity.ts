import { statfs } from "node:fs/promises";
import { BrokerError } from "@mac-operator/contracts";

/** Space kept for filesystem metadata, publication, and small runtime drift. */
export const ARCHIVE_CAPACITY_HEADROOM_BYTES = 4 * 1024 * 1024;
const MAX_ARCHIVE_CAPACITY_BYTES = 512 * 1024 * 1024;

/** @internal Test-only capacity probe; production callers must leave this unset. */
export type ArchiveCapacityProbe = (directory: string, requiredBytes: number) => Promise<number> | number;

/**
 * Fails before any archive temporary file is created when bounded free space is
 * unavailable. Archive publication uses a same-directory link, so one archive
 * payload plus headroom is the relevant disk requirement.
 */
export async function assertArchiveCapacity(
  directory: string,
  requiredBytes: number,
  capacityProbe?: ArchiveCapacityProbe
): Promise<void> {
  if (!Number.isSafeInteger(requiredBytes) || requiredBytes < 1 || requiredBytes > MAX_ARCHIVE_CAPACITY_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Archive capacity requirement is malformed");
  }

  let availableBytes: number;
  if (capacityProbe !== undefined) {
    try {
      availableBytes = await capacityProbe(directory, requiredBytes);
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Archive capacity could not be measured", true);
    }
  } else {
    try {
      const filesystem = await statfs(directory);
      availableBytes = filesystem.bavail * filesystem.bsize;
    } catch {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Archive capacity could not be measured", true);
    }
  }

  if (!Number.isSafeInteger(availableBytes) || availableBytes < requiredBytes) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Archive destination lacks bounded free space", true);
  }
}
