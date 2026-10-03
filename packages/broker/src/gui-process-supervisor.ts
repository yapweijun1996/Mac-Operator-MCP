import { throwGuiLauncherFailure } from "./gui-launcher-errors.js";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";

export const guiApplicationExecutable = join(homedir(), "Applications", "Mac Operator GUI.app", "Contents", "MacOS", "gui_vision");
export const guiLauncherExecutable = fileURLToPath(new URL("./gui_launcher", import.meta.url));

/** Routes only the fixed GUI adapter through LaunchServices; other adapters keep their supervisor. */
export class GuiProcessSupervisor {
  constructor(private readonly supervisor: Pick<ProcessSupervisor, "run"> = new ProcessSupervisor({ maxConcurrent: 1, allowedEnvironmentKeys: [] })) {}

  async run(request: ProcessExecutionRequest): Promise<ProcessExecutionResult> {
    if (request.executable !== guiApplicationExecutable) return this.supervisor.run(request);
    const result = await this.supervisor.run({
      ...request,
      executable: guiLauncherExecutable,
      allowUserOwnedExecutable: true,
      args: [],
      stdin: JSON.stringify({ args: request.args, stdin: request.stdin ?? "" })
    });
    throwGuiLauncherFailure(result);
    return result;
  }
}
