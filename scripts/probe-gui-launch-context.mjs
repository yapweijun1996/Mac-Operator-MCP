import { MacGuiHelperReadinessProbe } from "../packages/broker/dist/gui-helper-readiness.js";

// Permission evidence comes only from the fixed app's production LaunchServices
// transport. Neither Node nor a direct gui_vision invocation is authoritative.
if (process.platform !== "darwin") throw new Error("This probe requires macOS");
const readiness = await new MacGuiHelperReadinessProbe().probe();
console.log(JSON.stringify(readiness));
process.exitCode = readiness.installed && readiness.identity_valid &&
  readiness.accessibility === true && readiness.screen_recording === true ? 0 : 1;
