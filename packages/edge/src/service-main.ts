import { runEdgeServiceMain } from "./service-startup.js";

runEdgeServiceMain().catch(() => {
  // The launchd boundary receives only a non-zero exit; protected startup
  // paths and authentication details never reach stdout or stderr.
  process.exitCode = 1;
});
