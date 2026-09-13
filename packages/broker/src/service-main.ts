import { runBrokerServiceMain } from "./service-startup.js";

runBrokerServiceMain().catch(() => {
  // The launchd boundary receives only a non-zero exit; details stay out of
  // stdout/stderr because startup failures may contain protected paths.
  process.exitCode = 1;
});
