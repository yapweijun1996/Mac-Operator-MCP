import { inspectSystemPublishedExecutablePath } from "../packages/broker/dist/index.js";

if (process.platform !== "darwin") {
  console.error("The system-published executable probe requires macOS.");
  process.exitCode = 2;
} else {
  const paths = ["/bin/launchctl", "/usr/bin/sandbox-exec", "/usr/bin/printf"];
  const result = {
    schemaVersion: "0.1",
    mechanism: "darwin-system-published-executable-v1",
    paths: Object.fromEntries(paths.map((path) => [path, inspectSystemPublishedExecutablePath(path)]))
  };
  console.log(JSON.stringify(result));
  if (Object.values(result.paths).some((accepted) => accepted !== true)) process.exitCode = 1;
}
