# Confirm the deployment service is quiescent before replacing its protected state.
stop_deployment_service() {
  local pm2_path="$1" node_path="$2" service_name="$3"
  "$pm2_path" stop "$service_name" >/dev/null 2>&1 && return 0
  "$node_path" -e '
    const { execFileSync } = require("node:child_process");
    try {
      const raw = execFileSync(process.argv[1], ["jlist"], { shell: false, timeout: 30000, maxBuffer: 1048576,
        cwd: process.env.HOME, env: { PATH: process.env.PATH, HOME: process.env.HOME, ...(process.env.PM2_HOME ? { PM2_HOME: process.env.PM2_HOME } : {}) } }).toString();
      const service = JSON.parse(raw.slice(raw.indexOf("["))).find(value => value.name === process.argv[2]);
      process.exit(!service || service.pm2_env.status === "stopped" ? 0 : 1);
    } catch { process.exit(1); }
  ' "$pm2_path" "$service_name"
}
