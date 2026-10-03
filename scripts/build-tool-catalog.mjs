import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const toolName = /^mac_[a-z0-9_]+$/u;

/** Build public contract metadata without loading platform-specific executors. */
export async function buildToolCatalog(root, outputPath) {
  const directory = join(root, "tool-contracts");
  const names = (await readdir(directory)).filter(name => /^mac_[a-z0-9_]+\.json$/u.test(name)).sort();
  if (names.length === 0 || names.length > 256) throw new Error("Tool contract collection is empty or exceeds its bound");
  const schema = JSON.parse(await readFile(join(directory, "tool-contract.schema.json"), "utf8"));
  const levels = schema.properties?.capability_level?.enum;
  if (!Array.isArray(levels) || !levels.length) throw new Error("Contract capability-level schema is unavailable");
  const tools = [];
  const source = createHash("sha256");
  for (const name of names) {
    const path = join(directory, name);
    const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1048576) throw new Error("Contract input is not a bounded regular file");
    const bytes = await readFile(path);
    const contract = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!toolName.test(contract.tool_name) || `${contract.tool_name}.json` !== name || contract.schema_version !== "0.1" ||
        !Array.isArray(contract.required_scopes) || contract.required_scopes.length === 0 ||
        contract.required_scopes.some(scope => typeof scope !== "string" || !/^mac\.[a-z._]+$/u.test(scope)) ||
        new Set(contract.required_scopes).size !== contract.required_scopes.length ||
        !levels.includes(contract.capability_level) ||
        typeof contract.purpose !== "string" || contract.purpose.length === 0 || contract.purpose.length > 8192) {
      throw new Error("Contract identity or public metadata is invalid");
    }
    source.update(`${name}\0${digest(bytes)}\n`);
    tools.push({ name: contract.tool_name, contract_version: contract.schema_version, capability_level: contract.capability_level,
      required_scopes: [...contract.required_scopes], purpose: contract.purpose });
  }
  const catalog = { schema_version: "0.1", source_sha256: source.digest("hex"), tools };
  const payload = Buffer.from(`${JSON.stringify(catalog, null, 2)}\n`);
  await publish(outputPath, payload);
  const readback = await readFile(outputPath);
  if (!readback.equals(payload)) throw new Error("Tool catalog readback differs from built artifact");
  return { tool_count: tools.length, source_sha256: catalog.source_sha256, artifact_sha256: digest(readback) };
}

async function publish(path, bytes) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const stat = await lstat(path).catch(error => { if (error.code !== "ENOENT") throw error; });
  if (stat && (!stat.isFile() || stat.isSymbolicLink())) throw new Error("Catalog destination is not a regular file");
  const temporary = join(dirname(path), `.tool-catalog-${randomUUID()}`);
  const file = await open(temporary, "wx", 0o600);
  try {
    try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
    await rename(temporary, path);
    const directory = await open(dirname(path), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  } finally { await rm(temporary, { force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 2 && !(process.argv.length === 4 && process.argv[2] === "--output")) throw new Error("Expected optional --output path");
  const output = resolve(process.argv[3] ?? "packages/contracts/dist/tool-catalog.json");
  console.log(JSON.stringify(await buildToolCatalog(process.cwd(), output)));
}
