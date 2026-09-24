import { readFile, readdir } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PLANNED_TOOL_NAMES } from "./catalog.js";
import { validateToolContractSafety } from "./contract-invariants.js";
import { SCOPES } from "./types.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default as new (options: Record<string, unknown>) => {
  addSchema(schema: object): void;
  compile(schema: object): ((value: unknown) => boolean) & { errors?: unknown };
  errorsText(errors: unknown): string;
};
const addFormats = require("ajv-formats").default as (ajv: InstanceType<typeof Ajv2020>) => void;

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const contractsDirectory = join(repositoryRoot, "tool-contracts");
const catalogPath = join(repositoryRoot, "TOOL_CATALOG.md");
const schema = JSON.parse(await readFile(join(contractsDirectory, "tool-contract.schema.json"), "utf8")) as object;
const failureSchema = JSON.parse(await readFile(join(repositoryRoot, "schemas", "broker-failure.schema.json"), "utf8")) as object;
const policyDocumentSchema = JSON.parse(await readFile(join(repositoryRoot, "schemas", "policy-document.schema.json"), "utf8")) as object;
const signedPolicyBundleSchema = JSON.parse(await readFile(join(repositoryRoot, "schemas", "signed-policy-bundle.schema.json"), "utf8")) as object;
const approvalIssuanceSchema = JSON.parse(await readFile(join(repositoryRoot, "schemas", "approval-issuance.schema.json"), "utf8")) as object;
const ledgerRecordsSchema = JSON.parse(await readFile(join(repositoryRoot, "schemas", "ledger-records.schema.json"), "utf8")) as object;
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);
ajv.compile(failureSchema);
ajv.addSchema(policyDocumentSchema);
ajv.compile(signedPolicyBundleSchema);
ajv.compile(approvalIssuanceSchema);
ajv.compile(ledgerRecordsSchema);
const files = (await readdir(contractsDirectory)).filter((file) => file.startsWith("mac_") && file.endsWith(".json")).sort();

if (files.length !== 45) throw new Error(`Expected 45 tool contracts, found ${files.length}`);

const names = new Set<string>();
const sourceIds = new Set<string>();
const knownScopes = new Set<string>(SCOPES);
for (const file of files) {
  const contract = JSON.parse(await readFile(join(contractsDirectory, file), "utf8")) as Record<string, unknown>;
  if (!validate(contract)) throw new Error(`${file}: ${ajv.errorsText(validate.errors)}`);
  validateToolContractSafety(contract, file);
  const inputSchema = contract.input_schema as Record<string, unknown>;
  const outputSchema = contract.output_schema as Record<string, unknown>;
  ajv.compile(inputSchema);
  ajv.compile(outputSchema);
  const outputProperties = outputSchema.properties as Record<string, Record<string, unknown>>;
  if (outputProperties.ok?.const !== true || outputProperties.result_class?.const !== "SUCCEEDED") {
    throw new Error(`${file}: output_schema must describe only the SUCCEEDED envelope`);
  }
  const name = String(contract.tool_name);
  const sourceId = String((contract.source as Record<string, unknown>).kb_item_id);
  if (names.has(name)) throw new Error(`Duplicate tool_name: ${name}`);
  if (file !== `${name}.json`) throw new Error(`${file}: filename does not match tool_name ${name}`);
  if (sourceIds.has(sourceId)) throw new Error(`Duplicate source kb_item_id: ${sourceId}`);
  names.add(name);
  sourceIds.add(sourceId);

  const forbiddenInputFields = recursivePropertyNames(inputSchema).filter((property) =>
    /^(?:approval|authentication|command|credential|env|environment|password|policy|principal|scope|scopes|script|secret|shell|sudo|token)$/iu.test(property)
  );
  if (forbiddenInputFields.length > 0) {
    throw new Error(`${file}: model-editable input contains forbidden authority field(s): ${forbiddenInputFields.join(", ")}`);
  }
  const unknownScopes = (contract.required_scopes as string[]).filter((scope) => !knownScopes.has(scope));
  if (unknownScopes.length > 0) {
    throw new Error(`${file}: required_scopes contains unknown value(s): ${unknownScopes.join(", ")}`);
  }
}

const expectedNames = [...PLANNED_TOOL_NAMES].sort();
const actualNames = [...names].sort();
if (JSON.stringify(expectedNames) !== JSON.stringify(actualNames)) {
  throw new Error("Runtime catalog and materialized contract names differ");
}

const catalogText = await readFile(catalogPath, "utf8");
const catalogNames = [...catalogText.matchAll(/\]\(tool-contracts\/(mac_[a-z0-9_]+)\.json\)/gu)].map((match) => match[1]!);
if (catalogNames.length !== actualNames.length || new Set(catalogNames).size !== catalogNames.length ||
    JSON.stringify([...catalogNames].sort()) !== JSON.stringify(actualNames)) {
  throw new Error("Tool catalog links and materialized contract names differ");
}

process.stdout.write(`Validated ${files.length} unique tool contracts, the catalog links, and the versioned ledger-record schema.\n`);

function recursivePropertyNames(schemaValue: unknown): string[] {
  if (schemaValue === null || typeof schemaValue !== "object") return [];
  const record = schemaValue as Record<string, unknown>;
  const properties = record.properties;
  const own = properties !== null && typeof properties === "object" && !Array.isArray(properties)
    ? Object.keys(properties as Record<string, unknown>)
    : [];
  return [...own, ...Object.values(record).flatMap(recursivePropertyNames)];
}
