import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { BrokerError, decodeUtf8Strict } from "@mac-operator/contracts";
import { assertContentDoesNotContainSecrets, assertContentPathAllowed, redactLogText } from "./secret-policy.js";

export const PACKAGE_MANAGERS = ["npm", "pnpm", "yarn", "pip", "uv", "poetry", "brew"] as const;
export type PackageManager = (typeof PACKAGE_MANAGERS)[number];
export type PackageManagerRequest = PackageManager | "auto";

export interface SafePackageDependency {
  name: string;
  version: string;
  source?: string;
}

export interface SafePackageInspection {
  projectRoot: string;
  manager: PackageManager | "unknown";
  dependencies: readonly SafePackageDependency[];
  lockfile: {
    present: boolean;
    path?: string;
  };
  outdated: readonly {
    name: string;
    current: string;
    latest: string;
  }[];
  warnings: readonly string[];
  truncated: boolean;
}

export interface PackageExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface PackageInspector {
  inspect(
    projectRoot: string,
    manager: PackageManagerRequest,
    checkOutdated: boolean,
    control: PackageExecutionControl
  ): Promise<SafePackageInspection>;
}

const MAX_PROJECT_ROOT_LENGTH = 4_096;
const MAX_MANIFEST_BYTES = 512 * 1024;
const MAX_DEPENDENCIES = 5_000;
const MAX_TIMEOUT_MS = 30_000;
const PROJECT_ROOT_PATTERN = /^\/[^\u0000\n]*$/u;
const MANIFESTS: Readonly<Record<PackageManager, readonly string[]>> = {
  npm: ["package.json", "package-lock.json", "npm-shrinkwrap.json"],
  pnpm: ["package.json", "pnpm-lock.yaml"],
  yarn: ["package.json", "yarn.lock"],
  pip: ["requirements.txt", "requirements-dev.txt", "pyproject.toml"],
  uv: ["pyproject.toml"],
  poetry: ["pyproject.toml"],
  brew: ["Brewfile"]
};
const LOCKFILES: Readonly<Record<PackageManager, readonly string[]>> = {
  npm: ["package-lock.json", "npm-shrinkwrap.json"],
  pnpm: ["pnpm-lock.yaml"],
  yarn: ["yarn.lock"],
  pip: ["Pipfile.lock", "requirements.lock"],
  uv: ["uv.lock"],
  poetry: ["poetry.lock"],
  brew: ["Brewfile.lock.json"]
};

interface ProjectIdentity {
  path: string;
  identity: string;
}

interface SafeFile {
  relativePath: string;
  content: Buffer;
}

interface PackageParseContext {
  dependencies: SafePackageDependency[];
  warnings: string[];
  truncated: { value: boolean };
  check: () => void;
}

export class PackageInspectorImpl implements PackageInspector {
  async inspect(
    projectRoot: string,
    manager: PackageManagerRequest,
    checkOutdated: boolean,
    control: PackageExecutionControl
  ): Promise<SafePackageInspection> {
    validatePackageInspectRequest(projectRoot, manager, checkOutdated);
    const identity = canonicalProjectRoot(projectRoot);
    const startedAt = Date.now();
    const check = (): void => {
      if (control.shouldCancel()) throw new BrokerError("CANCELLED", "Package inspection was cancelled");
      if (Date.now() - startedAt > Math.min(control.timeoutMs, MAX_TIMEOUT_MS)) {
        throw new BrokerError("TIMEOUT", "Package inspection timed out");
      }
    };
    const warnings: string[] = [];
    const truncated = { value: false };
    const actualManager = detectManager(identity.path, manager);
    const dependencies: SafePackageDependency[] = [];
    const context: PackageParseContext = { dependencies, warnings, truncated, check };
    const manifest = firstReadableManifest(identity.path, actualManager, check);
    if (actualManager === "unknown") {
      addWarning(warnings, "No supported package manifest was found");
    } else if (!manifest) {
      addWarning(warnings, "The selected package manager has no supported manifest in the project root");
    } else {
      parseManifest(actualManager, manifest, context);
    }
    check();
    const lockPath = actualManager === "unknown"
      ? undefined
      : firstPresentPath(identity.path, LOCKFILES[actualManager], check);
    assertProjectIdentity(identity.path, identity.identity);
    if (checkOutdated) {
      addWarning(warnings, "Outdated package lookup is disabled until an allowlisted registry profile is configured");
    }
    return {
      projectRoot: identity.path,
      manager: actualManager,
      dependencies,
      lockfile: lockPath ? { present: true, path: lockPath } : { present: false },
      outdated: [],
      warnings,
      truncated: truncated.value
    };
  }
}

export function validatePackageInspectRequest(
  projectRoot: string,
  manager: PackageManagerRequest = "auto",
  checkOutdated = false
): void {
  if (typeof projectRoot !== "string" || projectRoot.length < 1 || projectRoot.length > MAX_PROJECT_ROOT_LENGTH ||
      !PROJECT_ROOT_PATTERN.test(projectRoot) || !isAbsolute(projectRoot) || resolve(projectRoot) !== projectRoot) {
    throw new BrokerError("PRECONDITION_FAILED", "Package project root is outside the supported range");
  }
  if (typeof manager !== "string" || (manager !== "auto" && !PACKAGE_MANAGERS.includes(manager as PackageManager))) {
    throw new BrokerError("PRECONDITION_FAILED", "Package manager is unsupported");
  }
  if (typeof checkOutdated !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "check_outdated must be a boolean");
  }
}

function detectManager(projectRoot: string, requested: PackageManagerRequest): PackageManager | "unknown" {
  if (requested !== "auto") return requested;
  if (hasRegularFile(projectRoot, "pnpm-lock.yaml")) return "pnpm";
  if (hasRegularFile(projectRoot, "yarn.lock")) return "yarn";
  if (hasRegularFile(projectRoot, "package-lock.json") || hasRegularFile(projectRoot, "npm-shrinkwrap.json") ||
      hasRegularFile(projectRoot, "package.json")) return "npm";
  if (hasRegularFile(projectRoot, "poetry.lock")) return "poetry";
  if (hasRegularFile(projectRoot, "uv.lock")) return "uv";
  if (hasRegularFile(projectRoot, "pyproject.toml") || hasRegularFile(projectRoot, "requirements.txt") ||
      hasRegularFile(projectRoot, "requirements-dev.txt")) return "pip";
  if (hasRegularFile(projectRoot, "Brewfile")) return "brew";
  return "unknown";
}

function firstReadableManifest(projectRoot: string, manager: PackageManager | "unknown", check: () => void): SafeFile | undefined {
  if (manager === "unknown") return undefined;
  for (const candidate of MANIFESTS[manager]) {
    check();
    const file = readRegularFile(projectRoot, candidate);
    if (file) return file;
  }
  return undefined;
}

function firstPresentPath(projectRoot: string, candidates: readonly string[], check: () => void): string | undefined {
  for (const candidate of candidates) {
    check();
    if (hasRegularFile(projectRoot, candidate)) return candidate;
  }
  return undefined;
}

function parseManifest(manager: PackageManager, manifest: SafeFile, context: PackageParseContext): void {
  let text: string;
  try { text = decodeUtf8Strict(manifest.content); }
  catch {
    addWarning(context.warnings, "The selected package manifest is not valid UTF-8");
    return;
  }
  if (manager === "npm" || manager === "pnpm" || manager === "yarn") {
    if (manifest.relativePath.endsWith(".json")) {
      parseNodeManifest(text, context);
    } else {
      addWarning(context.warnings, "The selected Node package lock is recorded as present but not parsed for dependency content");
    }
  } else if (manager === "pip" || manager === "uv" || manager === "poetry") {
    if (manifest.relativePath.endsWith(".txt")) {
      parseRequirements(text, manifest.relativePath, context);
    } else {
      parsePythonManifest(text, manager, context);
    }
  } else {
    parseBrewfile(text, context);
  }
}

function parseNodeManifest(text: string, context: PackageParseContext): void {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    addWarning(context.warnings, "The Node package manifest is not valid JSON");
    return;
  }
  if (!isRecord(value)) {
    addWarning(context.warnings, "The Node package manifest root is not an object");
    return;
  }
  for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    context.check();
    const values = value[section];
    if (!isRecord(values)) continue;
    for (const [name, version] of Object.entries(values)) {
      context.check();
      addDependency(context, name, typeof version === "string" ? version : "", section);
    }
  }
  const bundled = value.bundledDependencies;
  if (Array.isArray(bundled)) {
    for (const name of bundled) {
      context.check();
      if (typeof name === "string") addDependency(context, name, "", "bundledDependencies");
    }
  }
}

function parseRequirements(text: string, source: string, context: PackageParseContext): void {
  for (const line of text.split(/\r?\n/u)) {
    context.check();
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]{0,255})(?:\[[^\]]+\])?\s*(.*)$/u.exec(trimmed);
    if (!match) {
      addWarning(context.warnings, "Some Python requirement lines were omitted");
      continue;
    }
    addDependency(context, match[1]!, match[2]!.trim(), source);
  }
}

function parsePythonManifest(text: string, manager: PackageManager, context: PackageParseContext): void {
  let section = "";
  let inProjectDependencies = false;
  for (const rawLine of text.split(/\r?\n/u)) {
    context.check();
    const line = rawLine.trim();
    const sectionMatch = /^\[([^\]]+)\]$/u.exec(line);
    if (sectionMatch) {
      section = sectionMatch[1]!;
      inProjectDependencies = false;
      continue;
    }
    if (section === "project" && /^dependencies\s*=\s*\[/u.test(line)) {
      inProjectDependencies = true;
      continue;
    }
    if (inProjectDependencies) {
      if (line.startsWith("]")) {
        inProjectDependencies = false;
        continue;
      }
      const quoted = /["']([A-Za-z0-9][A-Za-z0-9._-]{0,255})(?:\[[^\]]+\])?\s*([^"']*)["']/u.exec(line);
      if (quoted) addDependency(context, quoted[1]!, quoted[2]!.trim(), "pyproject.toml");
      continue;
    }
    if (section === "tool.poetry.dependencies" || section === "tool.poetry.group.main.dependencies") {
      const assignment = /^([A-Za-z0-9][A-Za-z0-9._-]{0,255})\s*=\s*(.*)$/u.exec(line);
      if (assignment && assignment[1] !== "python") {
        const version = assignment[2]!.replace(/^["']|["']$/gu, "").trim();
        addDependency(context, assignment[1]!, version, manager === "poetry" ? "poetry" : "pyproject.toml");
      }
    }
  }
}

function parseBrewfile(text: string, context: PackageParseContext): void {
  for (const line of text.split(/\r?\n/u)) {
    context.check();
    const match = /^\s*(?:brew|cask)\s+["']([^"']+)["'](?:\s*,\s*version:\s*["']([^"']+)["'])?/u.exec(line);
    if (match) addDependency(context, match[1]!, match[2] ?? "", "Brewfile");
  }
}

function addDependency(context: PackageParseContext, name: string, version: string, source: string): void {
  const safeName = sanitizePackageValue(name, 256);
  const safeVersion = sanitizePackageValue(version, 128, true);
  const safeSource = sanitizePackageValue(source, 256);
  if (!safeName || safeVersion === null || !safeSource) {
    addWarning(context.warnings, "Some package dependency metadata was omitted as malformed");
    return;
  }
  if (context.dependencies.some((dependency) => dependency.name === safeName && dependency.source === safeSource)) return;
  if (context.dependencies.length >= MAX_DEPENDENCIES) {
    context.truncated.value = true;
    return;
  }
  context.dependencies.push({ name: safeName, version: safeVersion, source: safeSource });
}

function sanitizePackageValue(value: string, maxLength: number, allowEmpty = false): string | null {
  if ((!allowEmpty && value.length < 1) || value.length > maxLength) return null;
  const redacted = redactLogText(value);
  const safe = redacted.text.replace(/[\u0000-\u001f\u007f]/gu, "�");
  if ((!allowEmpty && safe.length < 1) || safe.length > maxLength) return null;
  return safe;
}

function addWarning(warnings: string[], warning: string): void {
  if (!warnings.includes(warning) && warnings.length < 32) warnings.push(warning);
}

function canonicalProjectRoot(projectRoot: string): ProjectIdentity {
  try {
    const lexical = lstatSync(projectRoot);
    if (!lexical.isDirectory() || lexical.isSymbolicLink()) {
      throw new BrokerError("POLICY_DENIED", "Package project root must be a non-symlink directory");
    }
    const canonical = realpathSync.native(projectRoot);
    if (canonical !== projectRoot || resolve(canonical) !== canonical) {
      throw new BrokerError("POLICY_DENIED", "Package project root must be canonical");
    }
    const stat = statSync(canonical);
    return { path: canonical, identity: String(stat.dev) + ":" + String(stat.ino) };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Package project root was not found");
  }
}

function assertProjectIdentity(projectRoot: string, expectedIdentity: string): void {
  try {
    const canonical = realpathSync.native(projectRoot);
    const stat = statSync(canonical);
    const identity = String(stat.dev) + ":" + String(stat.ino);
    if (canonical !== projectRoot || identity !== expectedIdentity) {
      throw new BrokerError("POLICY_DENIED", "Package project root changed during inspection");
    }
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("POLICY_DENIED", "Package project root changed during inspection");
  }
}

function hasRegularFile(projectRoot: string, relativePath: string): boolean {
  const target = safeCandidatePath(projectRoot, relativePath);
  let descriptor: number | undefined;
  try {
    const lexical = lstatSync(target);
    if (!lexical.isFile() || lexical.isSymbolicLink()) {
      if (lexical.isSymbolicLink()) throw new BrokerError("POLICY_DENIED", "Package manifest symlinks are denied");
      return false;
    }
    assertContentPathAllowed(target);
    if (realpathSync.native(target) !== target) throw new BrokerError("POLICY_DENIED", "Package manifest must be canonical");
    descriptor = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor);
    const after = lstatSync(target);
    if (opened.dev !== lexical.dev || opened.ino !== lexical.ino || opened.size !== lexical.size ||
        after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
        realpathSync.native(target) !== target) {
      throw new BrokerError("POLICY_DENIED", "Package manifest changed during inspection");
    }
    return true;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new BrokerError("TARGET_NOT_FOUND", "Package manifest was not found");
  } finally {
    if (typeof descriptor === "number") closeSync(descriptor);
  }
}

function readRegularFile(projectRoot: string, relativePath: string): SafeFile | undefined {
  const target = safeCandidatePath(projectRoot, relativePath);
  let lexical;
  try {
    lexical = lstatSync(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new BrokerError("TARGET_NOT_FOUND", "Package manifest was not found");
  }
  if (!lexical.isFile() || lexical.isSymbolicLink()) {
    if (lexical.isSymbolicLink()) throw new BrokerError("POLICY_DENIED", "Package manifest symlinks are denied");
    return undefined;
  }
  if (lexical.size > MAX_MANIFEST_BYTES) {
    throw new BrokerError("OUTPUT_LIMIT", "Package manifest exceeded its size limit");
  }
  assertContentPathAllowed(target);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor);
    if (opened.dev !== lexical.dev || opened.ino !== lexical.ino || opened.size !== lexical.size) {
      throw new BrokerError("POLICY_DENIED", "Package manifest changed while opening");
    }
    const content = readFileSync(descriptor);
    assertContentDoesNotContainSecrets(content);
    const after = lstatSync(target);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
        realpathSync.native(target) !== target) {
      throw new BrokerError("POLICY_DENIED", "Package manifest changed during inspection");
    }
    return { relativePath, content };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("POLICY_DENIED", "Package manifest cannot be read safely");
  } finally {
    if (typeof descriptor === "number") closeSync(descriptor);
  }
}

function safeCandidatePath(projectRoot: string, relativePath: string): string {
  if (relativePath.length < 1 || relativePath.includes("\0") || isAbsolute(relativePath) ||
      relativePath.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new BrokerError("PRECONDITION_FAILED", "Package manifest path is invalid");
  }
  const candidate = join(projectRoot, relativePath);
  if (resolve(projectRoot, relativePath) !== candidate || relative(projectRoot, candidate).startsWith("..")) {
    throw new BrokerError("POLICY_DENIED", "Package manifest escaped the project root");
  }
  return candidate;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
