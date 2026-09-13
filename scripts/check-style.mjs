import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { extname, resolve } from "node:path";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const checkedExtensions = new Set([".js", ".mjs", ".json", ".md", ".ts", ".yml", ".yaml"]);
const checkedSuffixes = [".plist.in"];

let files;
try {
  const output = execFileSync("/usr/bin/git", ["ls-files", "-z"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024
  });
  files = output.split("\0").filter(Boolean);
} catch {
  console.error("style check could not enumerate tracked files");
  process.exitCode = 1;
  process.exit();
}

const failures = [];
for (const relativePath of files) {
  if (!checkedExtensions.has(extname(relativePath)) && !checkedSuffixes.some((suffix) => relativePath.endsWith(suffix))) continue;
  const path = resolve(repositoryRoot, relativePath);
  let stats;
  try {
    stats = lstatSync(path);
  } catch {
    failures.push(`${relativePath}: file is unavailable`);
    continue;
  }
  if (!stats.isFile()) {
    failures.push(`${relativePath}: tracked style input is not a regular file`);
    continue;
  }
  let content;
  try {
    content = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(path));
  } catch {
    failures.push(`${relativePath}: file is not valid UTF-8 text`);
    continue;
  }
  if (content.includes("\r")) failures.push(`${relativePath}: CRLF or carriage-return bytes are not allowed`);
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    if (/[ \t]+$/u.test(lines[index] ?? "")) failures.push(`${relativePath}:${index + 1}: trailing whitespace`);
  }
  if (content.length > 0 && !content.endsWith("\n")) failures.push(`${relativePath}: missing final newline`);
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  process.exitCode = 1;
} else {
  console.log(`Style check passed for ${files.filter((file) => checkedExtensions.has(extname(file)) || checkedSuffixes.some((suffix) => file.endsWith(suffix))).length} tracked files.`);
}
