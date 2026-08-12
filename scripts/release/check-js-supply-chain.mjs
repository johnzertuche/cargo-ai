import fs from "node:fs";
import path from "node:path";

const approvedLicenses = new Set([
  "0BSD",
  "Apache-2.0",
  "Apache-2.0 AND LGPL-3.0-or-later",
  "Apache-2.0 AND LGPL-3.0-or-later AND MIT",
  "Apache-2.0 OR MIT",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "BlueOak-1.0.0",
  "CC-BY-4.0",
  "CC0-1.0",
  "ISC",
  "LGPL-3.0-or-later",
  "MIT",
  "MIT OR Apache-2.0",
  "MIT-0",
  "MPL-2.0",
  "Python-2.0",
]);

const lockfiles = process.argv.slice(2);
if (lockfiles.length === 0) throw new Error("pass one or more npm lockfiles");

const failures = [];
const summary = [];
for (const input of lockfiles) {
  const lockfile = path.resolve(input);
  const lock = JSON.parse(fs.readFileSync(lockfile, "utf8"));
  if (lock.lockfileVersion !== 3 || typeof lock.packages !== "object") {
    failures.push(`${input}: require npm lockfileVersion 3 with a packages map`);
    continue;
  }
  let checked = 0;
  for (const [packagePath, metadata] of Object.entries(lock.packages)) {
    if (packagePath === "") continue;
    checked += 1;
    const label = `${input}:${packagePath}`;
    if (!metadata.version || typeof metadata.version !== "string") {
      failures.push(`${label}: missing exact version`);
    }
    if (!approvedLicenses.has(metadata.license)) {
      failures.push(`${label}: unapproved or missing license ${JSON.stringify(metadata.license)}`);
    }
    if (typeof metadata.resolved !== "string" || !metadata.resolved.startsWith("https://registry.npmjs.org/")) {
      failures.push(`${label}: package source is not the approved npm registry`);
    }
    if (typeof metadata.integrity !== "string" || !metadata.integrity.startsWith("sha512-")) {
      failures.push(`${label}: package is not locked with SHA-512 integrity`);
    }
  }
  summary.push({ lockfile: input, packages_checked: checked });
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(JSON.stringify({ policy: "cargo-js-supply-chain-v1", results: summary }, null, 2));
