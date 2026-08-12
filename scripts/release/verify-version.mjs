import fs from "node:fs";

const tag = process.argv[2];
if (!tag || !/^v\d+\.\d+\.\d+$/.test(tag)) {
  throw new Error("production releases require an exact vMAJOR.MINOR.PATCH tag");
}
const expected = tag.slice(1);
const desktopPackage = JSON.parse(fs.readFileSync("apps/desktop/package.json", "utf8"));
const tauri = JSON.parse(fs.readFileSync("apps/desktop/src-tauri/tauri.conf.json", "utf8"));
const workspace = fs.readFileSync("Cargo.toml", "utf8");
const workspaceVersion = workspace.match(/\[workspace\.package\][\s\S]*?version\s*=\s*"([^"]+)"/)?.[1];
const versions = new Map([
  ["desktop package", desktopPackage.version],
  ["Tauri config", tauri.version],
  ["Rust workspace", workspaceVersion],
]);
for (const [source, version] of versions) {
  if (version !== expected) {
    throw new Error(`${source} version ${version ?? "<missing>"} does not match ${expected}`);
  }
}
console.log(`release versions agree on ${expected}`);
