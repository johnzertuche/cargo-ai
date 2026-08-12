import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const checker = path.resolve("scripts/release/check-js-supply-chain.mjs");

function run(lock) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "cargo-supply-chain-"));
  const input = path.join(directory, "package-lock.json");
  fs.writeFileSync(input, JSON.stringify(lock));
  const result = spawnSync(process.execPath, [checker, input], { encoding: "utf8" });
  fs.rmSync(directory, { recursive: true, force: true });
  return result;
}

function lock(metadata) {
  return {
    lockfileVersion: 3,
    packages: {
      "": { name: "fixture", version: "1.0.0" },
      "node_modules/fixture": {
        version: "1.2.3",
        license: "MIT",
        resolved: "https://registry.npmjs.org/fixture/-/fixture-1.2.3.tgz",
        integrity: "sha512-cargo-fixture",
        ...metadata,
      },
    },
  };
}

test("accepts only exact, licensed, registry-pinned npm packages", () => {
  assert.equal(run(lock({})).status, 0);
  for (const mutation of [
    { license: "UNKNOWN" },
    { resolved: "https://packages.example.test/fixture.tgz" },
    { integrity: "sha1-weak" },
    { version: "" },
  ]) {
    const result = run(lock(mutation));
    assert.equal(result.status, 1, `${JSON.stringify(mutation)} should fail closed`);
  }
});
