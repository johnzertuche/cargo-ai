import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";

test("production server applies browser security headers", async (t) => {
  const port = 31_000 + (process.pid % 1_000);
  const server = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: { ...process.env, PORT: String(port) },
    stdio: "ignore",
  });
  t.after(() => server.kill("SIGTERM"));

  let response;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      response = await fetch(`http://127.0.0.1:${port}/`);
      if (response.status === 200) break;
      await response.arrayBuffer();
    } catch {
      response = undefined;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  assert.ok(response, "production server did not become ready");
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("strict-transport-security") ?? "", /max-age=63072000/);
  assert.match(response.headers.get("permissions-policy") ?? "", /camera=\(\)/);
});
