import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";

const port = 3187;
const origin = `http://127.0.0.1:${port}`;
const app = spawn(
  process.execPath,
  ["node_modules/vinext/dist/cli.js", "start", "--port", String(port), "--hostname", "127.0.0.1"],
  { env: { ...process.env, PORT: String(port) }, stdio: "inherit" },
);

try {
  let response;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      response = await fetch(origin);
      if (response.ok) break;
    } catch {
      // The local renderer is still starting.
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!response?.ok) throw new Error("Vinext prerender server did not become ready");
  const html = await response.text();
  if (!html.includes("Cargo") || !html.includes("</html>")) {
    throw new Error("Prerender output did not contain a complete Cargo page");
  }
  await mkdir("dist", { recursive: true });
  await writeFile("dist/index.html", html);
} finally {
  app.kill("SIGTERM");
}
