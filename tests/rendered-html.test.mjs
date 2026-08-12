import assert from "node:assert/strict";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(new Request("http://localhost/", { headers: { accept: "text/html" } }), {
    ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
  }, { waitUntil() {}, passThroughOnException() {} });
}

test("server-renders the Cargo public landing page", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  const html = await response.text();
  assert.match(html, /<title>Cargo — Your AI life, owned by you<\/title>/i);
  assert.match(html, /Your AI life\./);
  assert.match(html, /Owned by you\./);
  assert.match(html, /Accountless by default/);
  assert.match(html, /View on GitHub/);
  assert.match(html, /No hosted vault/i);
  assert.match(html, /Apache 2\.0/);
  assert.doesNotMatch(html, /localStorage|working app|provider grant revoked/i);
});

test("publishes accurate social and security metadata", async () => {
  const html = await (await render()).text();
  assert.match(html, /cargo-og\.png/);
  assert.match(html, /https:\/\/cargo-ai-production\.up\.railway\.app\/cargo-og\.png/);
  assert.doesNotMatch(html, /localhost:3000/);
  assert.match(html, /Open-source, local-first AI portability/);
  assert.match(html, /johnzertuche\/cargo-ai/);
  assert.match(html, /Read the security model/);
});
