import { spawn } from "node:child_process";
import http from "node:http";

const publicPort = Number.parseInt(process.env.PORT ?? "3000", 10);
const appPort = publicPort === 3001 ? 3002 : 3001;
const app = spawn(
  process.execPath,
  ["node_modules/vinext/dist/cli.js", "start", "--port", String(appPort), "--hostname", "127.0.0.1"],
  {
    env: { ...process.env, PORT: String(appPort) },
    stdio: "inherit",
  },
);

const securityHeaders = {
  "content-security-policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
};

const server = http.createServer((request, response) => {
  const upstream = http.request(
    {
      hostname: "127.0.0.1",
      port: appPort,
      path: request.url,
      method: request.method,
      headers: request.headers,
    },
    (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, {
        ...upstreamResponse.headers,
        ...securityHeaders,
      });
      upstreamResponse.pipe(response);
    },
  );
  upstream.on("error", () => {
    if (!response.headersSent) {
      response.writeHead(503, { "content-type": "text/plain; charset=utf-8", ...securityHeaders });
    }
    response.end("Cargo is starting. Please retry shortly.");
  });
  request.pipe(upstream);
});

server.listen(publicPort, "0.0.0.0");

function shutdown() {
  server.close(() => app.kill("SIGTERM"));
  setTimeout(() => app.kill("SIGKILL"), 5_000).unref();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
app.on("exit", (code) => {
  if (code && code !== 0) process.exitCode = code;
});
