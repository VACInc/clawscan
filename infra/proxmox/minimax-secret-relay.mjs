import fs from "node:fs";
import http from "node:http";
import https from "node:https";

const listenAddress = process.env.OBSERVATORY_RELAY_LISTEN || "";
const apiKey = process.env.OBSERVATORY_MINIMAX_API_KEY || "";
const model = process.env.OBSERVATORY_RELAY_MODEL || "MiniMax-M3";
const receiptPath = process.env.OBSERVATORY_RELAY_RECEIPT || "";
const donePath = process.env.OBSERVATORY_RELAY_DONE_FILE || "";
const maxRequests = Number(process.env.OBSERVATORY_RELAY_MAX_REQUESTS || 16);
const maxRequestBytes = 8 * 1024 * 1024;
const maxResponseBytes = 32 * 1024 * 1024;
const maxTotalBytes = 64 * 1024 * 1024;
const maxConcurrent = 2;
const requestTimeoutMs = 180_000;
const deadlineSeconds = Number(process.env.OBSERVATORY_RELAY_DEADLINE_SECONDS || 0);
const upstream = new URL("https://api.minimax.io/v1/chat/completions");

if (!apiKey || !receiptPath || !donePath || !/^\d+$/.test(String(maxRequests)) || maxRequests < 1 || maxRequests > 64 ||
    !Number.isSafeInteger(deadlineSeconds) || deadlineSeconds < 1 || deadlineSeconds > 8_000) {
  throw new Error("relay key, receipt, done file, bounded request count, and scan-derived deadline are required");
}
const match = listenAddress.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)$/);
if (!match || Number(match[2]) < 1024 || Number(match[2]) > 65535) throw new Error("literal IPv4 relay listen address is required");
if (fs.existsSync(receiptPath) || fs.existsSync(receiptPath + ".ready") || fs.existsSync(donePath)) throw new Error("relay receipt, ready, and done paths must not exist");

const receipt = {
  schemaVersion: "observatory.minimax-secret-relay.v1",
  model,
  acceptedRequests: 0,
  rejectedRequests: 0,
  requestBytes: 0,
  responseBytes: 0,
  upstreamErrors: 0,
  peakConcurrency: 0,
  deadlineHit: false,
};
let active = 0;
let admittedRequests = 0;
let shuttingDown = false;
let receiptWritten = false;
let doneTimer;

function writeReceipt() {
  if (receiptWritten) return;
  fs.writeFileSync(receiptPath, JSON.stringify(receipt) + "\n", {encoding: "utf8", mode: 0o600, flag: "wx"});
  receiptWritten = true;
}
function shutdown(deadlineHit = false) {
  if (shuttingDown) return;
  shuttingDown = true;
  receipt.deadlineHit ||= deadlineHit;
  clearInterval(doneTimer);
  server.close(() => { writeReceipt(); process.exit(0); });
  setTimeout(() => { writeReceipt(); process.exit(active === 0 ? 0 : 1); }, 5000).unref();
}
function reject(res, status, message) {
  receipt.rejectedRequests++;
  deny(res, status, message);
  if (admittedRequests >= maxRequests && active === 0) shutdown(false);
}
function deny(res, status, message) {
  res.writeHead(status, {"content-type": "application/json", connection: "close"});
  res.end(JSON.stringify({error: {type: "observatory_relay", message}}));
}

const server = http.createServer((req, res) => {
  if (shuttingDown) return deny(res, 503, "relay is closing");
  if (admittedRequests >= maxRequests) {
    deny(res, 429, "request cap reached");
    if (active === 0) shutdown(false);
    return;
  }
  // Reserve the bounded request slot synchronously. Body parsing and upstream
  // forwarding are asynchronous, so counting only at body completion races.
  admittedRequests++;
  if (req.method !== "POST" || req.url !== "/v1/chat/completions") return reject(res, 404, "route is not allowed");
  if (req.headers.authorization !== "Bearer local") return reject(res, 401, "relay credential rejected");
  if (String(req.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase() !== "application/json") return reject(res, 415, "JSON required");
  if (active >= maxConcurrent) return reject(res, 429, "concurrency cap reached");
  const declared = Number(req.headers["content-length"] || 0);
  if (!Number.isSafeInteger(declared) || declared < 1 || declared > maxRequestBytes) return reject(res, 413, "request too large");

  active++;
  receipt.peakConcurrency = Math.max(receipt.peakConcurrency, active);
  const chunks = [];
  let bytes = 0;
  let upstreamRequest;
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    active--;
    if (admittedRequests >= maxRequests && active === 0) shutdown(false);
  };
  // A normally completed response emits "finish" before the socket's close
  // event. Release on either terminal event so graceful keep-alive teardown
  // cannot leave the bounded-concurrency counter stuck above zero and turn a
  // successful relay run into a fallback exit 1.
  res.once("finish", release);
  res.once("close", release);
  req.on("data", chunk => {
    bytes += chunk.length;
    receipt.requestBytes += chunk.length;
    if (bytes > maxRequestBytes || receipt.requestBytes + receipt.responseBytes > maxTotalBytes) {
      req.destroy();
      upstreamRequest?.destroy();
      if (!res.headersSent) reject(res, 413, "relay byte cap reached");
      else res.destroy();
      return;
    }
    chunks.push(chunk);
  });
  req.on("error", release);
  req.on("end", () => {
    if (res.writableEnded) return;
    let body;
    try {
      const parsed = JSON.parse(Buffer.concat(chunks, bytes).toString("utf8"));
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || parsed.model !== model) throw new Error("model mismatch");
      // MiniMax-M3's streamed OpenAI-compatible response can leave OpenClaw's
      // agent loop waiting for a terminal stream event after the HTTP response
      // itself has completed. Keep this credential boundary deterministic by
      // requesting the equivalent bounded non-streaming response upstream.
      parsed.stream = false;
      body = Buffer.from(JSON.stringify(parsed));
      if (body.length < 1 || body.length > maxRequestBytes) throw new Error("normalized request too large");
    } catch {
      return reject(res, 400, "valid JSON for the pinned model is required");
    }
    receipt.acceptedRequests++;
    upstreamRequest = https.request(upstream, {
      method: "POST",
      agent: false,
      headers: {
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        "content-length": String(body.length),
        connection: "close",
        "user-agent": "clawscan-observatory-secret-relay/1",
      },
      timeout: requestTimeoutMs,
    }, upstreamResponse => {
      const contentType = String(upstreamResponse.headers["content-type"] || "application/json").slice(0, 128);
      res.writeHead(upstreamResponse.statusCode || 502, {"content-type": contentType, connection: "close", "x-observatory-secret-relay": "bounded"});
      let responseBytes = 0;
      upstreamResponse.on("data", chunk => {
        responseBytes += chunk.length;
        receipt.responseBytes += chunk.length;
        if (responseBytes > maxResponseBytes || receipt.requestBytes + receipt.responseBytes > maxTotalBytes) {
          upstreamResponse.destroy();
          res.destroy();
          return;
        }
        if (!res.write(chunk)) upstreamResponse.pause();
      });
      res.on("drain", () => upstreamResponse.resume());
      upstreamResponse.on("end", () => res.end());
      upstreamResponse.on("error", () => { receipt.upstreamErrors++; res.destroy(); });
    });
    upstreamRequest.on("timeout", () => upstreamRequest.destroy(new Error("upstream timeout")));
    upstreamRequest.on("error", () => {
      receipt.upstreamErrors++;
      if (!res.headersSent) reject(res, 502, "upstream failed");
      else res.destroy();
    });
    upstreamRequest.end(body);
  });
});

server.maxConnections = maxConcurrent;
server.maxHeadersCount = 32;
server.maxRequestsPerSocket = 1;
server.headersTimeout = 5000;
server.requestTimeout = requestTimeoutMs;
server.keepAliveTimeout = 1000;
server.listen(Number(match[2]), match[1], 1, () => {
  fs.writeFileSync(receiptPath + ".ready", "ready\n", {encoding: "utf8", mode: 0o600, flag: "wx"});
});
server.on("error", error => { process.stderr.write(String(error) + "\n"); process.exit(1); });
process.on("SIGTERM", () => shutdown(false));
process.on("SIGINT", () => shutdown(false));
doneTimer = setInterval(() => {
  if (active === 0 && fs.existsSync(donePath)) shutdown(false);
}, 250);
setTimeout(() => shutdown(true), deadlineSeconds * 1000).unref();
