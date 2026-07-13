package observatory

// modelRelayScript is copied into the disposable guest and run only inside a
// hardened control-plane unit. It accepts one exact OpenAI-compatible route,
// validates JSON and model identity, forwards only fixed headers to one pinned
// upstream URL, and emits a body-free bounded receipt.
const modelRelayScript = `import fs from "node:fs";
import http from "node:http";
import https from "node:https";

if (process.argv.length !== 5) throw new Error("usage: model-relay.mjs RUNTIME_JSON RECEIPT LANE");
const runtime = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const receiptPath = process.argv[3];
const lane = process.argv[4];
if (lane !== "baseline" && lane !== "exercise") throw new Error("invalid relay lane");
const p = runtime.modelRelay;
if (!p || p.version !== "observatory.model-relay.v1" || p.allowedMethod !== "POST") throw new Error("invalid relay policy");
for (const key of ["maxRequests", "maxRequestBytes", "maxResponseBytes", "maxTotalBytes", "maxConcurrentRequests", "requestTimeoutSeconds", "deadlineSeconds", "receiptMaxBytes"]) {
  if (!Number.isSafeInteger(p[key]) || p[key] < 1) throw new Error("invalid relay numeric policy: " + key);
}
if (typeof p.policySha256 !== "string" || !/^sha256:[a-f0-9]{64}$/.test(p.policySha256)) throw new Error("invalid relay policy digest");
if (typeof p.expectedModel !== "string" || p.expectedModel.length === 0 || typeof p.allowedPath !== "string" || !p.allowedPath.startsWith("/")) throw new Error("invalid relay route policy");
const listen = new URL("http://" + p.listenAddress);
const upstream = new URL(p.upstreamUrl);
if (!listen.hostname.startsWith("127.") || !["http:", "https:"].includes(upstream.protocol) || upstream.pathname !== p.allowedPath || upstream.search || upstream.hash) throw new Error("invalid relay endpoint policy");
if (upstream.hostname === listen.hostname && upstream.port === listen.port) throw new Error("relay upstream loops to itself");

const receipt = {
  lane,
  policySha256: p.policySha256,
  acceptedRequests: 0,
  rejectedRequests: 0,
  requestBytes: 0,
  responseBytes: 0,
  peakConcurrency: 0,
  truncated: false,
  deadlineHit: false,
  upstreamErrorCount: 0,
};
let active = 0;
let shuttingDown = false;
let receiptWritten = false;

function reject(res, status, message) {
  if (!res.headersSent) {
    res.writeHead(status, {"content-type": "application/json", "connection": "close"});
  }
  res.end(JSON.stringify({error: {message, type: "observatory_model_relay"}}));
  if (receipt.acceptedRequests + receipt.rejectedRequests >= p.maxRequests) setImmediate(() => shutdown(false));
}

function finishReceipt() {
  if (receiptWritten) return;
  const data = JSON.stringify(receipt) + "\n";
  if (Buffer.byteLength(data) > p.receiptMaxBytes) throw new Error("model relay receipt exceeds bound");
  fs.writeFileSync(receiptPath, data, {encoding: "utf8", mode: 0o600, flag: "wx"});
  receiptWritten = true;
}

function shutdown(deadlineHit = false) {
  if (shuttingDown) return;
  shuttingDown = true;
  receipt.deadlineHit ||= deadlineHit;
  server.close(() => {
    finishReceipt();
    process.exit(0);
  });
  setTimeout(() => {
    receipt.truncated ||= active > 0;
    finishReceipt();
    process.exit(0);
  }, 2000).unref();
}

const server = http.createServer((req, res) => {
  if (shuttingDown) {
    res.writeHead(503, {"connection": "close"});
    return res.end();
  }
  if (receipt.acceptedRequests + receipt.rejectedRequests >= p.maxRequests) {
    res.writeHead(429, {"connection": "close"});
    res.end();
    return shutdown(false);
  }
  // Reserve every parsed HTTP request immediately. A request remains rejected
  // unless it passes the entire policy and is promoted to accepted below.
  receipt.rejectedRequests++;
  if (req.method !== p.allowedMethod) return reject(res, 405, "method is not allowed");
  if (req.url !== p.allowedPath) return reject(res, 404, "path is not allowed");
  if (String(req.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase() !== "application/json") return reject(res, 415, "content type must be application/json");
  if (active >= p.maxConcurrentRequests) return reject(res, 429, "relay concurrency cap reached");
  const declared = Number(req.headers["content-length"] || 0);
  if (!Number.isSafeInteger(declared) || declared < 0 || declared > p.maxRequestBytes || receipt.requestBytes + receipt.responseBytes + declared > p.maxTotalBytes) {
    return reject(res, 413, "request exceeds relay byte cap");
  }

  active++;
  receipt.peakConcurrency = Math.max(receipt.peakConcurrency, active);
  let released = false;
  let upstreamRequestRef;
  let wallTimer;
  const release = () => {
    if (released) return;
    released = true;
    if (!res.writableEnded) upstreamRequestRef?.destroy(new Error("relay client disconnected"));
    clearTimeout(wallTimer);
    active--;
    if (receipt.acceptedRequests + receipt.rejectedRequests >= p.maxRequests) setImmediate(() => shutdown(false));
  };
  res.once("close", release);
  wallTimer = setTimeout(() => {
    receipt.truncated = true;
    upstreamRequestRef?.destroy(new Error("request wall-clock deadline exceeded"));
    if (!res.headersSent) reject(res, 408, "request timed out");
    else res.destroy();
    req.destroy();
  }, p.requestTimeoutSeconds * 1000);
  const chunks = [];
  let bytes = 0;
  req.setTimeout(p.requestTimeoutSeconds * 1000, () => {
    receipt.truncated = true;
    reject(res, 408, "request timed out");
    req.destroy();
  });
  req.on("data", chunk => {
    bytes += chunk.length;
    if (bytes > p.maxRequestBytes || receipt.requestBytes + receipt.responseBytes + bytes > p.maxTotalBytes) {
      receipt.truncated = true;
      reject(res, 413, "request exceeds relay byte cap");
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });
  req.on("error", () => release());
  req.on("end", () => {
    if (res.writableEnded) return release();
    let body;
    try {
      body = Buffer.concat(chunks, bytes);
      const parsed = JSON.parse(body.toString("utf8"));
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || parsed.model !== p.expectedModel) throw new Error("model mismatch");
    } catch {
      return reject(res, 400, "request must be valid JSON for the configured model");
    }
    if (receipt.requestBytes + receipt.responseBytes + body.length > p.maxTotalBytes) {
      return reject(res, 429, "relay traffic cap reached");
    }
    receipt.rejectedRequests--;
    receipt.acceptedRequests++;
    receipt.requestBytes += body.length;
    const transport = upstream.protocol === "https:" ? https : http;
    const upstreamRequest = transport.request(upstream, {
      method: "POST",
      agent: false,
      headers: {
        "accept": "application/json, text/event-stream",
        "authorization": "Bearer local",
        "content-type": "application/json",
        "content-length": String(body.length),
        "connection": "close",
        "user-agent": "clawhub-observatory-model-relay/1",
      },
      timeout: p.requestTimeoutSeconds * 1000,
    }, upstreamResponse => {
      const contentType = String(upstreamResponse.headers["content-type"] || "application/json").slice(0, 256);
      res.writeHead(upstreamResponse.statusCode || 502, {"content-type": contentType, "connection": "close", "x-observatory-model-relay": "bounded"});
      let responseBytes = 0;
      upstreamResponse.on("data", chunk => {
        if (responseBytes + chunk.length > p.maxResponseBytes || receipt.requestBytes + receipt.responseBytes + chunk.length > p.maxTotalBytes) {
          receipt.truncated = true;
          upstreamResponse.destroy();
          res.destroy();
          return;
        }
        responseBytes += chunk.length;
        receipt.responseBytes += chunk.length;
        if (!res.write(chunk)) upstreamResponse.pause();
      });
      res.on("drain", () => upstreamResponse.resume());
      upstreamResponse.on("end", () => res.end());
      upstreamResponse.on("error", () => {
        receipt.upstreamErrorCount++;
        res.destroy();
      });
    });
    upstreamRequestRef = upstreamRequest;
    upstreamRequest.on("timeout", () => {
      receipt.upstreamErrorCount++;
      upstreamRequest.destroy(new Error("upstream timeout"));
    });
    upstreamRequest.on("error", () => {
      receipt.upstreamErrorCount++;
      if (!res.headersSent) reject(res, 502, "upstream request failed");
      else res.destroy();
    });
    upstreamRequest.end(body);
  });
});

server.maxConnections = p.maxConcurrentRequests;
server.maxHeadersCount = 32;
server.maxRequestsPerSocket = 1;
server.headersTimeout = Math.min(5000, p.requestTimeoutSeconds * 1000);
server.requestTimeout = p.requestTimeoutSeconds * 1000;
server.keepAliveTimeout = 1000;
server.on("clientError", (_error, socket) => {
  socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
});
server.listen(Number(listen.port), listen.hostname, 1, () => {
  fs.writeFileSync(receiptPath + ".ready", p.policySha256 + "\n", {encoding: "utf8", mode: 0o600, flag: "wx"});
});
server.on("error", error => {
  process.stderr.write(String(error) + "\n");
  process.exit(1);
});
process.on("SIGTERM", () => shutdown(false));
process.on("SIGINT", () => shutdown(false));
setTimeout(() => shutdown(true), p.deadlineSeconds * 1000).unref();
`
