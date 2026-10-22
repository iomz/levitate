// Run from /app in a freshly built image; no app state or credentials needed.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import https from "node:https";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createRemoteJWKSet } from "jose";

const { loadConfig } = await import(pathToFileURL(resolve("dist/src/config.js")));
const { CimdClientResolver } = await import(pathToFileURL(resolve("dist/src/oauth/as/cimd.js")));
assert.notEqual(process.env.NODE_TLS_REJECT_UNAUTHORIZED, "0");
for (const name of ["NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "SSL_CERT_FILE", "SSL_CERT_DIR"]) {
  assert.ok(!process.env[name], `Unexpected trust override: ${name}`);
}

// Only chain/trust failures count. DNS, timeout, refused connections, expired
// leaves and hostname mismatches are not evidence of this remediation.
const trustErrors = new Set([
  "CERT_REJECTED", "CERT_REVOKED", "CERT_UNTRUSTED",
  "CERT_SIGNATURE_FAILURE", "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "SELF_SIGNED_CERT_IN_CHAIN",
]);
function errorCodes(error) {
  const codes = [];
  for (let cause = error; cause; cause = cause.cause) {
    if (cause.code) codes.push(cause.code);
    if (cause.errors) codes.push(...cause.errors.flatMap(errorCodes));
  }
  return codes;
}
async function mustReject(label, request) {
  let failure;
  try {
    await request();
  } catch (error) {
    failure = error;
  }
  const codes = errorCodes(failure);
  assert.ok(codes.some((code) => trustErrors.has(code)),
    `${label}: expected certificate trust failure, got ${codes.join(",") || failure || "TLS accepted"}`);
  console.log(`PASS ${label}: ${codes.join(",")}`);
}

const systemCa = readFileSync("/etc/ssl/certs/ca-certificates.crt");
function systemHttps(url) {
  return new Promise((resolveResponse, reject) => {
    const request = https.get(url, { ca: systemCa, timeout: 15_000 }, (response) => {
      response.resume();
      resolveResponse(response.statusCode);
    });
    request.on("timeout", () => request.destroy(new Error("HTTPS timeout")));
    request.on("error", reject);
  });
}

const config = await loadConfig("config/fake-stdio.toml");
const logger = { debug() {}, info() {}, warn() {}, error() {} };
for (const host of ["dv-g3b-emudhra", "dv-g3b-aaa-emudhra"]) {
  const url = `https://${host}.we-have-a-problem.com/`;
  await mustReject(`fetch ${url}`, async () => {
    const response = await fetch(url, { signal: AbortSignal.timeout(15_000), redirect: "error" });
    await response.body?.cancel();
  });
  await mustReject(`JOSE JWKS ${url}`, () => createRemoteJWKSet(new URL(url)).reload());

  // Exercise the real CIMD resolver. Observe and rethrow the original native
  // fetch error because the resolver intentionally hides TLS details in logs.
  config.oauth.as.cimd.enabled = true;
  config.oauth.as.cimd.allowed_client_id_prefixes = [url];
  let fetchFailure;
  let calls = 0;
  const resolver = new CimdClientResolver(config, logger, async (...args) => {
    calls += 1;
    try {
      return await fetch(...args);
    } catch (error) {
      fetchFailure = error;
      throw error;
    }
  });
  await mustReject(`CIMD ${url}`, async () => {
    assert.equal(await resolver.get(`${url}client.json`), undefined);
    assert.equal(calls, 1, "CIMD must reach the TLS transport");
    if (fetchFailure) throw fetchFailure;
  });
  await mustReject(`system CA HTTPS ${url}`, () => systemHttps(url));
}

const normal = "https://example.com/";
const response = await fetch(normal, { signal: AbortSignal.timeout(15_000), redirect: "error" });
assert.equal(response.status, 200);
await response.body?.cancel();
assert.equal(await systemHttps(normal), 200);
console.log(`PASS normal HTTPS ${normal}: 200 (fetch and system CA)`);
