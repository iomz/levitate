import { generateKeyPairSync, type KeyObject } from "node:crypto";
import {
  createLocalJWKSet,
  exportJWK,
  SignJWT,
  type JWK,
  type JWTPayload,
} from "jose";
import { describe, expect, it } from "vitest";
import { OidcJwtAuthenticator } from "../src/auth/oidc.js";
import type { LevitateConfig } from "../src/config.js";
import type { Logger } from "../src/logging.js";
import { createApp } from "../src/server.js";

const issuer = "https://auth.example.test/";
const audience = "https://levitate.example.test";
const now = new Date("2027-01-15T08:00:00.000Z");
const nowSeconds = Math.floor(now.getTime() / 1000);

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const jwk = {
  ...await exportJWK(publicKey),
  kid: "test-key",
  alg: "RS256",
  use: "sig",
} satisfies JWK;

const config: LevitateConfig = {
  server: {
    name: "test",
    host: "127.0.0.1",
    port: 8787,
    log_level: "info",
  },
  stdio: {
    command: "node",
    args: [],
  },
  env: {},
  instructions: {},
  auth: {
    mode: "oidc",
    issuer,
    audience,
    jwks_uri: "https://auth.example.test/.well-known/jwks.json",
    allowed_subjects: [],
    allowed_emails: [],
  },
  tools: {
    deny: [],
  },
};

const logger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

describe("oidc jwt auth", () => {
  it("accepts a valid Auth0-style RS256 JWT", async () => {
    const auth = createAuth();
    const token = await signJwt({
      iss: issuer,
      sub: "client-id@clients",
      aud: audience,
      exp: nowSeconds + 60,
    });

    await expect(auth.authenticate(requestWithToken(token))).resolves.toEqual({
      subject: "client-id@clients",
    });
  });

  it("accepts tokens with a past not-before claim", async () => {
    const auth = createAuth();
    const token = await signJwt({
      iss: issuer,
      sub: "client-id@clients",
      aud: audience,
      exp: nowSeconds + 60,
      nbf: nowSeconds - 60,
    });

    await expect(auth.authenticate(requestWithToken(token))).resolves.toEqual({
      subject: "client-id@clients",
    });
  });

  it("accepts an audience array containing configured audience", async () => {
    const auth = createAuth();
    const token = await signJwt({
      iss: issuer,
      sub: "client-id@clients",
      aud: ["https://other.example", audience],
      exp: nowSeconds + 60,
    });

    await expect(auth.authenticate(requestWithToken(token))).resolves.toEqual({
      subject: "client-id@clients",
    });
  });

  it("rejects wrong issuer", async () => {
    const auth = createAuth();
    const token = await signJwt({
      iss: "https://wrong.example/",
      sub: "client-id@clients",
      aud: audience,
      exp: nowSeconds + 60,
    });

    await expect(auth.authenticate(requestWithToken(token))).rejects.toThrow("invalid oidc token");
  });

  it("rejects wrong audience", async () => {
    const auth = createAuth();
    const token = await signJwt({
      iss: issuer,
      sub: "client-id@clients",
      aud: "https://wrong.example",
      exp: nowSeconds + 60,
    });

    await expect(auth.authenticate(requestWithToken(token))).rejects.toThrow("invalid oidc token");
  });

  it("rejects expired tokens", async () => {
    const auth = createAuth();
    const token = await signJwt({
      iss: issuer,
      sub: "client-id@clients",
      aud: audience,
      exp: nowSeconds,
    });

    await expect(auth.authenticate(requestWithToken(token))).rejects.toThrow("invalid oidc token");
  });

  it("rejects tokens before not-before time", async () => {
    const auth = createAuth();
    const token = await signJwt({
      iss: issuer,
      sub: "client-id@clients",
      aud: audience,
      exp: nowSeconds + 60,
      nbf: nowSeconds + 1,
    });

    await expect(auth.authenticate(requestWithToken(token))).rejects.toThrow("invalid oidc token");
  });

  it("rejects unsupported algorithms", async () => {
    const auth = createAuth();
    const token = await new SignJWT({
      iss: issuer,
      sub: "client-id@clients",
      aud: audience,
      exp: nowSeconds + 60,
    })
      .setProtectedHeader({ alg: "HS256", typ: "JWT", kid: "test-key" })
      .sign(new TextEncoder().encode("secret"));

    await expect(auth.authenticate(requestWithToken(token))).rejects.toThrow("invalid oidc token");
  });

  it("rejects missing authorization header", async () => {
    const auth = createAuth();

    await expect(auth.authenticate(new Request("http://localhost/mcp"))).rejects.toThrow(
      "missing authorization header",
    );
  });

  it("rejects malformed authorization header", async () => {
    const auth = createAuth();

    await expect(auth.authenticate(new Request("http://localhost/mcp", {
      headers: { authorization: "Bearer" },
    }))).rejects.toThrow("invalid authorization scheme");
  });

  it("rejects non-Bearer authorization scheme", async () => {
    const auth = createAuth();

    await expect(auth.authenticate(new Request("http://localhost/mcp", {
      headers: { authorization: "Basic abc" },
    }))).rejects.toThrow("invalid authorization scheme");
  });

  it("accepts allowed subjects", async () => {
    const auth = createAuth({
      allowed_subjects: ["allowed-subject"],
    });
    const token = await signJwt({
      iss: issuer,
      sub: "allowed-subject",
      aud: audience,
      exp: nowSeconds + 60,
    });

    await expect(auth.authenticate(requestWithToken(token))).resolves.toEqual({
      subject: "allowed-subject",
    });
  });

  it("rejects unlisted subjects", async () => {
    const auth = createAuth({
      allowed_subjects: ["allowed-subject"],
    });
    const token = await signJwt({
      iss: issuer,
      sub: "blocked-subject",
      aud: audience,
      exp: nowSeconds + 60,
    });

    await expect(auth.authenticate(requestWithToken(token))).rejects.toThrow("jwt subject not allowed");
  });

  it("accepts allowed emails", async () => {
    const auth = createAuth({
      allowed_emails: ["allowed@example.com"],
    });
    const token = await signJwt({
      iss: issuer,
      sub: "client-id@clients",
      email: "allowed@example.com",
      aud: audience,
      exp: nowSeconds + 60,
    });

    await expect(auth.verifyToken(token)).resolves.toEqual({
      sub: "client-id@clients",
      email: "allowed@example.com",
    });
  });

  it("rejects unlisted emails", async () => {
    const auth = createAuth({
      allowed_emails: ["allowed@example.com"],
    });
    const token = await signJwt({
      iss: issuer,
      sub: "client-id@clients",
      email: "blocked@example.com",
      aud: audience,
      exp: nowSeconds + 60,
    });

    await expect(auth.authenticate(requestWithToken(token))).rejects.toThrow("jwt email not allowed");
  });

  it("returns a generic endpoint error for invalid oidc tokens", async () => {
    const app = createApp({
      config,
      authenticator: createAuth(),
      backend: {} as never,
      logger,
    });
    const token = await signJwt({
      iss: issuer,
      sub: "client-id@clients",
      aud: "https://wrong.example",
      exp: nowSeconds + 60,
    });

    const response = await app.fetch(new Request("http://localhost/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }));

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: "auth failed" });
  });

  it("returns a generic endpoint error for malformed authorization headers", async () => {
    const app = createApp({
      config,
      authenticator: createAuth(),
      backend: {} as never,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/mcp", {
      method: "POST",
      headers: {
        authorization: "Basic secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }));

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: "auth failed" });
  });
});

function createAuth(overrides: {
  allowed_subjects?: string[];
  allowed_emails?: string[];
} = {}): OidcJwtAuthenticator {
  return new OidcJwtAuthenticator({
    issuer,
    audience,
    jwks_uri: "https://auth.example.test/.well-known/jwks.json",
    ...overrides,
  }, createLocalJWKSet({ keys: [jwk] }), now);
}

function requestWithToken(token: string): Request {
  return new Request("http://localhost/mcp", {
    headers: { authorization: `Bearer ${token}` },
  });
}

async function signJwt(claims: JWTPayload, key: KeyObject = privateKey): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "test-key" })
    .sign(key);
}
