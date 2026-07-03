import { generateKeyPairSync, createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createAuthenticator } from "../src/auth/index.js";
import type { LevitateConfig } from "../src/config.js";
import type { Logger } from "../src/logging.js";
import type { StdioMcpBackend } from "../src/mcp/backend.js";
import { loadAuthorizationServerKeys } from "../src/oauth/as/keys.js";
import { createOAuthAuthorizationServer } from "../src/oauth/as/routes.js";
import { createApp } from "../src/server.js";

const logger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

const backend = {
  async listTools() {
    return {
      tools: [{
        name: "search",
        inputSchema: { type: "object", properties: {} },
      }],
    };
  },
  async callTool() {
    return { content: [{ type: "text", text: "ok" }] };
  },
} as unknown as StdioMcpBackend;

describe("oauth authorization server facade", () => {
  it("serves authorization server metadata and jwks", async () => {
    const context = await createTestApp();

    const metadata = await context.app.fetch(new Request("http://localhost/.well-known/oauth-authorization-server"));
    await expect(metadata.json()).resolves.toEqual({
      issuer: "https://levitate.example.com",
      authorization_endpoint: "https://levitate.example.com/oauth/authorize",
      token_endpoint: "https://levitate.example.com/oauth/token",
      registration_endpoint: "https://levitate.example.com/oauth/register",
      jwks_uri: "https://levitate.example.com/.well-known/jwks.json",
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["brain:read", "brain:write"],
    });

    const jwks = await context.app.fetch(new Request("http://localhost/.well-known/jwks.json"));
    const body = await jwks.json() as { keys: Array<{ kid?: string; kty?: string }> };
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0].kid).toBe("test-key");
    expect(body.keys[0].kty).toBe("RSA");
  });

  it("rejects missing or invalid signing keys", async () => {
    const context = createTestConfig();
    context.config.oauth.as.keys.private_key_file = join(context.dir, "missing.pem");
    await expect(loadAuthorizationServerKeys(context.config)).rejects.toThrow(
      "failed to load oauth authorization server signing key",
    );

    writeFileSync(context.privateKeyFile, "not a private key", "utf8");
    context.config.oauth.as.keys.private_key_file = context.privateKeyFile;
    await expect(loadAuthorizationServerKeys(context.config)).rejects.toThrow(
      "failed to load oauth authorization server signing key",
    );
  });

  it("registers a ChatGPT-style public client and persists it", async () => {
    const context = await createTestApp();
    const response = await registerClient(context.app);
    const client = await response.json() as { client_id: string; client_secret?: string };

    expect(response.status).toBe(201);
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeUndefined();
    expect(context.clientStoreText()).toContain(client.client_id);
  });

  it("rejects invalid dynamic client registration metadata", async () => {
    const context = await createTestApp();

    await expectRegistrationError(context.app, {
      redirect_uris: ["http://chatgpt.com/connector/oauth/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, "invalid_redirect_uri");

    await expectRegistrationError(context.app, {
      redirect_uris: ["https://example.com/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, "invalid_redirect_uri");

    await expectRegistrationError(context.app, {
      redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
    }, "invalid_client_metadata");

    await expectRegistrationError(context.app, {
      redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
      grant_types: ["client_credentials"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, "invalid_client_metadata");

    await expectRegistrationError(context.app, {
      redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: "brain:admin",
    }, "invalid_client_metadata");
  });

  it("requires redirect prefixes to match origin and path boundaries", async () => {
    const context = await createTestApp({ allowedRedirectUriPrefixes: ["https://chatgpt.com/connector/oauth"] });

    await expectRegistrationError(context.app, {
      redirect_uris: ["https://chatgpt.com.evil.example/connector/oauth/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, "invalid_redirect_uri");

    await expectRegistrationError(context.app, {
      redirect_uris: ["https://chatgpt.com/connector/oauthish/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, "invalid_redirect_uri");

    const response = await registerClient(context.app);
    expect(response.status).toBe(201);
  });

  it("rejects invalid authorization requests", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);
    const challenge = pkceChallenge("verifier");

    const unknown = await authorize(context.app, {
      client_id: "missing",
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: challenge,
      resource: "https://levitate.example.com/brain/mcp",
    });
    expect(unknown.status).toBe(400);

    const wrongRedirect = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/other",
      code_challenge: challenge,
      resource: "https://levitate.example.com/brain/mcp",
    });
    expect(wrongRedirect.status).toBe(400);

    const missingPkce = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      resource: "https://levitate.example.com/brain/mcp",
    });
    expect(missingPkce.status).toBe(302);
    expect(missingPkce.headers.get("location")).toContain("error=invalid_request");

    const wrongResource = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: challenge,
      resource: "https://levitate.example.com/wrong/mcp",
    });
    expect(wrongResource.headers.get("location")).toContain("error=invalid_target");

    const badScope = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: challenge,
      resource: "https://levitate.example.com/brain/mcp",
      scope: "brain:admin",
    });
    expect(badScope.headers.get("location")).toContain("error=invalid_scope");
  });

  it("authorizes with pkce and preserves state", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);
    const response = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge("verifier"),
      resource: "https://levitate.example.com/brain/mcp",
      state: "state-1",
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe("https://chatgpt.com/connector/oauth/callback");
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe("state-1");
  });

  it("exchanges an authorization code for an RS256 access token", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);
    const verifier = "verifier";
    const code = await authorizeAndGetCode(context.app, client.client_id, verifier);

    const response = await token(context.app, {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      client_id: client.client_id,
      code_verifier: verifier,
      resource: "https://levitate.example.com/brain/mcp",
    });
    const body = await response.json() as { access_token: string; token_type: string; expires_in: number; scope: string };

    expect(response.status).toBe(200);
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe("brain:read");
    const auth = await context.authenticator.authenticate(new Request("http://localhost/mcp", {
      headers: { authorization: `Bearer ${body.access_token}` },
    }));
    expect(auth).toMatchObject({
      kind: "levitate",
      subject: "local-user",
      clientId: client.client_id,
      scopes: ["brain:read"],
      audience: "https://levitate.example.com/brain/mcp",
      issuer: "https://levitate.example.com",
    });
  });

  it("rejects invalid token exchanges", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);
    const otherClient = await registerAndReadClient(context.app);
    const verifier = "verifier";
    const code = await authorizeAndGetCode(context.app, client.client_id, verifier);

    await expectTokenError(context.app, { code, client_id: otherClient.client_id, code_verifier: verifier });
    await expectTokenError(context.app, {
      code,
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/other",
      code_verifier: verifier,
    });
    await expectTokenError(context.app, {
      code,
      client_id: client.client_id,
      resource: "https://levitate.example.com/wrong/mcp",
      code_verifier: verifier,
    });
    await expectTokenError(context.app, {
      code,
      client_id: client.client_id,
      code_verifier: "wrong-verifier",
    });

    const success = await token(context.app, validTokenRequest(code, client.client_id, verifier));
    expect(success.status).toBe(200);
    await expectTokenError(context.app, { code, client_id: client.client_id, code_verifier: verifier });
  });

  it("rejects expired authorization codes", async () => {
    const context = await createTestApp({ codeTtlSeconds: 1 });
    const client = await registerAndReadClient(context.app);
    const code = await authorizeAndGetCode(context.app, client.client_id, "verifier");

    await new Promise((resolve) => setTimeout(resolve, 1100));
    await expectTokenError(context.app, { code, client_id: client.client_id, code_verifier: "verifier" });
  });

  it("accepts Levitate-issued JWTs on the MCP route", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);
    const code = await authorizeAndGetCode(context.app, client.client_id, "verifier");
    const issued = await token(context.app, validTokenRequest(code, client.client_id, "verifier"));
    const body = await issued.json() as { access_token: string };

    const response = await context.app.fetch(new Request("http://localhost/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${body.access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "test-client", version: "0.1.0" },
        },
      }),
    }));

    expect(response.status).not.toBe(401);
  });

  it("rejects invalid Levitate JWTs on the MCP route", async () => {
    const context = await createTestApp();
    const opaque = await context.app.fetch(mcpRequest("opaque"));
    expect(opaque.status).toBe(401);
    await expect(opaque.json()).resolves.toEqual({ error: "auth failed" });

    const unsigned = `${Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")}.${
      Buffer.from(JSON.stringify({
        iss: "https://levitate.example.com",
        sub: "local-user",
        aud: "https://levitate.example.com/brain/mcp",
        client_id: "client",
        scope: "brain:read",
      })).toString("base64url")
    }.`;
    expect((await context.app.fetch(mcpRequest(unsigned))).status).toBe(401);

    const wrongIssuer = await signToken(context, { issuer: "https://wrong.example.com" });
    expect((await context.app.fetch(mcpRequest(wrongIssuer))).status).toBe(401);

    const wrongAudience = await signToken(context, { audience: "https://levitate.example.com/wrong/mcp" });
    expect((await context.app.fetch(mcpRequest(wrongAudience))).status).toBe(401);

    const expired = await signToken(context, { expiresIn: "-1s" });
    expect((await context.app.fetch(mcpRequest(expired))).status).toBe(401);
  });
});

async function createTestApp(options: TestOptions = {}) {
  const context = createTestConfig(options);
  const keys = await loadAuthorizationServerKeys(context.config);
  const oauthAuthorizationServer = createOAuthAuthorizationServer(context.config, keys, logger);
  const authenticator = createAuthenticator(context.config, keys);
  const app = createApp({
    config: context.config,
    authenticator,
    backend,
    logger,
    oauthAuthorizationServer,
  });

  return {
    ...context,
    app,
    keys,
    authenticator,
    clientStoreText: () => JSON.stringify(JSON.parse(readFileSync(context.clientStoreFile, "utf8"))),
  };
}

interface TestOptions {
  allowedRedirectUriPrefixes?: string[];
  codeTtlSeconds?: number;
}

function createTestConfig(options: TestOptions = {}) {
  const dir = mkdtempSync(join(tmpdir(), "levitate-oauth-as-"));
  const privateKeyFile = join(dir, "private.pem");
  const clientStoreFile = join(dir, "clients.json");
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  writeFileSync(privateKeyFile, privateKey.export({ type: "pkcs8", format: "pem" }), "utf8");

  const config: LevitateConfig = {
    server: {
      name: "test",
      host: "127.0.0.1",
      port: 8787,
      log_level: "info",
      mcp_path: "/mcp",
    },
    stdio: {
      command: "node",
      args: [],
    },
    env: {},
    instructions: {},
    auth: {
      mode: "levitate",
    },
    oauth: {
      resource: {
        enabled: true,
        resource: "https://levitate.example.com/brain/mcp",
        authorization_servers: ["https://levitate.example.com"],
        scopes_supported: ["brain:read", "brain:write"],
      },
      as: {
        enabled: true,
        issuer: "https://levitate.example.com",
        subject: "local-user",
        approval: "auto",
        allowed_redirect_uri_prefixes: options.allowedRedirectUriPrefixes ?? ["https://chatgpt.com/connector/oauth/"],
        scopes_supported: ["brain:read", "brain:write"],
        default_scopes: ["brain:read"],
        access_token_ttl_seconds: 3600,
        authorization_code_ttl_seconds: options.codeTtlSeconds ?? 300,
        client_store_file: clientStoreFile,
        keys: {
          private_key_file: privateKeyFile,
          key_id: "test-key",
        },
      },
    },
    tools: {
      allow: ["search"],
      deny: [],
    },
  };

  return {
    config,
    dir,
    privateKeyFile,
    clientStoreFile,
  };
}

function registerClient(app: Awaited<ReturnType<typeof createTestApp>>["app"]) {
  return app.fetch(new Request("http://localhost/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "ChatGPT Connector",
      redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  }));
}

async function registerAndReadClient(app: Awaited<ReturnType<typeof createTestApp>>["app"]) {
  const response = await registerClient(app);
  return await response.json() as { client_id: string };
}

async function expectRegistrationError(
  app: Awaited<ReturnType<typeof createTestApp>>["app"],
  body: unknown,
  error: string,
) {
  const response = await app.fetch(new Request("http://localhost/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }));
  expect(response.status).toBe(400);
  await expect(response.json()).resolves.toEqual({ error });
}

function authorize(
  app: Awaited<ReturnType<typeof createTestApp>>["app"],
  params: Record<string, string | undefined>,
) {
  const url = new URL("http://localhost/oauth/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("code_challenge_method", "S256");
  for (const [key, value] of Object.entries(params)) {
    if (value) url.searchParams.set(key, value);
  }
  return app.fetch(new Request(url));
}

async function authorizeAndGetCode(
  app: Awaited<ReturnType<typeof createTestApp>>["app"],
  clientId: string,
  verifier: string,
) {
  const response = await authorize(app, {
    client_id: clientId,
    redirect_uri: "https://chatgpt.com/connector/oauth/callback",
    code_challenge: pkceChallenge(verifier),
    resource: "https://levitate.example.com/brain/mcp",
  });
  const location = new URL(response.headers.get("location") ?? "");
  return location.searchParams.get("code") ?? "";
}

function token(app: Awaited<ReturnType<typeof createTestApp>>["app"], params: Record<string, string>) {
  return app.fetch(new Request("http://localhost/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
  }));
}

async function expectTokenError(
  app: Awaited<ReturnType<typeof createTestApp>>["app"],
  overrides: { code: string; client_id?: string; redirect_uri?: string; resource?: string; code_verifier?: string },
) {
  const response = await token(app, validTokenRequest(
    overrides.code,
    overrides.client_id ?? "client",
    overrides.code_verifier ?? "verifier",
    overrides.redirect_uri,
    overrides.resource,
  ));
  expect(response.status).toBe(400);
  await expect(response.json()).resolves.toEqual({ error: "invalid_grant" });
}

function validTokenRequest(
  code: string,
  clientId: string,
  verifier: string,
  redirectUri = "https://chatgpt.com/connector/oauth/callback",
  resource = "https://levitate.example.com/brain/mcp",
) {
  return {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: verifier,
    resource,
  };
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function mcpRequest(token: string): Request {
  return new Request("http://localhost/mcp", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
}

async function signToken(
  context: Awaited<ReturnType<typeof createTestApp>>,
  overrides: { issuer?: string; audience?: string; expiresIn?: string } = {},
): Promise<string> {
  return new SignJWT({ client_id: "client", scope: "brain:read" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key", typ: "JWT" })
    .setIssuer(overrides.issuer ?? "https://levitate.example.com")
    .setSubject("local-user")
    .setAudience(overrides.audience ?? "https://levitate.example.com/brain/mcp")
    .setIssuedAt()
    .setExpirationTime(overrides.expiresIn ?? "1h")
    .sign(context.keys.privateKey);
}
