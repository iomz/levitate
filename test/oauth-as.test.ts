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
import { runOAuthClientsCommand } from "../src/oauth/as/clients-cli.js";
import { loadAuthorizationServerKeys } from "../src/oauth/as/keys.js";
import { createOAuthAuthorizationServer } from "../src/oauth/as/routes.js";
import { JsonClientStore } from "../src/oauth/as/store.js";
import { CimdClientResolver } from "../src/oauth/as/cimd.js";
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

const validVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
const otherValidVerifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

describe("oauth authorization server facade", () => {
  it("emits safe structured audit fields without raw registration metadata", async () => {
    const entries: Record<string, unknown>[] = [];
    const auditLogger: Logger = {
      debug: () => {},
      info: (_message, fields) => entries.push(fields ?? {}),
      warn: (_message, fields) => entries.push(fields ?? {}),
      error: () => {},
    };
    const context = await createTestApp({ logger: auditLogger });

    await context.app.fetch(new Request("http://localhost/oauth/register", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-request-id": "audit-test",
      },
      body: JSON.stringify({
        client_name: "sensitive-client-name",
        redirect_uris: ["https://forbidden.example.com/callback"],
      }),
    }));

    expect(entries).toContainEqual(expect.objectContaining({
      event: "client_registration",
      outcome: "rejected",
      requestId: "audit-test",
    }));
    expect(JSON.stringify(entries)).not.toContain("sensitive-client-name");
    expect(JSON.stringify(entries)).not.toContain("forbidden.example.com");
  });

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

  it("omits registration metadata and rejects registration when dcr is disabled", async () => {
    const context = await createTestApp({ dcrEnabled: false });

    const metadata = await context.app.fetch(new Request("http://localhost/.well-known/oauth-authorization-server"));
    const metadataBody = await metadata.json() as { registration_endpoint?: string };
    expect(metadataBody.registration_endpoint).toBeUndefined();

    const response = await registerClient(context.app);
    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({ error: "registration_disabled" });
  });

  it("advertises and resolves allowlisted CIMD public clients", async () => {
    const clientId = "https://chatgpt.com/oauth/levitate-client.json";
    let fetchCount = 0;
    const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
      fetchCount += 1;
      expect(String(input)).toBe(clientId);
      expect(init?.redirect).toBe("error");
      return new Response(JSON.stringify({
        client_id: clientId,
        client_name: "ChatGPT",
        redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
      }), {
        headers: {
          "content-type": "application/json",
          "cache-control": "max-age=60",
        },
      });
    }) as typeof fetch;
    const context = await createTestApp({
      cimdEnabled: true,
      cimdAllowedClientIdPrefixes: ["https://chatgpt.com/oauth/"],
      dcrEnabled: false,
      fetchImpl,
    });

    const metadata = await context.app.fetch(new Request("http://localhost/.well-known/oauth-authorization-server"));
    await expect(metadata.json()).resolves.toEqual(expect.objectContaining({
      client_id_metadata_document_supported: true,
    }));

    const code = await authorizeAndGetCode(context.app, clientId, validVerifier);
    expect(code).not.toBe("");
    const response = await token(context.app, validTokenRequest(code, clientId, validVerifier));
    expect(response.status).toBe(200);
    expect(fetchCount).toBe(1);
  });

  it("does not fetch CIMD client IDs outside configured prefixes", async () => {
    let fetched = false;
    const context = await createTestApp({
      cimdEnabled: true,
      cimdAllowedClientIdPrefixes: ["https://chatgpt.com/oauth/"],
      dcrEnabled: false,
      fetchImpl: (async () => {
        fetched = true;
        throw new Error("unexpected fetch");
      }) as typeof fetch,
    });

    const response = await authorize(context.app, {
      client_id: "https://attacker.example/client.json",
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_client" });
    expect(fetched).toBe(false);
  });

  it.each([
    ["mismatched client ID", { client_id: "https://chatgpt.com/oauth/other.json" }],
    ["unapproved redirect URI", { redirect_uris: ["https://attacker.example/callback"] }],
  ])("rejects CIMD metadata with %s", async (_name, override) => {
    const clientId = "https://chatgpt.com/oauth/levitate-client.json";
    const context = await createTestApp({
      cimdEnabled: true,
      cimdAllowedClientIdPrefixes: ["https://chatgpt.com/oauth/"],
      dcrEnabled: false,
      fetchImpl: (async () => new Response(JSON.stringify({
        client_id: clientId,
        client_name: "ChatGPT",
        redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        ...override,
      }), { headers: { "content-type": "application/json" } })) as typeof fetch,
    });

    const response = await authorize(context.app, {
      client_id: clientId,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_client" });
  });

  it("bounds CIMD cache entries and metadata fetches", async () => {
    const context = createTestConfig({
      cimdEnabled: true,
      cimdAllowedClientIdPrefixes: ["https://chatgpt.com/oauth/"],
    });
    let fetchCount = 0;
    const fetchImpl = (async (input: string | URL | Request) => {
      fetchCount += 1;
      const clientId = String(input);
      return new Response(JSON.stringify({
        client_id: clientId,
        client_name: "ChatGPT",
        redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }), {
        headers: {
          "content-type": "application/json",
          "cache-control": "max-age=60",
        },
      });
    }) as typeof fetch;
    const resolver = new CimdClientResolver(context.config, logger, fetchImpl, {
      maxCacheEntries: 1,
      maxFetchesPerMinute: 3,
    });
    const first = "https://chatgpt.com/oauth/first.json";
    const second = "https://chatgpt.com/oauth/second.json";

    expect(await resolver.get(first)).toBeDefined();
    expect(await resolver.get(second)).toBeDefined();
    expect(await resolver.get(first)).toBeDefined();
    expect(await resolver.get("https://chatgpt.com/oauth/blocked.json")).toBeUndefined();
    expect(fetchCount).toBe(3);
  });

  it("keeps existing clients usable when dcr is disabled", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);

    context.config.oauth.as.dcr.enabled = false;

    const blockedRegistration = await registerClient(context.app);
    expect(blockedRegistration.status).toBe(404);

    const code = await authorizeAndGetCode(context.app, client.client_id, validVerifier);
    const response = await token(context.app, validTokenRequest(code, client.client_id, validVerifier));
    expect(response.status).toBe(200);
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

  it("persists concurrent client registrations", async () => {
    const context = await createTestApp();
    const responses = await Promise.all(Array.from({ length: 8 }, () => registerClient(context.app)));

    expect(responses.every((response) => response.status === 201)).toBe(true);
    const stored = JSON.parse(context.clientStoreText()) as { clients: Array<{ client_id: string }> };
    expect(stored.clients).toHaveLength(8);
  });

  it("normalizes omitted public client registration metadata", async () => {
    const context = await createTestApp();
    const response = await registerClient(context.app, {
      grant_types: undefined,
      response_types: undefined,
      token_endpoint_auth_method: undefined,
    });
    const client = await response.json() as {
      grant_types: string[];
      response_types: string[];
      token_endpoint_auth_method: string;
    };

    expect(response.status).toBe(201);
    expect(client.grant_types).toEqual(["authorization_code"]);
    expect(client.response_types).toEqual(["code"]);
    expect(client.token_endpoint_auth_method).toBe("none");
  });

  it("rejects unsupported refresh-token registration metadata", async () => {
    const context = await createTestApp();
    const response = await registerClient(context.app, {
      grant_types: ["authorization_code", "refresh_token"],
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_client_metadata" });
  });

  it("lists, shows, and revokes clients with the management command", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);

    const listOutput = await runClientsCommand(context.config, ["list"]);
    expect(JSON.parse(listOutput)).toEqual([
      expect.objectContaining({ client_id: client.client_id }),
    ]);

    const showOutput = await runClientsCommand(context.config, ["show", client.client_id]);
    expect(JSON.parse(showOutput)).toEqual(expect.objectContaining({ client_id: client.client_id }));

    const revokeOutput = await runClientsCommand(context.config, ["revoke", client.client_id]);
    const revoked = JSON.parse(revokeOutput) as { revoked_at?: string };
    expect(revoked.revoked_at).toBeTruthy();
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
      grant_types: ["authorization_code", "client_credentials"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, "invalid_client_metadata");

    await expectRegistrationError(context.app, {
      redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code", "token"],
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
    const challenge = pkceChallenge(validVerifier);

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

    const invalidPkce = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: "short",
      resource: "https://levitate.example.com/brain/mcp",
    });
    expect(invalidPkce.headers.get("location")).toContain("error=invalid_request");

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

  it("rejects revoked clients during authorization and token exchange", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);
    const code = await authorizeAndGetCode(context.app, client.client_id, validVerifier);
    const store = new JsonClientStore(context.clientStoreFile);
    await store.revoke(client.client_id);

    const authorization = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
    });
    expect(authorization.headers.get("location")).toContain("error=invalid_client");

    const exchanged = await token(context.app, validTokenRequest(code, client.client_id, validVerifier));
    expect(exchanged.status).toBe(400);
    await expect(exchanged.json()).resolves.toEqual({ error: "invalid_client" });
  });

  it("limits requested scopes to the registered client scope", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app, { scope: "brain:read" });

    const response = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
      scope: "brain:write",
    });

    expect(response.headers.get("location")).toContain("error=invalid_scope");
  });

  it("allows globally supported scopes when client registration omits scope", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);

    const response = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
      scope: "brain:read brain:write",
    });

    expect(response.status).toBe(302);
    expect(new URL(response.headers.get("location") ?? "").searchParams.get("code")).toBeTruthy();
  });

  it("authorizes with pkce and preserves state", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);
    const response = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
      state: "state-1",
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe("https://chatgpt.com/connector/oauth/callback");
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe("state-1");
  });

  it("requires manual approval before issuing an authorization code", async () => {
    const context = await createTestApp({ approval: "manual" });
    const client = await registerAndReadClient(context.app);
    const response = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
      scope: "brain:read",
      state: "state-1",
    });

    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain("Approve Levitate access");
    expect(html).toContain("ChatGPT Connector");
    expect(html).toContain("https://chatgpt.com");
    expect(html).toContain("https://levitate.example.com/brain/mcp");
    expect(html).toContain("brain:read");
    expect(html).toContain("Approval secret");
    expect(html).toContain('id="eye_open"');
    expect(html).toContain('id="eye_closed"');
    expect(html).not.toContain("cdnjs.cloudflare.com");
    expect(html).toContain("Cancel");
    expect(html).not.toContain("state-1");

    const approved = await submitApproval(context.app, html, "approve");
    expect(approved.status).toBe(302);
    const location = new URL(approved.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe("https://chatgpt.com/connector/oauth/callback");
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe("state-1");
  });

  it("requires the owner approval secret before approving manually", async () => {
    const context = await createTestApp({ approval: "manual" });
    const client = await registerAndReadClient(context.app);
    const response = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
      state: "state-1",
    });
    const html = await response.text();

    const rejected = await submitApproval(context.app, html, "approve", "wrong-secret");
    expect(rejected.status).toBe(403);
    expect(await rejected.text()).toContain("Approval secret invalid");

    const approved = await submitApproval(context.app, html, "approve");
    expect(approved.status).toBe(302);
    const location = new URL(approved.headers.get("location") ?? "");
    expect(location.searchParams.get("code")).toBeTruthy();
  });

  it("returns access_denied when manual approval is denied", async () => {
    const context = await createTestApp({ approval: "manual" });
    const client = await registerAndReadClient(context.app);
    const response = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
      state: "state-1",
    });
    const denied = await submitApproval(context.app, await response.text(), "deny", "");

    expect(denied.status).toBe(302);
    const location = new URL(denied.headers.get("location") ?? "");
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("state")).toBe("state-1");
  });

  it("rejects manual approval when the client is revoked while pending", async () => {
    const context = await createTestApp({ approval: "manual" });
    const client = await registerAndReadClient(context.app);
    const response = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/callback",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
      state: "state-1",
    });
    const html = await response.text();
    const store = new JsonClientStore(context.clientStoreFile);
    await store.revoke(client.client_id);

    const approved = await submitApproval(context.app, html, "approve");
    expect(approved.status).toBe(302);
    const location = new URL(approved.headers.get("location") ?? "");
    expect(location.searchParams.get("error")).toBe("invalid_client");
    expect(location.searchParams.get("code")).toBeNull();
    expect(location.searchParams.get("state")).toBe("state-1");
  });

  it("does not render manual approval for unsafe redirect requests", async () => {
    const context = await createTestApp({ approval: "manual" });
    const client = await registerAndReadClient(context.app);
    const response = await authorize(context.app, {
      client_id: client.client_id,
      redirect_uri: "https://chatgpt.com/connector/oauth/other",
      code_challenge: pkceChallenge(validVerifier),
      resource: "https://levitate.example.com/brain/mcp",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_request" });
  });

  it("exchanges an authorization code for an RS256 access token", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);
    const verifier = validVerifier;
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
    const verifier = validVerifier;
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
      code_verifier: otherValidVerifier,
    });

    const success = await token(context.app, validTokenRequest(code, client.client_id, verifier));
    expect(success.status).toBe(200);
    await expectTokenError(context.app, { code, client_id: client.client_id, code_verifier: verifier });
  });

  it("rejects expired authorization codes", async () => {
    const context = await createTestApp({ codeTtlSeconds: 1 });
    const client = await registerAndReadClient(context.app);
    const code = await authorizeAndGetCode(context.app, client.client_id, validVerifier);

    await new Promise((resolve) => setTimeout(resolve, 1100));
    await expectTokenError(context.app, { code, client_id: client.client_id, code_verifier: validVerifier });
  });

  it("accepts Levitate-issued JWTs on the MCP route", async () => {
    const context = await createTestApp();
    const client = await registerAndReadClient(context.app);
    const code = await authorizeAndGetCode(context.app, client.client_id, validVerifier);
    const issued = await token(context.app, validTokenRequest(code, client.client_id, validVerifier));
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
  const appLogger = options.logger ?? logger;
  const oauthAuthorizationServer = createOAuthAuthorizationServer(
    context.config,
    keys,
    appLogger,
    options.fetchImpl,
  );
  const authenticator = createAuthenticator(context.config, keys);
  const app = createApp({
    config: context.config,
    authenticator,
    backend,
    logger: appLogger,
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
  approval?: "auto" | "manual";
  codeTtlSeconds?: number;
  dcrEnabled?: boolean;
  cimdEnabled?: boolean;
  cimdAllowedClientIdPrefixes?: string[];
  fetchImpl?: typeof fetch;
  logger?: Logger;
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
        approval: options.approval ?? "auto",
        approval_secret_env: options.approval === "manual" ? "LEVITATE_APPROVAL_SECRET" : undefined,
        dcr: {
          enabled: options.dcrEnabled ?? true,
        },
        cimd: {
          enabled: options.cimdEnabled ?? false,
          allowed_client_id_prefixes: options.cimdAllowedClientIdPrefixes ?? [],
        },
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

  if (options.approval === "manual") {
    process.env.LEVITATE_APPROVAL_SECRET = "test-secret";
  }

  return {
    config,
    dir,
    privateKeyFile,
    clientStoreFile,
  };
}

function registerClient(
  app: Awaited<ReturnType<typeof createTestApp>>["app"],
  overrides: {
    grant_types?: string[];
    response_types?: string[];
    scope?: string;
    token_endpoint_auth_method?: string;
  } = {},
) {
  return app.fetch(new Request("http://localhost/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "ChatGPT Connector",
      redirect_uris: ["https://chatgpt.com/connector/oauth/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      ...overrides,
    }),
  }));
}

async function registerAndReadClient(
  app: Awaited<ReturnType<typeof createTestApp>>["app"],
  overrides: { scope?: string } = {},
) {
  const response = await registerClient(app, overrides);
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

async function runClientsCommand(config: LevitateConfig, args: string[]): Promise<string> {
  let output = "";
  await runOAuthClientsCommand(config, args, {
    write(chunk: string | Uint8Array) {
      output += chunk.toString();
      return true;
    },
  });
  return output;
}

function submitApproval(
  app: Awaited<ReturnType<typeof createTestApp>>["app"],
  html: string,
  decision: "approve" | "deny",
  approvalSecret = "test-secret",
) {
  const path = html.match(/action="([^"]+)"/)?.[1];
  if (!path) throw new Error("approval action missing");
  return app.fetch(new Request(`http://localhost${path}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ decision, approval_secret: approvalSecret }),
  }));
}

async function expectTokenError(
  app: Awaited<ReturnType<typeof createTestApp>>["app"],
  overrides: { code: string; client_id?: string; redirect_uri?: string; resource?: string; code_verifier?: string },
) {
  const response = await token(app, validTokenRequest(
    overrides.code,
    overrides.client_id ?? "client",
    overrides.code_verifier ?? validVerifier,
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
