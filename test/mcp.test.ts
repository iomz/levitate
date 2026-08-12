import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  CallToolRequest,
  CallToolResult,
  ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";
import { BearerAuthenticator } from "../src/auth/bearer.js";
import { getBackendConfigs, type LevitateConfig } from "../src/config.js";
import type { Logger } from "../src/logging.js";
import { StdioMcpBackend } from "../src/mcp/backend.js";
import { createApp } from "../src/server.js";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packageVersion = (JSON.parse(
  readFileSync(resolve(repoRoot, "package.json"), "utf8"),
) as { version: string }).version;

const logger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

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
    mode: "bearer",
    token: "secret",
  },
  oauth: {
    resource: {
      enabled: false,
      mode: "service",
      authorization_servers: [],
      scopes_supported: [],
    },
    as: {
      enabled: false,
      approval: "auto",
      dcr: {
        enabled: false,
      },
      cimd: {
        enabled: false,
        allowed_client_id_prefixes: [],
      },
      allowed_redirect_uri_prefixes: [],
      scopes_supported: [],
      default_scopes: [],
      access_token_ttl_seconds: 3600,
      refresh_token_ttl_seconds: 2_592_000,
      authorization_code_ttl_seconds: 300,
      keys: {},
    },
  },
  tools: {
    allow: ["search", "delete_note"],
    deny: ["delete_note"],
  },
};

const backend = {
  async listTools(): Promise<ListToolsResult> {
    return {
      tools: [
        {
          name: "search",
          inputSchema: {
            type: "object",
            properties: {},
          },
        },
        {
          name: "delete_note",
          inputSchema: {
            type: "object",
            properties: {},
          },
        },
      ],
    };
  },
  async callTool(params: CallToolRequest["params"]): Promise<CallToolResult> {
    return {
      content: [
        {
          type: "text",
          text: `called ${params.name}`,
        },
      ],
    };
  },
} as unknown as StdioMcpBackend;

describe("mcp endpoint", () => {
  const clients: Client[] = [];
  const backends: StdioMcpBackend[] = [];

  afterEach(async () => {
    await Promise.all(clients.map((client) => client.close()));
    await Promise.all(backends.map((stdioBackend) => stdioBackend.close()));
    clients.length = 0;
    backends.length = 0;
  });

  it("reports liveness separately from backend readiness", async () => {
    const unavailableBackend = {
      ...backend,
      isReady: () => false,
    } as unknown as StdioMcpBackend;
    const app = createApp({
      config,
      authenticator: new BearerAuthenticator("secret"),
      backend: unavailableBackend,
      logger,
    });

    const health = await app.fetch(new Request("http://localhost/health"));
    const ready = await app.fetch(new Request("http://localhost/ready"));

    expect(health.status).toBe(200);
    await expect(health.json()).resolves.toEqual({ status: "ok", name: "test" });
    expect(ready.status).toBe(503);
    await expect(ready.json()).resolves.toEqual({
      status: "not_ready",
      name: "test",
      backends: [{ id: "default", name: "test", path: "/mcp", ready: false }],
    });
  });

  it("returns a validated request correlation ID", async () => {
    const app = createApp({
      config,
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const supplied = await app.fetch(new Request("http://localhost/health", {
      headers: { "x-request-id": "test-request:123" },
    }));
    const rejected = await app.fetch(new Request("http://localhost/health", {
      headers: { "x-request-id": "invalid request id" },
    }));

    expect(supplied.headers.get("x-request-id")).toBe("test-request:123");
    expect(rejected.headers.get("x-request-id")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it("requires bearer auth", async () => {
    const app = createApp({
      config,
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
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

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: "auth failed" });
  });

  it("serves mcp at the default path", async () => {
    const app = createApp({
      config,
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/mcp", {
      method: "OPTIONS",
    }));

    expect(response.status).toBe(204);
  });

  it("serves the public Levitate server icon", async () => {
    const app = createApp({
      config,
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request(
      "http://localhost/assets/levitate-icon-64.png",
    ));

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("image/png");
    expect(response.headers.get("cache-control")).toBe("public, max-age=3600");
    expect((await response.arrayBuffer()).byteLength).toBeGreaterThan(0);
  });

  it("permits all CORS origins by default", async () => {
    const app = createApp({
      config,
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/mcp", {
      method: "OPTIONS",
      headers: {
        Origin: "https://example.com",
        "Access-Control-Request-Method": "POST",
      },
    }));

    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("permits configured CORS origins exactly", async () => {
    const app = createApp({
      config: {
        ...config,
        server: {
          ...config.server,
          cors: { allowed_origins: ["https://chatgpt.com"] },
        },
      },
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/mcp", {
      method: "OPTIONS",
      headers: {
        Origin: "https://chatgpt.com",
        "Access-Control-Request-Method": "POST",
      },
    }));

    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://chatgpt.com",
    );
  });

  it("omits CORS permission for disallowed origins", async () => {
    const app = createApp({
      config: {
        ...config,
        server: {
          ...config.server,
          cors: { allowed_origins: ["https://chatgpt.com"] },
        },
      },
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/mcp", {
      method: "OPTIONS",
      headers: {
        Origin: "https://example.com",
        "Access-Control-Request-Method": "POST",
      },
    }));

    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("does not block clients without an Origin header", async () => {
    const app = createApp({
      config: {
        ...config,
        server: {
          ...config.server,
          cors: { allowed_origins: ["https://chatgpt.com"] },
        },
      },
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/mcp"));

    expect(response.status).toBe(401);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("serves mcp at a custom path", async () => {
    const app = createApp({
      config: {
        ...config,
        server: {
          ...config.server,
          mcp_path: "/brain/mcp",
        },
      },
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const configured = await app.fetch(new Request("http://localhost/brain/mcp"));
    const defaultPath = await app.fetch(new Request("http://localhost/mcp"));

    expect(configured.status).toBe(401);
    expect(defaultPath.status).toBe(404);
  });

  it("requires auth at a custom mcp path", async () => {
    const app = createApp({
      config: {
        ...config,
        server: {
          ...config.server,
          mcp_path: "/brain/mcp",
        },
      },
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/brain/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
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

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: "auth failed" });
  });

  it("serves configured oauth protected resource metadata", async () => {
    const app = createApp({
      config: {
        ...config,
        oauth: {
          resource: {
            enabled: true,
            mode: "service",
            resource: "https://levitate.example.com/brain/mcp",
            authorization_servers: ["https://auth.example.com/"],
            scopes_supported: ["levitate:read", "levitate:call"],
          },
          as: config.oauth.as,
        },
      },
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/.well-known/oauth-protected-resource"));
    const pathScopedResponse = await app.fetch(new Request(
      "http://localhost/.well-known/oauth-protected-resource/brain/mcp",
    ));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      resource: "https://levitate.example.com/brain/mcp",
      authorization_servers: ["https://auth.example.com/"],
      bearer_methods_supported: ["header"],
      scopes_supported: ["levitate:read", "levitate:call"],
    });
    expect(pathScopedResponse.status).toBe(200);
    await expect(pathScopedResponse.json()).resolves.toEqual({
      resource: "https://levitate.example.com/brain/mcp",
      authorization_servers: ["https://auth.example.com/"],
      bearer_methods_supported: ["header"],
      scopes_supported: ["levitate:read", "levitate:call"],
    });
  });

  it("adds oauth protected resource metadata to auth challenges", async () => {
    const app = createApp({
      config: {
        ...config,
        server: {
          ...config.server,
          mcp_path: "/brain/mcp",
        },
        oauth: {
          resource: {
            enabled: true,
            mode: "service",
            resource: "https://levitate.example.com/brain/mcp",
            authorization_servers: ["https://auth.example.com/"],
            scopes_supported: ["levitate:read"],
          },
          as: config.oauth.as,
        },
      },
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const response = await app.fetch(new Request("http://localhost/brain/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }));

    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe(
      'Bearer resource_metadata="https://levitate.example.com/.well-known/oauth-protected-resource/brain/mcp"',
    );
    await expect(response.json()).resolves.toEqual({ error: "auth failed" });
  });

  it("preserves trailing slashes in path-scoped resource metadata URLs", async () => {
    const app = createApp({
      config: {
        ...config,
        server: {
          ...config.server,
          mcp_path: "/brain/mcp/",
        },
        oauth: {
          resource: {
            enabled: true,
            mode: "service",
            resource: "https://levitate.example.com/brain/mcp/",
            authorization_servers: ["https://auth.example.com/"],
            scopes_supported: ["levitate:read"],
          },
          as: config.oauth.as,
        },
      },
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });

    const metadata = await app.fetch(new Request(
      "http://localhost/.well-known/oauth-protected-resource/brain/mcp/",
    ));
    const unauthorized = await app.fetch(new Request("http://localhost/brain/mcp/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }));

    expect(metadata.status).toBe(200);
    expect(unauthorized.headers.get("www-authenticate")).toBe(
      'Bearer resource_metadata="https://levitate.example.com/.well-known/oauth-protected-resource/brain/mcp/"',
    );
  });

  it("serves gateway metadata and route-specific challenges for named backends", async () => {
    const backendConfig = (id: string, path: string) => ({
      id,
      name: id,
      mcp_path: path,
      stdio: { command: "unused", args: [] },
      env: {},
      instructions: {},
      tools: { deny: [] },
    });
    const app = createApp({
      config: {
        ...config,
        oauth: {
          resource: {
            enabled: true,
            mode: "gateway",
            resource: "https://levitate.example.com",
            authorization_servers: ["https://levitate.example.com"],
            scopes_supported: ["gateway:access"],
          },
          as: config.oauth.as,
        },
      },
      authenticator: new BearerAuthenticator("secret"),
      backends: [
        { config: backendConfig("notes", "/notes/mcp"), backend },
        { config: backendConfig("ingest", "/ingest/mcp"), backend },
      ],
      logger,
    });

    for (const path of ["/notes/mcp", "/ingest/mcp"]) {
      const metadataPath = `/.well-known/oauth-protected-resource${path}`;
      const metadata = await app.fetch(new Request(`http://localhost${metadataPath}`));
      expect(metadata.status).toBe(200);
      await expect(metadata.json()).resolves.toEqual({
        resource: "https://levitate.example.com",
        authorization_servers: ["https://levitate.example.com"],
        bearer_methods_supported: ["header"],
        scopes_supported: ["gateway:access"],
      });

      const unauthorized = await app.fetch(new Request(`http://localhost${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      }));
      expect(unauthorized.status).toBe(401);
      expect(unauthorized.headers.get("www-authenticate")).toBe(
        `Bearer resource_metadata="https://levitate.example.com${metadataPath}"`,
      );
    }

    const rootMetadata = await app.fetch(new Request(
      "http://localhost/.well-known/oauth-protected-resource",
    ));
    expect(rootMetadata.status).toBe(200);
  });

  it("proxies tools through streamable http with policy applied", async () => {
    const app = createApp({
      config,
      authenticator: new BearerAuthenticator("secret"),
      backend,
      logger,
    });
    const client = new Client(
      { name: "test-client", version: "0.1.0" },
      { capabilities: {} },
    );
    clients.push(client);

    const transport = new StreamableHTTPClientTransport(
      new URL("http://localhost/mcp"),
      {
        requestInit: {
          headers: { authorization: "Bearer secret" },
        },
        fetch: async (input, init) => app.fetch(new Request(input, init)),
      },
    );
    await client.connect(transport);

    expect(client.getServerVersion()).toEqual({
      name: "test",
      title: "Levitate / test",
      version: packageVersion,
      description: "MCP endpoint exposed through Levitate.",
      websiteUrl: "https://github.com/iomz/levitate",
      icons: [{
        src: "http://localhost/assets/levitate-icon-64.png",
        mimeType: "image/png",
        sizes: ["64x64"],
      }],
    });

    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name)).toEqual(["search"]);

    const allowed = await client.callTool({ name: "search", arguments: {} });
    expect(allowed.content).toEqual([{ type: "text", text: "called search" }]);

    const denied = await client.callTool({ name: "delete_note", arguments: {} });
    expect(denied.isError).toBe(true);
    expect(denied.content).toEqual([
      {
        type: "text",
        text: "Levitate denied tool call: delete_note (tool in denylist)",
      },
    ]);
  });

  it("isolates named backends by MCP path", async () => {
    const namedBackend = (toolName: string) => ({
      async listTools() {
        return { tools: [{ name: toolName, inputSchema: { type: "object", properties: {} } }] };
      },
      async callTool() {
        return { content: [{ type: "text", text: toolName }] };
      },
      isReady: () => true,
    }) as unknown as StdioMcpBackend;
    const backendConfig = (id: string, path: string) => ({
      id,
      name: id,
      mcp_path: path,
      stdio: { command: "unused", args: [] },
      env: {},
      instructions: {},
      tools: { deny: [] },
    });
    const app = createApp({
      config,
      authenticator: new BearerAuthenticator("secret"),
      backends: [
        { config: backendConfig("notes", "/notes/mcp"), backend: namedBackend("notes_search") },
        { config: backendConfig("ingest", "/ingest/mcp"), backend: namedBackend("ingest_sync") },
      ],
      logger,
    });

    for (const [path, expected] of [["/notes/mcp", "notes_search"], ["/ingest/mcp", "ingest_sync"]]) {
      const client = new Client({ name: "test-client", version: "0.1.0" }, { capabilities: {} });
      clients.push(client);
      await client.connect(new StreamableHTTPClientTransport(new URL(`http://localhost${path}`), {
        requestInit: { headers: { authorization: "Bearer secret" } },
        fetch: async (input, init) => app.fetch(new Request(input, init)),
      }));
      expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual([expected]);
    }
  });

  it("proxies a real stdio backend and returns tool errors for denied direct calls", async () => {
    const stdioConfig: LevitateConfig = {
      ...config,
      server: {
        ...config.server,
        name: "fake",
      },
      stdio: {
        command: process.execPath,
        args: [resolve(repoRoot, "test/fixtures/fake-stdio-server.mjs")],
      },
      tools: {
        allow: ["fake_allowed", "fake_denied"],
        deny: ["fake_denied"],
      },
    };
    const stdioBackend = new StdioMcpBackend(getBackendConfigs(stdioConfig)[0], logger);
    await stdioBackend.start();
    backends.push(stdioBackend);

    const app = createApp({
      config: stdioConfig,
      authenticator: new BearerAuthenticator("secret"),
      backend: stdioBackend,
      logger,
    });
    const client = new Client(
      { name: "test-client", version: "0.1.0" },
      { capabilities: {} },
    );
    clients.push(client);

    const transport = new StreamableHTTPClientTransport(
      new URL("http://localhost/mcp"),
      {
        requestInit: {
          headers: { authorization: "Bearer secret" },
        },
        fetch: async (input, init) => app.fetch(new Request(input, init)),
      },
    );
    await client.connect(transport);

    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name)).toEqual(["fake_allowed"]);

    const allowed = await client.callTool({
      name: "fake_allowed",
      arguments: { message: "hello" },
    });
    expect(allowed.isError).not.toBe(true);
    expect(allowed.content).toEqual([
      {
        type: "text",
        text: "{\"tool\":\"fake_allowed\",\"arguments\":{\"message\":\"hello\"}}",
      },
    ]);

    const denied = await client.callTool({ name: "fake_denied", arguments: {} });
    expect(denied.isError).toBe(true);
    expect(denied.content).toEqual([
      {
        type: "text",
        text: "Levitate denied tool call: fake_denied (tool in denylist)",
      },
    ]);
  });
});
