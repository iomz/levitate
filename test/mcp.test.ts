import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  CallToolRequest,
  CallToolResult,
  ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";
import { BearerAuthenticator } from "../src/auth/bearer.js";
import type { LevitateConfig } from "../src/config.js";
import type { Logger } from "../src/logging.js";
import { StdioMcpBackend } from "../src/mcp/backend.js";
import { createApp } from "../src/server.js";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

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
    const stdioBackend = new StdioMcpBackend(stdioConfig, logger);
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
