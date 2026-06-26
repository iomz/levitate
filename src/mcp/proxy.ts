import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { StdioMcpBackend } from "./backend.js";
import { deniedReason, filterTools, type ToolPolicy } from "./policy.js";
import type { Logger } from "../logging.js";

export interface ProxyOptions {
  serverName: string;
  instructions?: string;
  backend: StdioMcpBackend;
  policy: ToolPolicy;
  logger: Logger;
}

export async function handleMcpRequest(
  request: Request,
  options: ProxyOptions,
): Promise<Response> {
  const transport = new WebStandardStreamableHTTPServerTransport({
    enableJsonResponse: true,
  });
  const server = createProxyServer(options);
  await server.connect(transport);
  return transport.handleRequest(request);
}

export function createProxyServer(options: ProxyOptions): Server {
  const server = new Server(
    { name: options.serverName, version: "0.1.0" },
    {
      capabilities: { tools: {} },
      instructions: options.instructions,
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const result = await options.backend.listTools();
    const tools = filterTools(result.tools, options.policy);
    options.logger.info("tools listed", {
      backendTools: result.tools.length,
      advertisedTools: tools.length,
    });
    return { ...result, tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const reason = deniedReason(request.params.name, options.policy);
    if (reason) {
      options.logger.warn("tool call denied", {
        tool: request.params.name,
        reason,
      });
      return {
        content: [
          {
            type: "text",
            text: `Levitate denied tool call: ${request.params.name} (${reason})`,
          },
        ],
        isError: true,
      };
    }

    options.logger.info("tool call allowed", { tool: request.params.name });
    return options.backend.callTool(request.params);
  });

  return server;
}
