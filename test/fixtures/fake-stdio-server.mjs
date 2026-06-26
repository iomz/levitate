#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "levitate-fake-stdio", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "fake_allowed",
      description: "Allowed fixture tool",
      inputSchema: {
        type: "object",
        properties: {
          message: { type: "string" },
        },
      },
    },
    {
      name: "fake_denied",
      description: "Denied fixture tool",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => ({
  content: [
    {
      type: "text",
      text: JSON.stringify({
        tool: request.params.name,
        arguments: request.params.arguments ?? {},
      }),
    },
  ],
}));

await server.connect(new StdioServerTransport());
