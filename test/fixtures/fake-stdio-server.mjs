#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

export const instructions = [
  "Fixture backend for Levitate proxy tests.",
  "It knows nothing beyond the two tools it advertises.",
].join("\n");

const server = new Server(
  { name: "levitate-fake-stdio", version: "0.1.0" },
  { capabilities: { tools: {} }, instructions },
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
      // _meta is echoed only when present, so callers that send none see the
      // same payload as before.
      text: JSON.stringify({
        tool: request.params.name,
        arguments: request.params.arguments ?? {},
        ...(request.params._meta ? { meta: request.params._meta } : {}),
      }),
    },
  ],
}));

await server.connect(new StdioServerTransport());
