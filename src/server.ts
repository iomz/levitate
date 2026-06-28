import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import type { ServerType } from "@hono/node-server";
import type { Authenticator } from "./auth/types.js";
import { AuthError } from "./auth/types.js";
import type { LevitateConfig } from "./config.js";
import type { Logger } from "./logging.js";
import type { StdioMcpBackend } from "./mcp/backend.js";
import { handleMcpRequest } from "./mcp/proxy.js";

export interface AppContext {
  config: LevitateConfig;
  authenticator: Authenticator;
  backend: StdioMcpBackend;
  instructions?: string;
  logger: Logger;
}

export function createApp(context: AppContext): Hono {
  const app = new Hono();

  app.use("*", cors({
    origin: "*",
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: [
      "Authorization",
      "Content-Type",
      "mcp-session-id",
      "Last-Event-ID",
      "mcp-protocol-version",
    ],
    exposeHeaders: ["mcp-session-id", "mcp-protocol-version"],
  }));

  app.get("/health", (c) => c.json({
    status: "ok",
    name: context.config.server.name,
  }));

  app.all("/mcp", async (c) => {
    if (c.req.method === "OPTIONS") return c.body(null, 204);

    try {
      await context.authenticator.authenticate(c.req.raw);
    } catch (error) {
      const message = error instanceof Error ? error.message : "auth failed";
      context.logger.warn("auth failed", { message });
      if (error instanceof AuthError) {
        return c.json({ error: "auth failed" }, error.status);
      }
      return c.json({ error: "auth failed" }, 401);
    }

    context.logger.info("remote mcp request", { method: c.req.method });
    return handleMcpRequest(c.req.raw, {
      serverName: context.config.server.name,
      instructions: context.instructions,
      backend: context.backend,
      policy: context.config.tools,
      logger: context.logger,
    });
  });

  app.notFound((c) => c.json({ error: "not found" }, 404));

  return app;
}

export function startHttpServer(context: AppContext): ServerType {
  const app = createApp(context);
  const { host, port } = context.config.server;

  context.logger.info("http server starting", {
    host,
    port,
    endpoint: "/mcp",
  });

  return serve({
    fetch: app.fetch,
    hostname: host,
    port,
  });
}
