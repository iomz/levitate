import { serve } from "@hono/node-server";
import { randomUUID } from "node:crypto";
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import type { ServerType } from "@hono/node-server";
import type { Authenticator } from "./auth/types.js";
import { AuthError } from "./auth/types.js";
import { getBackendConfigs, type BackendConfig, type LevitateConfig } from "./config.js";
import type { Logger } from "./logging.js";
import type { StdioMcpBackend } from "./mcp/backend.js";
import { handleMcpRequest } from "./mcp/proxy.js";
import type { OAuthAuthorizationServer } from "./oauth/as/routes.js";

export interface AppContext {
  config: LevitateConfig;
  authenticator: Authenticator;
  backend?: StdioMcpBackend;
  instructions?: string;
  backends?: BackendRuntime[];
  logger: Logger;
  oauthAuthorizationServer?: OAuthAuthorizationServer;
}

export interface BackendRuntime {
  config: BackendConfig;
  backend: StdioMcpBackend;
  instructions?: string;
}

type AppEnv = {
  Variables: {
    requestId: string;
  };
};

export function createApp(context: AppContext): Hono<AppEnv> {
  const app = new Hono<AppEnv>();
  const backends = context.backends ?? [{
    config: getBackendConfigs(context.config)[0],
    backend: context.backend!,
    instructions: context.instructions,
  }];
  const allowedOrigins = context.config.server.cors?.allowed_origins;

  app.use("*", cors({
    origin: allowedOrigins
      ? (origin) => allowedOrigins.includes(origin) ? origin : undefined
      : "*",
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: [
      "Authorization",
      "Content-Type",
      "mcp-session-id",
      "Last-Event-ID",
      "mcp-protocol-version",
    ],
    exposeHeaders: ["mcp-session-id", "mcp-protocol-version", "WWW-Authenticate"],
  }));

  app.use("*", async (c, next) => {
    const supplied = c.req.header("x-request-id");
    const requestId = supplied && /^[A-Za-z0-9._:-]{1,128}$/.test(supplied)
      ? supplied
      : randomUUID();
    c.set("requestId", requestId);
    c.header("x-request-id", requestId);
    await next();
  });

  app.get("/health", (c) => c.json({
    status: "ok",
    name: context.config.server.name,
  }));

  app.get("/ready", (c) => {
    const states = backends.map(({ config, backend }) => ({
      id: config.id,
      name: config.name,
      path: config.mcp_path,
      ready: backend.isReady?.() ?? true,
    }));
    const ready = states.every((state) => state.ready);
    return c.json({
      status: ready ? "ready" : "not_ready",
      name: context.config.server.name,
      backends: states,
    }, ready ? 200 : 503);
  });

  if (context.config.oauth.resource.enabled) {
    const serveProtectedResourceMetadata = (c: Context<AppEnv>) => {
      const resource = context.config.oauth.resource;
      return c.json({
        resource: resource.resource,
        authorization_servers: resource.authorization_servers,
        bearer_methods_supported: ["header"],
        scopes_supported: resource.scopes_supported,
      });
    };
    app.get("/.well-known/oauth-protected-resource", serveProtectedResourceMetadata);
    const pathScopedRoute = getPathScopedResourceMetadataPath(context.config);
    if (pathScopedRoute !== "/.well-known/oauth-protected-resource") {
      app.get(pathScopedRoute, serveProtectedResourceMetadata);
    }
  }

  context.oauthAuthorizationServer?.registerRoutes(app);

  for (const runtime of backends) app.all(runtime.config.mcp_path, async (c) => {
    if (c.req.method === "OPTIONS") return c.body(null, 204);

    try {
      await context.authenticator.authenticate(c.req.raw);
    } catch (error) {
      const message = error instanceof Error ? error.message : "auth failed";
      context.logger.warn("auth failed", {
        message,
        requestId: c.get("requestId"),
      });
      const resourceMetadataUrl = getResourceMetadataUrl(context.config);
      if (resourceMetadataUrl) {
        c.header("WWW-Authenticate", `Bearer resource_metadata="${resourceMetadataUrl}"`);
      }
      if (error instanceof AuthError) {
        return c.json({ error: "auth failed" }, error.status);
      }
      return c.json({ error: "auth failed" }, 401);
    }

    context.logger.info("remote mcp request", {
      method: c.req.method,
      requestId: c.get("requestId"),
      backend: runtime.config.id,
    });
    return handleMcpRequest(c.req.raw, {
      serverName: runtime.config.name,
      instructions: runtime.instructions,
      backend: runtime.backend,
      policy: runtime.config.tools,
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
    endpoints: getBackendConfigs(context.config).map((backend) => backend.mcp_path),
  });

  return serve({
    fetch: app.fetch,
    hostname: host,
    port,
  });
}

function getResourceMetadataUrl(config: LevitateConfig): string | undefined {
  const resource = config.oauth.resource;
  if (!resource.enabled || !resource.resource) return undefined;
  if (resource.metadata_url) return resource.metadata_url;
  const url = new URL(resource.resource);
  url.pathname = getPathScopedResourceMetadataPath(config);
  url.search = "";
  url.hash = "";
  return url.toString();
}

function getPathScopedResourceMetadataPath(config: LevitateConfig): string {
  const resourceUrl = config.oauth.resource.resource;
  if (!resourceUrl) return "/.well-known/oauth-protected-resource";
  const resourcePath = new URL(resourceUrl).pathname;
  return resourcePath === "/"
    ? "/.well-known/oauth-protected-resource"
    : `/.well-known/oauth-protected-resource${resourcePath}`;
}
