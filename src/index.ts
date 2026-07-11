#!/usr/bin/env node
import { createAuthenticator } from "./auth/index.js";
import { getBackendConfigs, getConfigPath, loadConfig } from "./config.js";
import { createLogger } from "./logging.js";
import { StdioMcpBackend } from "./mcp/backend.js";
import { loadInstructions } from "./mcp/instructions.js";
import { runOAuthClientsCommand } from "./oauth/as/clients-cli.js";
import { loadAuthorizationServerKeys } from "./oauth/as/keys.js";
import { createOAuthAuthorizationServer } from "./oauth/as/routes.js";
import { startHttpServer } from "./server.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const config = await loadConfig(getConfigPath());
  if (args[0] === "oauth" && args[1] === "clients") {
    await runOAuthClientsCommand(config, args.slice(2));
    return;
  }

  const logger = createLogger(config.server.log_level);
  const authorizationServerKeys = config.oauth.as.enabled
    ? await loadAuthorizationServerKeys(config)
    : undefined;
  const oauthAuthorizationServer = authorizationServerKeys
    ? createOAuthAuthorizationServer(config, authorizationServerKeys, logger)
    : undefined;

  const authenticator = createAuthenticator(config, authorizationServerKeys);
  const backendConfigs = getBackendConfigs(config);
  const backends = await Promise.all(backendConfigs.map(async (backendConfig) => ({
    config: backendConfig,
    backend: new StdioMcpBackend(backendConfig, logger),
    instructions: await loadInstructions(backendConfig),
  })));

  logger.info("levitate starting", {
    name: config.server.name,
    backends: backendConfigs.map(({ id, mcp_path }) => ({ id, path: mcp_path })),
  });

  const startedBackends: StdioMcpBackend[] = [];
  try {
    for (const runtime of backends) {
      await runtime.backend.start();
      startedBackends.push(runtime.backend);
    }
  } catch (error) {
    await Promise.allSettled(startedBackends.map((backend) => backend.close()));
    throw error;
  }
  const server = startHttpServer({
    config,
    authenticator,
    backends,
    logger,
    oauthAuthorizationServer,
  });

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info("levitate stopping", { signal });
    const httpClosed = new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    const forceCloseTimer = setTimeout(() => {
      logger.warn("forcing remaining http connections closed", { signal });
      if ("closeAllConnections" in server) server.closeAllConnections();
    }, 1_000);
    forceCloseTimer.unref();
    await Promise.all([
      httpClosed,
      ...backends.map(({ backend }) => backend.close()),
    ]);
    clearTimeout(forceCloseTimer);
    oauthAuthorizationServer?.close();
    logger.info("levitate stopped", { signal });
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({
    time: new Date().toISOString(),
    level: "error",
    message: "levitate failed",
    error: error instanceof Error ? error.message : String(error),
  })}\n`);
  process.exit(1);
});
