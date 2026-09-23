#!/usr/bin/env node
import { createAuthenticator } from "./auth/index.js";
import { getBackendConfigs, getConfigPath, loadConfig } from "./config.js";
import { createLogger } from "./logging.js";
import { StdioMcpBackend } from "./mcp/backend.js";
import { loadInstructions, resolveInstructions } from "./mcp/instructions.js";
import { runOAuthClientsCommand } from "./oauth/as/clients-cli.js";
import { runOAuthKeysCommand } from "./oauth/as/keys-cli.js";
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
  if (args[0] === "oauth" && args[1] === "keys") {
    await runOAuthKeysCommand(config, args.slice(2));
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
  // Configured instructions files are read here, before any backend process is
  // spawned, so a misconfigured path fails without costing a start and stop
  // cycle. The backend's own instructions are only available from its
  // handshake, so the two are combined once it has started.
  const backends = await Promise.all(backendConfigs.map(async (backendConfig) => ({
    config: backendConfig,
    backend: new StdioMcpBackend(backendConfig, logger),
    configuredInstructions: await loadInstructions(backendConfig),
    instructions: undefined as string | undefined,
  })));

  logger.info("levitate starting", {
    name: config.server.name,
    backends: backendConfigs.map(({ id, mcp_path }) => ({ id, path: mcp_path })),
  });

  const startedBackends: StdioMcpBackend[] = [];
  let server: ReturnType<typeof startHttpServer>;
  try {
    for (const runtime of backends) {
      await runtime.backend.start();
      startedBackends.push(runtime.backend);
      runtime.instructions = resolveInstructions(
        runtime.config,
        runtime.configuredInstructions,
        runtime.backend,
        logger,
      );
    }
    server = startHttpServer({
      config,
      authenticator,
      backends,
      logger,
      oauthAuthorizationServer,
    });
  } catch (error) {
    await Promise.allSettled(startedBackends.map((backend) => backend.close()));
    throw error;
  }
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
    try {
      await Promise.all([
        httpClosed,
        ...backends.map(({ backend }) => backend.close()),
      ]);
    } catch (error) {
      logger.warn("shutdown error", {
        error: error instanceof Error ? error.message : String(error),
      });
    } finally {
      clearTimeout(forceCloseTimer);
      oauthAuthorizationServer?.close();
      logger.info("levitate stopped", { signal });
      process.exit(0);
    }
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
