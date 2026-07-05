#!/usr/bin/env node
import { createAuthenticator } from "./auth/index.js";
import { getConfigPath, loadConfig } from "./config.js";
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
  const instructions = await loadInstructions(config);
  const backend = new StdioMcpBackend(config, logger);

  logger.info("levitate starting", {
    name: config.server.name,
    instructionsLoaded: Boolean(instructions),
  });

  await backend.start();
  const server = startHttpServer({
    config,
    authenticator,
    backend,
    instructions,
    logger,
    oauthAuthorizationServer,
  });

  const shutdown = async (signal: string) => {
    logger.info("levitate stopping", { signal });
    server.close();
    await backend.close();
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
