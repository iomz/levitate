import { readFile } from "node:fs/promises";
import type { BackendConfig } from "../config.js";
import type { Logger } from "../logging.js";

export async function loadInstructions(config: Pick<BackendConfig, "instructions">): Promise<string | undefined> {
  if (config.instructions.text) return config.instructions.text;
  if (config.instructions.file) return readFile(config.instructions.file, "utf8");
  return undefined;
}

/**
 * Resolves the instructions Levitate advertises for one backend.
 *
 * Configuration wins when it is set, because an operator who wrote the text
 * meant it to replace whatever the backend says. Otherwise the backend's own
 * instructions are forwarded: they are part of MCP discovery, and they are the
 * only place a server can state what it does not know.
 *
 * The backend value is only available after its initialize handshake, so this
 * runs once the backend process has started rather than at configuration load.
 */
export async function resolveInstructions(
  config: Pick<BackendConfig, "id" | "instructions">,
  backend: { getInstructions(): string | undefined },
  logger: Logger,
): Promise<string | undefined> {
  const configured = await loadInstructions(config);
  const advertised = backend.getInstructions();

  if (configured !== undefined) {
    if (advertised) {
      logger.info("backend instructions overridden by configuration", {
        backend: config.id,
        backendChars: advertised.length,
      });
    }
    return configured;
  }

  if (!config.instructions.passthrough) {
    if (advertised) {
      logger.info("backend instructions suppressed by configuration", {
        backend: config.id,
        backendChars: advertised.length,
      });
    }
    return undefined;
  }

  if (advertised) {
    logger.info("backend instructions forwarded", {
      backend: config.id,
      backendChars: advertised.length,
    });
  }
  return advertised;
}
