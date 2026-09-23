import { readFile } from "node:fs/promises";
import type { BackendConfig } from "../config.js";
import type { Logger } from "../logging.js";

/**
 * Reads the instructions a backend's configuration supplies, if any.
 *
 * This runs before any backend process is spawned. Reading the file late — once
 * the backend was already running — meant a misconfigured path cost a start and
 * stop cycle before failing, and in a crash loop it did so every time.
 *
 * An unreadable file is fatal, deliberately. Configuring one is a statement
 * that this text should be served in place of whatever the backend advertises,
 * and quietly serving something else instead is the silent substitution this
 * gateway already refuses to make in the other direction.
 */
export async function loadInstructions(
  config: Pick<BackendConfig, "id" | "instructions">,
): Promise<string | undefined> {
  if (config.instructions.text) return config.instructions.text;

  const file = config.instructions.file;
  if (!file) return undefined;

  let contents: string;
  try {
    contents = await readFile(file, "utf8");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `backend "${config.id}": cannot read instructions file '${file}': ${message}`,
    );
  }

  // A file with nothing in it is treated as unset, matching how an empty
  // instructions.text behaves. Otherwise truncating a file would suppress the
  // backend's own instructions and serve an empty string, with no error to say
  // so — the same silent drop as serving none at all.
  return contents.trim().length > 0 ? contents : undefined;
}

/**
 * Resolves the instructions Levitate advertises for one backend.
 *
 * Configuration wins when it is set, because an operator who wrote the text
 * meant it to replace whatever the backend says. Otherwise the backend's own
 * instructions are forwarded: they are part of MCP discovery, and they are the
 * only place a server can state what it does not know.
 *
 * `configured` comes from loadInstructions, read before the backend started.
 * This step only needs the backend's handshake value, so it does no I/O and
 * cannot fail.
 */
export function resolveInstructions(
  config: Pick<BackendConfig, "id" | "instructions">,
  configured: string | undefined,
  backend: { getInstructions(): string | undefined },
  logger: Logger,
): string | undefined {
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
