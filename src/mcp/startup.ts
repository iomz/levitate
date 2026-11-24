import type { BackendConfig } from "../config.js";
import type { Logger } from "../logging.js";
import { loadInstructions, resolveInstructions } from "./instructions.js";

export interface StartableBackend {
  start(): Promise<void>;
  close(): Promise<void>;
  getInstructions(): string | undefined;
}

export interface StartedBackend<B extends StartableBackend> {
  config: BackendConfig;
  backend: B;
  instructions?: string;
  /**
   * Set when this backend could not be started. Its MCP path answers 503 and
   * /ready reports it as failed; the reason itself goes to the log only,
   * because /ready is unauthenticated and the reason can name local paths.
   */
  startupError?: string;
}

/**
 * Starts every configured backend, isolating failures to the backend that
 * caused them.
 *
 * One backend's bad configuration or failed spawn used to take the whole
 * gateway down, including backends that had nothing wrong with them. Now a
 * backend that cannot start is marked failed and logged at error level while
 * the rest serve. Startup still fails when no backend starts, since a gateway
 * serving nothing should not look like a running one.
 *
 * Configured instructions files are all read before any backend process is
 * spawned, so a bad path costs no start and stop cycle. The backend's own
 * instructions are only available from its handshake, so the two are combined
 * once it has started.
 */
export async function startBackends<B extends StartableBackend>(
  configs: BackendConfig[],
  createBackend: (config: BackendConfig) => B,
  logger: Logger,
): Promise<StartedBackend<B>[]> {
  const configured = await Promise.all(configs.map((config) =>
    loadInstructions(config).then(
      (value) => ({ value, error: undefined }),
      (error: unknown) => ({ value: undefined, error: errorMessage(error) }),
    )));

  const runtimes: StartedBackend<B>[] = [];
  for (const [index, config] of configs.entries()) {
    const backend = createBackend(config);
    const loaded = configured[index];
    // loadInstructions already names the backend in its message.
    let startupError = loaded.error;
    if (!startupError) {
      try {
        await backend.start();
      } catch (error) {
        startupError = `backend "${config.id}": failed to start: ${errorMessage(error)}`;
        // A failed handshake can leave a spawned process behind.
        await backend.close().catch(() => {});
      }
    }

    if (startupError) {
      logger.error("backend failed to start", { backend: config.id, error: startupError });
      runtimes.push({ config, backend, startupError });
      continue;
    }

    runtimes.push({
      config,
      backend,
      instructions: resolveInstructions(config, loaded.value, backend, logger),
    });
  }

  if (runtimes.every((runtime) => runtime.startupError)) {
    throw new Error(runtimes.map((runtime) => runtime.startupError).join("; "));
  }
  return runtimes;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
