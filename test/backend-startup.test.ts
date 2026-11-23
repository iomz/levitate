import { describe, expect, it } from "vitest";
import type { BackendConfig } from "../src/config.js";
import type { Logger } from "../src/logging.js";
import { startBackends, type StartableBackend } from "../src/mcp/startup.js";

class FakeBackend implements StartableBackend {
  started = false;
  closed = false;

  constructor(readonly config: BackendConfig, private readonly failure?: string) {}

  async start(): Promise<void> {
    if (this.failure) throw new Error(this.failure);
    this.started = true;
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  getInstructions(): string | undefined {
    return `${this.config.id} instructions`;
  }
}

describe("backend startup isolation", () => {
  it("keeps healthy backends when one has an unreadable instructions file", async () => {
    const { logger, errors } = recordingLogger();
    const created: FakeBackend[] = [];

    const runtimes = await startBackends(
      [backendConfig("healthy"), backendConfig("broken", "/nonexistent/SKILL.md")],
      (config) => track(created, new FakeBackend(config)),
      logger,
    );

    expect(runtimes.map(({ config, startupError }) => [config.id, startupError])).toEqual([
      ["healthy", undefined],
      ["broken", expect.stringContaining(`backend "broken": cannot read instructions file`)],
    ]);
    expect(runtimes[0].instructions).toBe("healthy instructions");
    // The broken backend's process is never spawned.
    expect(created.map((backend) => backend.started)).toEqual([true, false]);
    expect(errors).toEqual([{
      message: "backend failed to start",
      fields: { backend: "broken", error: runtimes[1].startupError },
    }]);
  });

  it("keeps healthy backends when one fails to spawn, and closes what it left", async () => {
    const { logger } = recordingLogger();
    const created: FakeBackend[] = [];

    const runtimes = await startBackends(
      [backendConfig("broken"), backendConfig("healthy")],
      (config) => track(created, new FakeBackend(
        config,
        config.id === "broken" ? "spawn ENOENT" : undefined,
      )),
      logger,
    );

    expect(runtimes[0].startupError).toBe(`backend "broken": failed to start: spawn ENOENT`);
    expect(runtimes[1].startupError).toBeUndefined();
    expect(created[0].closed).toBe(true);
    expect(created[1].started).toBe(true);
  });

  it("fails startup when no backend starts, naming each one", async () => {
    const { logger } = recordingLogger();

    await expect(startBackends(
      [backendConfig("first", "/nonexistent/a.md"), backendConfig("second")],
      (config) => new FakeBackend(config, config.id === "second" ? "boom" : undefined),
      logger,
    )).rejects.toThrow(
      /^backend "first": cannot read instructions file .*; backend "second": failed to start: boom$/,
    );
  });
});

function track(created: FakeBackend[], backend: FakeBackend): FakeBackend {
  created.push(backend);
  return backend;
}

function backendConfig(id: string, instructionsFile?: string): BackendConfig {
  return {
    id,
    name: id,
    mcp_path: `/${id}/mcp`,
    stdio: { command: "unused", args: [] },
    env: {},
    instructions: { file: instructionsFile, passthrough: true },
    principal: { enabled: false },
    tools: { deny: [] },
  };
}

function recordingLogger(): {
  logger: Logger;
  errors: { message: string; fields?: Record<string, unknown> }[];
} {
  const errors: { message: string; fields?: Record<string, unknown> }[] = [];
  return {
    errors,
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: (message, fields) => errors.push({ message, fields }),
    },
  };
}
