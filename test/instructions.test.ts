import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { BackendConfig } from "../src/config.js";
import { loadInstructions, resolveInstructions } from "../src/mcp/instructions.js";
import type { Logger } from "../src/logging.js";

const logger: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
const backend = { getInstructions: () => "BACKEND TEXT" };
const silentBackend = { getInstructions: () => undefined };

describe("configured instructions", () => {
  it("names the backend and the path when the file cannot be read", async () => {
    const missing = join(freshDirectory(), "gone", "SKILL.md");

    await expect(loadInstructions(config({ file: missing }))).rejects.toThrow(
      `backend "notes": cannot read instructions file '${missing}'`,
    );
  });

  it("reports the underlying filesystem reason", async () => {
    const missing = join(freshDirectory(), "SKILL.md");

    await expect(loadInstructions(config({ file: missing }))).rejects.toThrow(/ENOENT/);
  });

  it("treats an empty file as unset so the backend's own text is forwarded", async () => {
    const file = fileContaining("");

    const configured = await loadInstructions(config({ file }));

    expect(configured).toBeUndefined();
    expect(resolveInstructions(config({ file }), configured, backend, logger))
      .toBe("BACKEND TEXT");
  });

  it("treats a whitespace-only file as unset", async () => {
    const file = fileContaining("\n\n   \t\n");

    await expect(loadInstructions(config({ file }))).resolves.toBeUndefined();
  });

  it("keeps a file whose content is meaningful, including its surrounding whitespace", async () => {
    const file = fileContaining("\n# Vault\n\nRules.\n");

    await expect(loadInstructions(config({ file }))).resolves.toBe("\n# Vault\n\nRules.\n");
  });

  it("still prefers configured text over a configured file", async () => {
    const file = fileContaining("from file");

    await expect(loadInstructions(config({ text: "from text", file }))).resolves.toBe("from text");
  });

  it("returns nothing when no instructions are configured", async () => {
    await expect(loadInstructions(config({}))).resolves.toBeUndefined();
  });
});

describe("instructions resolution", () => {
  it("does not read the filesystem, so it cannot fail once a backend is running", () => {
    // The configured value is supplied by loadInstructions, which ran before
    // any backend was spawned. A path that does not exist is irrelevant here.
    const resolved = resolveInstructions(
      config({ file: "/nonexistent/SKILL.md" }),
      "already read",
      backend,
      logger,
    );

    expect(resolved).toBe("already read");
  });

  it("forwards the backend's instructions when configuration supplies none", () => {
    expect(resolveInstructions(config({}), undefined, backend, logger)).toBe("BACKEND TEXT");
  });

  it("suppresses the backend's instructions when passthrough is disabled", () => {
    expect(resolveInstructions(config({}, false), undefined, backend, logger)).toBeUndefined();
  });

  it("returns nothing when neither source has anything to say", () => {
    expect(resolveInstructions(config({}), undefined, silentBackend, logger)).toBeUndefined();
  });
});

function freshDirectory(): string {
  return mkdtempSync(join(tmpdir(), "levitate-instructions-"));
}

function fileContaining(contents: string): string {
  const file = join(freshDirectory(), "SKILL.md");
  writeFileSync(file, contents, "utf8");
  return file;
}

function config(
  instructions: { text?: string; file?: string },
  passthrough = true,
): Pick<BackendConfig, "id" | "instructions"> {
  return { id: "notes", instructions: { ...instructions, passthrough } };
}
