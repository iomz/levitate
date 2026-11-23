import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

/**
 * The ordering and isolation this covers live in main(), which no other test
 * exercises: a regression that moved the instructions read back after
 * backend.start(), or let one backend's failure stop the gateway, would still
 * satisfy every unit test, because they call the steps directly.
 */
describe("startup ordering", () => {
  it("serves the healthy backend when another has an unreadable instructions file", async () => {
    const result = await runLevitate(configText("/nonexistent/SKILL.md"), { exitAfterReady: true });

    // The logs are JSON lines, so assert on the record rather than on the
    // escaping of a substring.
    const failure = logRecords(result.output).find((record) => record.message === "backend failed to start");
    expect(failure?.backend).toBe("broken");
    expect(failure?.error).toBe(
      `backend "broken": cannot read instructions file '/nonexistent/SKILL.md': ` +
      "ENOENT: no such file or directory, open '/nonexistent/SKILL.md'",
    );
    // Only the healthy backend is spawned; the broken one never costs a cycle.
    expect(result.output.match(/backend process starting/g)).toHaveLength(1);
    expect(result.output).toContain("http server starting");
    expect(result.output).not.toContain("levitate failed");
  }, 60_000);

  it("fails without spawning anything when no backend can start", async () => {
    const result = await runLevitate(configText("/nonexistent/SKILL.md", { allBroken: true }));

    expect(result.code).toBe(1);
    const failure = logRecords(result.output).find((record) => record.message === "levitate failed");
    expect(failure?.error).toContain(`backend "healthy": cannot read instructions file`);
    expect(failure?.error).toContain(`backend "broken": cannot read instructions file`);
    expect(result.output).not.toContain("backend process starting");
  }, 60_000);

  it("starts backends when every configured instructions file is readable", async () => {
    const directory = mkdtempSync(join(tmpdir(), "levitate-startup-"));
    const skill = join(directory, "SKILL.md");
    writeFileSync(skill, "# Vault\n", "utf8");

    const result = await runLevitate(configText(skill), { exitAfterReady: true });

    expect(result.output).toContain("backend process starting");
    expect(result.output).toContain("http server starting");
    expect(result.output).not.toContain("backend failed to start");
  }, 60_000);
});

function logRecords(output: string): { message?: string; error?: string; backend?: string }[] {
  return output
    .split("\n")
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line) as { message?: string; error?: string; backend?: string });
}

function configText(instructionsFile: string, options: { allBroken?: boolean } = {}): string {
  const fixture = resolve(repoRoot, "test/fixtures/fake-stdio-server.mjs");
  return [
    "[server]",
    'name = "startup-test"',
    "port = 8801",
    "",
    "[backends.healthy]",
    'mcp_path = "/healthy/mcp"',
    "[backends.healthy.stdio]",
    `command = "${process.execPath}"`,
    `args = ["${fixture}"]`,
    ...(options.allBroken ? ["[backends.healthy.instructions]", `file = "${instructionsFile}"`] : []),
    "",
    "[backends.broken]",
    'mcp_path = "/broken/mcp"',
    "[backends.broken.stdio]",
    `command = "${process.execPath}"`,
    `args = ["${fixture}"]`,
    "[backends.broken.instructions]",
    `file = "${instructionsFile}"`,
    "",
    "[auth]",
    'mode = "bearer"',
    'token_env = "LEVITATE_TOKEN"',
    "",
  ].join("\n");
}

async function runLevitate(
  configContents: string,
  options: { exitAfterReady?: boolean } = {},
): Promise<{ code: number | null; output: string }> {
  const directory = mkdtempSync(join(tmpdir(), "levitate-startup-"));
  const configPath = join(directory, "levitate.toml");
  writeFileSync(configPath, configContents, "utf8");

  return new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      [resolve(repoRoot, "node_modules/tsx/dist/cli.mjs"), "src/index.ts", "--config", configPath],
      { cwd: repoRoot, env: { ...process.env, LEVITATE_TOKEN: "startup-test" } },
    );

    let output = "";
    const collect = (chunk: Buffer) => {
      output += chunk.toString();
      // The success case never exits on its own, so stop it once the HTTP
      // server is up and the ordering has been observed.
      if (options.exitAfterReady && output.includes("http server starting")) child.kill("SIGTERM");
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.on("error", reject);
    child.on("close", (code) => resolvePromise({ code, output }));
  });
}
