import { readFile } from "node:fs/promises";
import type { BackendConfig } from "../config.js";

export async function loadInstructions(config: Pick<BackendConfig, "instructions">): Promise<string | undefined> {
  if (config.instructions.text) return config.instructions.text;
  if (config.instructions.file) return readFile(config.instructions.file, "utf8");
  return undefined;
}
