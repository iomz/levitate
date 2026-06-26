import { readFile } from "node:fs/promises";
import type { LevitateConfig } from "../config.js";

export async function loadInstructions(config: LevitateConfig): Promise<string | undefined> {
  if (config.instructions.text) return config.instructions.text;
  if (config.instructions.file) return readFile(config.instructions.file, "utf8");
  return undefined;
}
