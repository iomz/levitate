import { readFileSync } from "node:fs";

const packageJsonUrls = [
  new URL("../package.json", import.meta.url),
  new URL("../../package.json", import.meta.url),
];

export const LEVITATE_VERSION = readLevitateVersion();

function readLevitateVersion(): string {
  for (const packageJsonUrl of packageJsonUrls) {
    try {
      const parsed = JSON.parse(readFileSync(packageJsonUrl, "utf8")) as {
        version?: unknown;
      };
      if (typeof parsed.version === "string" && parsed.version.length > 0) {
        return parsed.version;
      }
    } catch {
      // Try source and compiled module layouts before failing startup.
    }
  }
  throw new Error("unable to read Levitate version from package.json");
}
