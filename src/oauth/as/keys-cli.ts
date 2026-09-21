import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { calculateJwkThumbprint, exportJWK } from "jose";
import type { LevitateConfig } from "../../config.js";

const MODULUS_LENGTH = 3072;
const KEY_FILE_MODE = 0o600;

export async function runOAuthKeysCommand(
  config: LevitateConfig,
  args: string[],
  stdout: Pick<NodeJS.WriteStream, "write"> = process.stdout,
): Promise<void> {
  if (args[0] !== "init") {
    throw new Error("usage: levitate oauth keys init [--force]");
  }

  // --config/-c is consumed by config resolution before dispatch, so drop it
  // here rather than rejecting it as an unknown option.
  const options: string[] = [];
  for (let index = 1; index < args.length; index += 1) {
    if (args[index] === "--config" || args[index] === "-c") {
      index += 1;
      continue;
    }
    options.push(args[index]);
  }
  const unknown = options.find((option) => option !== "--force");
  if (unknown) {
    throw new Error(`unknown option for levitate oauth keys init: ${unknown}`);
  }
  const force = options.includes("--force");

  const { private_key_file: privateKeyFile, key_id: keyId } = config.oauth.as.keys;
  if (!privateKeyFile || !keyId) {
    throw new Error("oauth.as.keys.private_key_file and oauth.as.keys.key_id are required");
  }

  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: MODULUS_LENGTH,
  });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  mkdirSync(dirname(privateKeyFile), { recursive: true });
  const replaced = force && existsSync(privateKeyFile);
  try {
    writeFileSync(privateKeyFile, pem, { mode: KEY_FILE_MODE, flag: force ? "w" : "wx" });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(
        `oauth.as.keys.private_key_file already exists at '${privateKeyFile}'. ` +
        "Pass --force to replace it, which invalidates every token signed by the previous key " +
        "immediately and requires every client to reauthorize.",
      );
    }
    throw error;
  }
  // The mode argument only applies when the file is created, so an overwrite
  // keeps whatever permissions the previous key file carried.
  chmodSync(privateKeyFile, KEY_FILE_MODE);

  const publicJwk = await exportJWK(publicKey);
  stdout.write(`${JSON.stringify({
    private_key_file: privateKeyFile,
    key_id: keyId,
    jwk_thumbprint: await calculateJwkThumbprint(publicJwk, "sha256"),
    modulus_length: MODULUS_LENGTH,
    replaced,
  }, null, 2)}\n`);
  if (replaced) {
    stdout.write(
      "Replaced the previous signing key. Every token signed by it is invalid " +
      "immediately and every client must reauthorize.\n",
    );
  }
}
