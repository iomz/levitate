import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
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

  // 0o700 on directories this creates. mkdir's default is 0o777 masked by the
  // umask, so a permissive umask would leave the key's own directory writable
  // by other local users, who could then replace a key they cannot read.
  // Directories that already exist keep their permissions.
  mkdirSync(dirname(privateKeyFile), { recursive: true, mode: 0o700 });
  const replaced = force && existsSync(privateKeyFile);
  writeKeyFile(privateKeyFile, pem, force);

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

function writeKeyFile(privateKeyFile: string, pem: string, force: boolean): void {
  if (!force) {
    try {
      // "wx" is O_CREAT|O_EXCL, which fails on any existing path including a
      // symbolic link, so the refusal below is also the symlink guard.
      writeFileSync(privateKeyFile, pem, { mode: KEY_FILE_MODE, flag: "wx" });
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
    // The requested mode is masked by the umask on creation, so set it exactly.
    // The path is one this process just created exclusively, never a link.
    chmodSync(privateKeyFile, KEY_FILE_MODE);
    return;
  }

  // Writing to the destination with "w" would follow a symbolic link sitting
  // there, and so would the chmod that has to follow it, letting anyone who can
  // create that link redirect the write. Creating a fresh file exclusively and
  // renaming it over the destination replaces the link itself. The rename is
  // also atomic, so a crash mid-write cannot leave a truncated key behind.
  const temporaryFile = join(
    dirname(privateKeyFile),
    `.${basename(privateKeyFile)}.${randomBytes(8).toString("hex")}`,
  );
  try {
    writeFileSync(temporaryFile, pem, { mode: KEY_FILE_MODE, flag: "wx" });
    chmodSync(temporaryFile, KEY_FILE_MODE);
    renameSync(temporaryFile, privateKeyFile);
  } catch (error) {
    if (existsSync(temporaryFile)) unlinkSync(temporaryFile);
    throw error;
  }
}
