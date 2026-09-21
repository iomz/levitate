import { createPrivateKey } from "node:crypto";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { LevitateConfig } from "../src/config.js";
import { runOAuthKeysCommand } from "../src/oauth/as/keys-cli.js";
import { loadAuthorizationServerKeys } from "../src/oauth/as/keys.js";

describe("oauth signing key CLI", () => {
  it("creates an RSA-3072 PKCS#8 key the server can load", async () => {
    const privateKeyFile = keyFileInFreshStateDirectory();
    const config = keysConfig(privateKeyFile);
    const output = captureStdout();

    await runOAuthKeysCommand(config, ["init"], output);

    const pem = readFileSync(privateKeyFile, "utf8");
    expect(pem).toContain("BEGIN PRIVATE KEY");
    const privateKey = createPrivateKey(pem);
    expect(privateKey.asymmetricKeyType).toBe("rsa");
    expect(privateKey.asymmetricKeyDetails?.modulusLength).toBe(3072);
    expect(statSync(privateKeyFile).mode & 0o777).toBe(0o600);

    const reported = JSON.parse(output.text()) as Record<string, unknown>;
    expect(reported.key_id).toBe("levitate-key");
    expect(reported.jwk_thumbprint).toEqual(expect.any(String));
    expect(reported.replaced).toBe(false);

    const keys = await loadAuthorizationServerKeys(config);
    expect(keys.keyId).toBe("levitate-key");
    expect(keys.jwks.keys[0]?.kid).toBe("levitate-key");
  });

  it("refuses to overwrite an existing key without --force", async () => {
    const privateKeyFile = keyFileInFreshStateDirectory();
    const config = keysConfig(privateKeyFile);
    await runOAuthKeysCommand(config, ["init"], captureStdout());
    const original = readFileSync(privateKeyFile, "utf8");

    await expect(runOAuthKeysCommand(config, ["init"], captureStdout())).rejects.toThrow(
      /already exists.*--force/s,
    );
    expect(readFileSync(privateKeyFile, "utf8")).toBe(original);
  });

  it("replaces an existing key with --force and states the consequence", async () => {
    const privateKeyFile = keyFileInFreshStateDirectory();
    const config = keysConfig(privateKeyFile);
    await runOAuthKeysCommand(config, ["init"], captureStdout());
    const original = readFileSync(privateKeyFile, "utf8");
    const output = captureStdout();

    await runOAuthKeysCommand(config, ["init", "--config", "unused.toml", "--force"], output);

    expect(readFileSync(privateKeyFile, "utf8")).not.toBe(original);
    expect(statSync(privateKeyFile).mode & 0o777).toBe(0o600);
    expect(output.text()).toContain("every client must reauthorize");
  });

  it("names the init command when the key file is missing", async () => {
    const privateKeyFile = keyFileInFreshStateDirectory();

    await expect(loadAuthorizationServerKeys(keysConfig(privateKeyFile))).rejects.toThrow(
      "Create one with: levitate oauth keys init --config <config>",
    );
  });
});

function keyFileInFreshStateDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "levitate-keys-"));
  return join(directory, "state", "oauth-private-key.pem");
}

function captureStdout(): Pick<NodeJS.WriteStream, "write"> & { text(): string } {
  const chunks: string[] = [];
  return {
    write: (chunk: string) => {
      chunks.push(chunk);
      return true;
    },
    text: () => chunks.join(""),
  } as Pick<NodeJS.WriteStream, "write"> & { text(): string };
}

function keysConfig(privateKeyFile: string): LevitateConfig {
  return {
    server: {
      name: "test",
      host: "127.0.0.1",
      port: 8787,
      log_level: "info",
      mcp_path: "/mcp",
    },
    stdio: { command: "node", args: [] },
    env: {},
    instructions: {},
    auth: { mode: "bearer", token: "secret" },
    oauth: {
      resource: {
        enabled: false,
        mode: "service",
        authorization_servers: [],
        scopes_supported: [],
      },
      as: {
        enabled: true,
        issuer: "https://levitate.example.com",
        subject: "owner",
        approval: "auto",
        dcr: { enabled: false },
        cimd: { enabled: false, allowed_client_id_prefixes: [] },
        allowed_redirect_uri_prefixes: ["https://chatgpt.com/"],
        scopes_supported: ["gateway:access"],
        default_scopes: ["gateway:access"],
        access_token_ttl_seconds: 3600,
        refresh_token_ttl_seconds: 2_592_000,
        authorization_code_ttl_seconds: 300,
        keys: { private_key_file: privateKeyFile, key_id: "levitate-key" },
      },
    },
    tools: { deny: [] },
  };
}
