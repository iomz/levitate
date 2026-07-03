import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { exportJWK, type JWK } from "jose";
import type { LevitateConfig } from "../../config.js";

export interface AuthorizationServerKeys {
  privateKey: KeyObject;
  publicKey: KeyObject;
  jwks: { keys: JWK[] };
  keyId: string;
}

export async function loadAuthorizationServerKeys(config: LevitateConfig): Promise<AuthorizationServerKeys> {
  const asConfig = config.oauth.as;
  if (!asConfig.enabled) {
    throw new Error("oauth authorization server is not enabled");
  }

  const keyId = asConfig.keys.key_id;
  const privateKeyFile = asConfig.keys.private_key_file;
  if (!keyId || !privateKeyFile) {
    throw new Error("oauth.as.keys.private_key_file and oauth.as.keys.key_id are required");
  }

  try {
    const privateKey = createPrivateKey(readFileSync(privateKeyFile, "utf8"));
    if (privateKey.asymmetricKeyType !== "rsa") {
      throw new Error("oauth.as.keys.private_key_file must contain an RSA private key");
    }

    const publicKey = createPublicKey(privateKey);
    const publicJwk = await exportJWK(publicKey);
    return {
      privateKey,
      publicKey,
      keyId,
      jwks: {
        keys: [{
          ...publicJwk,
          kid: keyId,
          alg: "RS256",
          use: "sig",
        }],
      },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`failed to load oauth authorization server signing key: ${message}`);
  }
}
