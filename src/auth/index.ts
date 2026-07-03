import { BearerAuthenticator } from "./bearer.js";
import { LevitateJwtAuthenticator } from "./levitate.js";
import { OidcJwtAuthenticator } from "./oidc.js";
import type { Authenticator } from "./types.js";
import type { LevitateConfig } from "../config.js";
import { resolveBearerToken } from "../config.js";
import type { AuthorizationServerKeys } from "../oauth/as/keys.js";

export function createAuthenticator(
  config: LevitateConfig,
  authorizationServerKeys?: AuthorizationServerKeys,
): Authenticator {
  const auth = config.auth;
  if (auth.mode === "bearer") {
    return new BearerAuthenticator(resolveBearerToken(auth));
  }

  if (auth.mode === "levitate") {
    if (!authorizationServerKeys) {
      throw new Error("oauth authorization server keys are required for levitate auth");
    }
    return new LevitateJwtAuthenticator(config, authorizationServerKeys);
  }

  return new OidcJwtAuthenticator(auth);
}
