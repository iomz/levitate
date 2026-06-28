import { BearerAuthenticator } from "./bearer.js";
import { OidcJwtAuthenticator } from "./oidc.js";
import type { Authenticator } from "./types.js";
import type { AuthConfig } from "../config.js";
import { resolveBearerToken } from "../config.js";

export function createAuthenticator(auth: AuthConfig): Authenticator {
  if (auth.mode === "bearer") {
    return new BearerAuthenticator(resolveBearerToken(auth));
  }

  return new OidcJwtAuthenticator(auth);
}
