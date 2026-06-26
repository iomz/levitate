import { AuthError, type Authenticator, type AuthResult } from "./types.js";

export class OidcAuthenticator implements Authenticator {
  async authenticate(): Promise<AuthResult> {
    throw new AuthError("oidc auth is not implemented in MVP");
  }
}
