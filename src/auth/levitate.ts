import { parseBearerToken } from "./oidc.js";
import type { Authenticator, AuthResult } from "./types.js";
import type { LevitateConfig } from "../config.js";
import type { AuthorizationServerKeys } from "../oauth/as/keys.js";
import { verifyLevitateAccessToken } from "../oauth/as/tokens.js";

export class LevitateJwtAuthenticator implements Authenticator {
  constructor(
    private readonly config: LevitateConfig,
    private readonly keys: AuthorizationServerKeys,
    private readonly currentDate?: Date,
  ) {}

  async authenticate(request: Request): Promise<AuthResult> {
    const token = parseBearerToken(request.headers.get("authorization"));
    return verifyLevitateAccessToken(token, this.config, this.keys, this.currentDate);
  }
}
