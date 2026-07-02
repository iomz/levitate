import { Authenticator, AuthError, type AuthResult } from "./types.js";

export class BearerAuthenticator implements Authenticator {
  constructor(private readonly token: string) {}

  async authenticate(request: Request): Promise<AuthResult> {
    return validateBearerAuthorization(request.headers.get("authorization"), this.token);
  }
}

export function validateBearerAuthorization(
  authorization: string | null,
  token: string,
): AuthResult {
  if (!authorization) throw new AuthError("missing authorization header");

  const match = authorization.match(/^Bearer (.+)$/);
  if (!match) throw new AuthError("invalid authorization scheme");

  if (match[1] !== token) throw new AuthError("invalid bearer token");
  return { kind: "bearer", subject: "bearer-token", scopes: [] };
}
