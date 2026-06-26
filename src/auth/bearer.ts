import { Authenticator, AuthError, type AuthResult } from "./types.js";

export class BearerAuthenticator implements Authenticator {
  constructor(private readonly token: string) {}

  async authenticate(request: Request): Promise<AuthResult> {
    const authorization = request.headers.get("authorization");
    if (!authorization) throw new AuthError("missing authorization header");

    const match = authorization.match(/^Bearer (.+)$/);
    if (!match) throw new AuthError("invalid authorization scheme");

    if (match[1] !== this.token) throw new AuthError("invalid bearer token");
    return { subject: "bearer-token" };
  }
}

export function validateBearerAuthorization(
  authorization: string | null,
  token: string,
): AuthResult {
  const request = new Request("http://levitate.local/mcp", {
    headers: authorization ? { authorization } : {},
  });
  const match = request.headers.get("authorization")?.match(/^Bearer (.+)$/);
  if (!match) throw new AuthError("missing or invalid bearer token");
  if (match[1] !== token) throw new AuthError("invalid bearer token");
  return { subject: "bearer-token" };
}
