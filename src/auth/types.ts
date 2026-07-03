export interface AuthResult {
  kind: "bearer" | "oidc" | "levitate";
  subject?: string;
  email?: string;
  clientId?: string;
  scopes: string[];
  audience?: string | string[];
  issuer?: string;
}

export interface Authenticator {
  authenticate(request: Request): Promise<AuthResult>;
}

export class AuthError extends Error {
  readonly status = 401;

  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}
