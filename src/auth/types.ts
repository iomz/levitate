export interface AuthResult {
  subject: string;
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
