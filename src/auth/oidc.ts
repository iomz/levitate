import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import { Authenticator, AuthError, type AuthResult } from "./types.js";

export interface OidcConfig {
  issuer: string;
  audience: string;
  jwks_uri?: string;
  allowed_subjects?: string[];
  allowed_emails?: string[];
}

export class OidcJwtAuthenticator implements Authenticator {
  private readonly jwks: JWTVerifyGetKey;

  constructor(
    private readonly config: OidcConfig,
    jwks: JWTVerifyGetKey = createRemoteJWKSet(new URL(config.jwks_uri ?? defaultJwksUri(config.issuer))),
    private readonly currentDate?: Date,
  ) {
    this.jwks = jwks;
  }

  async authenticate(request: Request): Promise<AuthResult> {
    const token = parseBearerToken(request.headers.get("authorization"));
    const payload = await this.verifyToken(token);
    return { subject: payload.sub };
  }

  async verifyToken(token: string): Promise<{ sub: string; email?: string }> {
    const payload = await this.verifyJwt(token);

    if (!payload.sub) {
      throw new AuthError("missing jwt subject");
    }

    const email = getEmail(payload);
    if (this.config.allowed_subjects?.length && !this.config.allowed_subjects.includes(payload.sub)) {
      throw new AuthError("jwt subject not allowed");
    }

    if (this.config.allowed_emails?.length && payload.email_verified !== true) {
      throw new AuthError("jwt email not verified");
    }

    if (this.config.allowed_emails?.length && (!email || !this.config.allowed_emails.includes(email))) {
      throw new AuthError("jwt email not allowed");
    }

    return { sub: payload.sub, email };
  }

  private async verifyJwt(token: string): Promise<JWTPayload> {
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.config.issuer,
        audience: this.config.audience,
        algorithms: ["RS256"],
        currentDate: this.currentDate,
      });
      return payload;
    } catch {
      throw new AuthError("invalid oidc token");
    }
  }
}

export function parseBearerToken(authorization: string | null): string {
  if (!authorization) throw new AuthError("missing authorization header");

  const match = authorization.match(/^Bearer (.+)$/);
  if (!match) throw new AuthError("invalid authorization scheme");
  return match[1];
}

function getEmail(payload: JWTPayload): string | undefined {
  return typeof payload.email === "string" ? payload.email : undefined;
}

export function defaultJwksUri(issuer: string): string {
  const base = issuer.endsWith("/") ? issuer : `${issuer}/`;
  return new URL(".well-known/jwks.json", base).toString();
}
