import { jwtVerify, SignJWT, type JWTPayload } from "jose";
import type { AuthorizationServerKeys } from "./keys.js";
import type { LevitateConfig } from "../../config.js";
import { getClientId } from "../../auth/oidc.js";
import { AuthError, type AuthResult } from "../../auth/types.js";

export interface AccessTokenInput {
  clientId: string;
  scopes: string[];
  subject?: string;
}

export async function issueAccessToken(
  input: AccessTokenInput,
  config: LevitateConfig,
  keys: AuthorizationServerKeys,
): Promise<string> {
  const asConfig = config.oauth.as;
  const resource = config.oauth.resource.resource;
  if (!asConfig.enabled || !asConfig.issuer || !asConfig.subject || !resource) {
    throw new Error("oauth authorization server config is incomplete");
  }

  return new SignJWT({
    scope: input.scopes.join(" "),
    client_id: input.clientId,
  })
    .setProtectedHeader({ alg: "RS256", kid: keys.keyId, typ: "JWT" })
    .setIssuer(asConfig.issuer)
    .setSubject(input.subject ?? asConfig.subject)
    .setAudience(resource)
    .setIssuedAt()
    .setExpirationTime(`${asConfig.access_token_ttl_seconds}s`)
    .sign(keys.privateKey);
}

export async function verifyLevitateAccessToken(
  token: string,
  config: LevitateConfig,
  keys: AuthorizationServerKeys,
  currentDate?: Date,
): Promise<AuthResult> {
  const asConfig = config.oauth.as;
  const resource = config.oauth.resource.resource;
  if (!asConfig.enabled || !asConfig.issuer || !resource) {
    throw new AuthError("levitate auth is not configured");
  }

  let payload: JWTPayload;
  try {
    const result = await jwtVerify(token, keys.publicKey, {
      issuer: asConfig.issuer,
      audience: resource,
      algorithms: ["RS256"],
      currentDate,
    });
    payload = result.payload;
  } catch {
    throw new AuthError("invalid levitate token");
  }

  if (!payload.sub) throw new AuthError("missing jwt subject");
  const clientId = getClientId(payload);
  if (!clientId) throw new AuthError("missing jwt client id");

  return {
    kind: "levitate",
    subject: payload.sub,
    clientId,
    scopes: parseScopes(payload),
    audience: payload.aud,
    issuer: payload.iss,
  };
}

function parseScopes(payload: JWTPayload): string[] {
  if (typeof payload.scope !== "string") return [];
  return payload.scope.split(" ").map((scope) => scope.trim()).filter(Boolean);
}
