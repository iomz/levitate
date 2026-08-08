import type { Hono } from "hono";
import type { LevitateConfig } from "../../config.js";
import type { Logger } from "../../logging.js";
import { AuthorizationCodeStore, verifyPkceS256 } from "./codes.js";
import type { AuthorizationServerKeys } from "./keys.js";
import type { ClientLookup } from "./store.js";
import { issueAccessToken } from "./tokens.js";
import { isValidPkceVerifier, stringFormValue } from "./validation.js";
import type { OAuthRateLimiter } from "./rate-limit.js";
import { oauthAudit, oauthClientAuditFields } from "./audit.js";

export function registerTokenRoute(app: Hono, config: LevitateConfig, keys: AuthorizationServerKeys, clients: ClientLookup, codes: AuthorizationCodeStore, logger: Logger, rateLimiter?: OAuthRateLimiter): void {
  const asConfig = config.oauth.as;
  app.post("/oauth/token", async (c) => {
    const form = await c.req.parseBody();
    const grantType = stringFormValue(form.grant_type);
    const code = stringFormValue(form.code);
    const redirectUri = stringFormValue(form.redirect_uri);
    const clientId = stringFormValue(form.client_id);
    const codeVerifier = stringFormValue(form.code_verifier);
    const resource = stringFormValue(form.resource);

    if (grantType !== "authorization_code")
      return c.json({ error: "unsupported_grant_type" }, 400);
    if (!code || !redirectUri || !clientId || !codeVerifier || !resource) {
      logger.warn("oauth token request rejected", {
        ...oauthAudit(c, "token_exchange", "rejected"),
        error: "invalid_request",
        grantType,
        hasCode: Boolean(code),
        redirectUri,
        ...oauthClientAuditFields(clientId),
        hasCodeVerifier: Boolean(codeVerifier),
        resource,
      });
      return c.json({ error: "invalid_request" }, 400);
    }

    const retryAfter = rateLimiter?.consume("token", clientId);
    if (retryAfter) {
      c.header("Retry-After", String(retryAfter));
      logger.warn("oauth audit", {
        ...oauthAudit(c, "token_exchange", "rate_limited"),
        ...oauthClientAuditFields(clientId),
      });
      return c.json({ error: "temporarily_unavailable" }, 429);
    }
    const client = await clients.get(clientId);
    if (!client || client.revoked_at) {
      logger.warn("oauth token request rejected", {
        ...oauthAudit(c, "token_exchange", "rejected"),
        error: "invalid_client",
        ...oauthClientAuditFields(clientId),
        hasClient: Boolean(client),
        revoked: Boolean(client?.revoked_at),
      });
      return c.json({ error: "invalid_client" }, 400);
    }
    let record;
    try {
      record = codes.get(code);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "invalid authorization code";
      logger.warn("oauth token code rejected", {
        ...oauthAudit(c, "token_exchange", "rejected"),
        message,
      });
      return c.json({ error: "invalid_grant" }, 400);
    }

    if (
      record.clientId !== clientId ||
      record.redirectUri !== redirectUri ||
      record.resource !== resource ||
      !isValidPkceVerifier(codeVerifier) ||
      !verifyPkceS256(codeVerifier, record.codeChallenge)
    ) {
      logger.warn("oauth token request rejected", {
        ...oauthAudit(c, "token_exchange", "rejected"),
        error: "invalid_grant",
        ...oauthClientAuditFields(clientId),
        codeClientMatches: record.clientId === clientId,
        redirectUri,
        codeRedirectUri: record.redirectUri,
        resource,
        codeResource: record.resource,
        validVerifierSyntax: isValidPkceVerifier(codeVerifier),
      });
      return c.json({ error: "invalid_grant" }, 400);
    }

    codes.markUsed(code);

    const accessToken = await issueAccessToken(
      {
        clientId,
        scopes: record.scopes,
      },
      config,
      keys,
    );

    logger.info("oauth audit", {
      ...oauthAudit(c, "token_exchange", "succeeded"),
      ...oauthClientAuditFields(clientId),
      scopes: record.scopes,
    });

    return c.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: asConfig.access_token_ttl_seconds,
      scope: record.scopes.join(" "),
    });
  });
}
