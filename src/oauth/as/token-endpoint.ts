import type { Context, Hono } from "hono";
import type { LevitateConfig } from "../../config.js";
import type { Logger } from "../../logging.js";
import { AuthorizationCodeStore, verifyPkceS256 } from "./codes.js";
import type { AuthorizationServerKeys } from "./keys.js";
import type { ClientLookup, OAuthClient } from "./store.js";
import { issueAccessToken } from "./tokens.js";
import { isValidPkceVerifier, stringFormValue } from "./validation.js";
import type { OAuthRateLimiter } from "./rate-limit.js";
import { oauthAudit, oauthClientAuditFields } from "./audit.js";
import {
  JsonRefreshTokenStore,
  RefreshTokenError,
} from "./refresh-tokens.js";

export function registerTokenRoute(
  app: Hono,
  config: LevitateConfig,
  keys: AuthorizationServerKeys,
  clients: ClientLookup,
  codes: AuthorizationCodeStore,
  refreshTokens: JsonRefreshTokenStore,
  logger: Logger,
  rateLimiter?: OAuthRateLimiter,
): void {
  app.post("/oauth/token", async (c) => {
    const form = await c.req.parseBody();
    const grantType = stringFormValue(form.grant_type);
    const clientId = stringFormValue(form.client_id);

    if (!clientId || !["authorization_code", "refresh_token"].includes(grantType ?? "")) {
      return c.json({
        error: grantType && grantType !== "authorization_code" && grantType !== "refresh_token"
          ? "unsupported_grant_type"
          : "invalid_request",
      }, 400);
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

    if (grantType === "refresh_token") {
      return exchangeRefreshToken(
        c,
        form,
        clientId,
        client,
        config,
        keys,
        refreshTokens,
        logger,
      );
    }

    const code = stringFormValue(form.code);
    const redirectUri = stringFormValue(form.redirect_uri);
    const codeVerifier = stringFormValue(form.code_verifier);
    const resource = stringFormValue(form.resource);
    if (!code || !redirectUri || !codeVerifier || !resource) {
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

    let record;
    try {
      record = codes.get(code);
    } catch (error) {
      logger.warn("oauth token code rejected", {
        ...oauthAudit(c, "token_exchange", "rejected"),
        message: error instanceof Error ? error.message : "invalid authorization code",
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
      { clientId, scopes: record.scopes, subject: record.subject },
      config,
      keys,
    );
    const refreshGrant = client.grant_types.includes("refresh_token")
      ? await refreshTokens.issue(
          {
            client_id: clientId,
            resource: record.resource,
            subject: record.subject,
            scopes: record.scopes,
          },
          config.oauth.as.refresh_token_ttl_seconds,
        )
      : undefined;

    logger.info("oauth audit", {
      ...oauthAudit(c, "token_exchange", "succeeded"),
      ...oauthClientAuditFields(clientId),
      grantType,
      scopes: record.scopes,
      refreshTokenIssued: Boolean(refreshGrant),
    });

    return c.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: config.oauth.as.access_token_ttl_seconds,
      scope: record.scopes.join(" "),
      ...(refreshGrant ? { refresh_token: refreshGrant.token } : {}),
    });
  });
}

async function exchangeRefreshToken(
  c: Context,
  form: Record<string, FormDataEntryValue | FormDataEntryValue[]>,
  clientId: string,
  client: OAuthClient,
  config: LevitateConfig,
  keys: AuthorizationServerKeys,
  refreshTokens: JsonRefreshTokenStore,
  logger: Logger,
) {
  const refreshToken = stringFormValue(form.refresh_token);
  const resource = stringFormValue(form.resource);
  const scopeValue = stringFormValue(form.scope);
  const scopes = scopeValue === undefined
    ? undefined
    : scopeValue.split(" ").map((scope) => scope.trim()).filter(Boolean);
  if (!refreshToken || !client.grant_types.includes("refresh_token")) {
    return c.json({ error: "invalid_grant" }, 400);
  }

  try {
    const grant = await refreshTokens.rotate(refreshToken, {
      clientId,
      resource,
      scopes,
    }, config.oauth.as.refresh_token_ttl_seconds);
    const accessToken = await issueAccessToken(
      {
        clientId,
        scopes: grant.record.scopes,
        subject: grant.record.subject,
      },
      config,
      keys,
    );
    logger.info("oauth audit", {
      ...oauthAudit(c, "token_refresh", "succeeded"),
      ...oauthClientAuditFields(clientId),
      scopes: grant.record.scopes,
    });
    return c.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: config.oauth.as.access_token_ttl_seconds,
      scope: grant.record.scopes.join(" "),
      refresh_token: grant.token,
    });
  } catch (error) {
    if (!(error instanceof RefreshTokenError)) throw error;
    const reason = error.reason;
    logger.warn("oauth token refresh rejected", {
      ...oauthAudit(c, "token_refresh", "rejected"),
      ...oauthClientAuditFields(clientId),
      reason,
    });
    return c.json({
      error: reason === "invalid_scope" ? "invalid_scope" : "invalid_grant",
    }, 400);
  }
}
