import type { Hono } from "hono";
import type { LevitateConfig } from "../../config.js";
import type { Logger } from "../../logging.js";
import type { ClientStore } from "./store.js";
import { validateRegistration, type RegisterRequest } from "./validation.js";
import type { OAuthRateLimiter } from "./rate-limit.js";
import { oauthAudit } from "./audit.js";

export function registerClientRegistrationRoute(app: Hono, config: LevitateConfig, clients: ClientStore, logger: Logger, rateLimiter?: OAuthRateLimiter): void {
  const asConfig = config.oauth.as;
  app.post("/oauth/register", async (c) => {
    const retryAfter = rateLimiter?.consume("registration", "global");
    if (retryAfter) {
      c.header("Retry-After", String(retryAfter));
      logger.warn("oauth audit", oauthAudit(c, "client_registration", "rate_limited"));
      return c.json({ error: "temporarily_unavailable" }, 429);
    }
    if (!asConfig.dcr.enabled)
      return c.json({ error: "registration_disabled" }, 404);

    let body: RegisterRequest;
    try {
      body = await c.req.json<RegisterRequest>();
    } catch {
      logger.warn("oauth client registration body rejected", {
        ...oauthAudit(c, "client_registration", "rejected"),
        error: "invalid_client_metadata",
      });
      return c.json({ error: "invalid_client_metadata" }, 400);
    }

    const validationError = validateRegistration(body, config);
    if (validationError) {
      logger.warn("oauth client registration rejected", {
        ...oauthAudit(c, "client_registration", "rejected"),
        error: validationError,
      });
      return c.json({ error: validationError }, 400);
    }

    const redirectUris = body.redirect_uris as string[];
    const scope = typeof body.scope === "string" ? body.scope : undefined;
    const registered = await clients.add({
      client_name:
        typeof body.client_name === "string" ? body.client_name : undefined,
      redirect_uris: redirectUris,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope,
    });

    logger.info("oauth client registered", {
      ...oauthAudit(c, "client_registration", "succeeded"),
      clientId: registered.client_id,
      redirectUriCount: registered.redirect_uris.length,
    });

    return c.json(
      {
        client_id: registered.client_id,
        client_name: registered.client_name,
        redirect_uris: registered.redirect_uris,
        grant_types: registered.grant_types,
        response_types: registered.response_types,
        token_endpoint_auth_method: registered.token_endpoint_auth_method,
        scope: registered.scope,
      },
      201,
    );
  });


}
