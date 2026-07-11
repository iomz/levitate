import { randomUUID } from "node:crypto";
import type { Hono } from "hono";
import type { LevitateConfig } from "../../config.js";
import type { Logger } from "../../logging.js";
import { getApprovalSecret, isApprovalSecretValid, PendingAuthorizationStore, renderApprovalExpiredPage, renderApprovalPage, type PendingAuthorization } from "./approval.js";
import { AuthorizationCodeStore } from "./codes.js";
import type { JsonClientStore } from "./store.js";
import { isExactRegisteredRedirectUri, isValidPkceS256Challenge, parseRequestedScopes, stringFormValue } from "./validation.js";

export function registerAuthorizationRoutes(app: Hono, config: LevitateConfig, clients: JsonClientStore, codes: AuthorizationCodeStore, pendingAuthorizations: PendingAuthorizationStore, approvalSecret: string | undefined, logger: Logger): void {
  const asConfig = config.oauth.as;
  app.get("/oauth/authorize", async (c) => {
    const url = new URL(c.req.url);
    const clientId = url.searchParams.get("client_id");
    const redirectUri = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state") ?? undefined;
    const client = clientId ? await clients.get(clientId) : undefined;

    const redirectError = (error: string) => {
      logger.warn("oauth authorization rejected", {
        error,
        clientId,
        hasClient: Boolean(client),
        redirectUri,
        responseType: url.searchParams.get("response_type"),
        codeChallengeMethod: url.searchParams.get("code_challenge_method"),
        resource: url.searchParams.get("resource"),
        scope: url.searchParams.get("scope"),
      });
      if (
        client &&
        redirectUri &&
        isExactRegisteredRedirectUri(client, redirectUri)
      ) {
        const location = new URL(redirectUri);
        location.searchParams.set("error", error);
        if (state) location.searchParams.set("state", state);
        return c.redirect(location.toString(), 302);
      }
      return c.json({ error }, 400);
    };

    if (url.searchParams.get("response_type") !== "code")
      return redirectError("unsupported_response_type");
    if (!client || client.revoked_at)
      return redirectError("invalid_client");
    if (
      !redirectUri ||
      !isExactRegisteredRedirectUri(client, redirectUri)
    ) {
      logger.warn("oauth authorization rejected", {
        error: "invalid_request",
        clientId,
        hasClient: Boolean(client),
        redirectUri,
        registeredRedirectUris: client?.redirect_uris,
      });
      return c.json({ error: "invalid_request" }, 400);
    }
    const codeChallenge = url.searchParams.get("code_challenge");
    if (!codeChallenge || !isValidPkceS256Challenge(codeChallenge))
      return redirectError("invalid_request");
    if (url.searchParams.get("code_challenge_method") !== "S256")
      return redirectError("invalid_request");

    const resource = url.searchParams.get("resource");
    const configuredResource = config.oauth.resource.resource;
    if (!resource || resource !== configuredResource)
      return redirectError("invalid_target");

    const scopes = parseRequestedScopes(
      url.searchParams.get("scope"),
      config,
      client,
    );
    if (!scopes) return redirectError("invalid_scope");

    const pending: PendingAuthorization = {
      id: randomUUID(),
      clientId: client.client_id,
      clientName: client.client_name,
      redirectUri,
      resource,
      scopes,
      codeChallenge,
      state,
      expiresAt:
        Date.now() + asConfig.authorization_code_ttl_seconds * 1000,
    };

    if (asConfig.approval === "manual") {
      pendingAuthorizations.create(pending);
      logger.info("oauth authorization pending approval", {
        clientId: pending.clientId,
        redirectOrigin: new URL(pending.redirectUri).origin,
        resource: pending.resource,
        scopes: pending.scopes,
      });
      return c.html(renderApprovalPage(pending));
    }

    logger.info("oauth authorization approved automatically", {
      clientId: pending.clientId,
      redirectOrigin: new URL(pending.redirectUri).origin,
      resource: pending.resource,
      scopes: pending.scopes,
    });
    return c.redirect(
      issueAuthorizationRedirect(pending, codes, config).toString(),
      302,
    );
  });

  app.get("/oauth/approval/:id", (c) => {
    const pending = pendingAuthorizations.get(c.req.param("id"));
    if (!pending) return c.html(renderApprovalExpiredPage(), 404);
    logger.info("oauth approval page loaded", {
      clientId: pending.clientId,
    });
    return c.html(renderApprovalPage(pending));
  });

  app.post("/oauth/approval/:id", async (c) => {
    const pending = pendingAuthorizations.get(c.req.param("id"));
    if (!pending) return c.html(renderApprovalExpiredPage(), 404);

    const form = await c.req.parseBody();
    if (stringFormValue(form.decision) !== "approve") {
      pendingAuthorizations.consume(pending.id);
      logger.info("oauth authorization denied manually", {
        clientId: pending.clientId,
      });
      const location = new URL(pending.redirectUri);
      location.searchParams.set("error", "access_denied");
      if (pending.state) location.searchParams.set("state", pending.state);
      return c.redirect(location.toString(), 302);
    }

    if (
      !approvalSecret ||
      !isApprovalSecretValid(
        stringFormValue(form.approval_secret),
        approvalSecret,
      )
    ) {
      logger.warn("oauth approval secret rejected", {
        clientId: pending.clientId,
      });
      return c.html(
        renderApprovalPage(pending, "Approval secret invalid"),
        403,
      );
    }

    pendingAuthorizations.consume(pending.id);

    const client = await clients.get(pending.clientId);
    if (!client || client.revoked_at) {
      logger.info("oauth authorization rejected after approval", {
        clientId: pending.clientId,
      });
      const location = new URL(pending.redirectUri);
      location.searchParams.set("error", "invalid_client");
      if (pending.state) location.searchParams.set("state", pending.state);
      return c.redirect(location.toString(), 302);
    }

    logger.info("oauth authorization approved manually", {
      clientId: pending.clientId,
      redirectOrigin: new URL(pending.redirectUri).origin,
      resource: pending.resource,
      scopes: pending.scopes,
    });
    return c.redirect(
      issueAuthorizationRedirect(pending, codes, config).toString(),
      302,
    );
  });


}

function issueAuthorizationRedirect(
  pending: PendingAuthorization,
  codes: AuthorizationCodeStore,
  config: LevitateConfig,
): URL {
  const code = codes.create({
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    resource: pending.resource,
    scopes: pending.scopes,
    codeChallenge: pending.codeChallenge,
    codeChallengeMethod: "S256",
    subject: config.oauth.as.subject!,
    expiresAt:
      Date.now() + config.oauth.as.authorization_code_ttl_seconds * 1000,
  });

  const location = new URL(pending.redirectUri);
  location.searchParams.set("code", code);
  if (pending.state) location.searchParams.set("state", pending.state);
  return location;
}

