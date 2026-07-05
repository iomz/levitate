import { Hono } from "hono";
import { AuthorizationCodeStore, verifyPkceS256 } from "./codes.js";
import type { AuthorizationServerKeys } from "./keys.js";
import { JsonClientStore, type RegisteredClient } from "./store.js";
import { issueAccessToken } from "./tokens.js";
import type { LevitateConfig } from "../../config.js";
import type { Logger } from "../../logging.js";

export interface OAuthAuthorizationServer {
  registerRoutes(app: Hono): void;
}

interface RegisterRequest {
  client_name?: unknown;
  redirect_uris?: unknown;
  grant_types?: unknown;
  response_types?: unknown;
  token_endpoint_auth_method?: unknown;
  scope?: unknown;
}

export function createOAuthAuthorizationServer(
  config: LevitateConfig,
  keys: AuthorizationServerKeys,
  logger: Logger,
): OAuthAuthorizationServer | undefined {
  const asConfig = config.oauth.as;
  if (!asConfig.enabled) return undefined;
  if (!asConfig.issuer || !asConfig.subject || !asConfig.client_store_file) {
    throw new Error("oauth authorization server config is incomplete");
  }

  const clients = new JsonClientStore(asConfig.client_store_file);
  const codes = new AuthorizationCodeStore();

  return {
    registerRoutes(app: Hono): void {
      app.get("/.well-known/oauth-authorization-server", (c) => {
        const issuer = asConfig.issuer;
        const metadata: Record<string, unknown> = {
          issuer,
          authorization_endpoint: new URL("/oauth/authorize", issuer).toString(),
          token_endpoint: new URL("/oauth/token", issuer).toString(),
          jwks_uri: new URL("/.well-known/jwks.json", issuer).toString(),
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code"],
          token_endpoint_auth_methods_supported: ["none"],
          code_challenge_methods_supported: ["S256"],
          scopes_supported: asConfig.scopes_supported,
        };
        if (asConfig.dcr.enabled) {
          metadata.registration_endpoint = new URL("/oauth/register", issuer).toString();
        }
        return c.json(metadata);
      });

      app.get("/.well-known/jwks.json", (c) => c.json(keys.jwks));

      app.post("/oauth/register", async (c) => {
        if (!asConfig.dcr.enabled) return c.json({ error: "registration_disabled" }, 404);

        let body: RegisterRequest;
        try {
          body = await c.req.json<RegisterRequest>();
        } catch {
          return c.json({ error: "invalid_client_metadata" }, 400);
        }

        const validationError = validateRegistration(body, config);
        if (validationError) return c.json({ error: validationError }, 400);

        const redirectUris = body.redirect_uris as string[];
        const grantTypes = body.grant_types as string[];
        const responseTypes = body.response_types as string[];
        const scope = typeof body.scope === "string" ? body.scope : undefined;
        const registered = await clients.add({
          client_name: typeof body.client_name === "string" ? body.client_name : undefined,
          redirect_uris: redirectUris,
          grant_types: grantTypes,
          response_types: responseTypes,
          token_endpoint_auth_method: "none",
          scope,
        });

        logger.info("oauth client registered", {
          clientId: registered.client_id,
          redirectUriCount: registered.redirect_uris.length,
        });

        return c.json({
          client_id: registered.client_id,
          client_name: registered.client_name,
          redirect_uris: registered.redirect_uris,
          grant_types: registered.grant_types,
          response_types: registered.response_types,
          token_endpoint_auth_method: registered.token_endpoint_auth_method,
          scope: registered.scope,
        }, 201);
      });

      app.get("/oauth/authorize", async (c) => {
        const url = new URL(c.req.url);
        const clientId = url.searchParams.get("client_id");
        const redirectUri = url.searchParams.get("redirect_uri");
        const state = url.searchParams.get("state") ?? undefined;
        const client = clientId ? await clients.get(clientId) : undefined;

        const redirectError = (error: string) => {
          if (client && redirectUri && isExactRegisteredRedirectUri(client, redirectUri)) {
            const location = new URL(redirectUri);
            location.searchParams.set("error", error);
            if (state) location.searchParams.set("state", state);
            return c.redirect(location.toString(), 302);
          }
          return c.json({ error }, 400);
        };

        if (url.searchParams.get("response_type") !== "code") return redirectError("unsupported_response_type");
        if (!client) return redirectError("invalid_client");
        if (!redirectUri || !isExactRegisteredRedirectUri(client, redirectUri)) {
          return c.json({ error: "invalid_request" }, 400);
        }
        const codeChallenge = url.searchParams.get("code_challenge");
        if (!codeChallenge || !isValidPkceS256Challenge(codeChallenge)) return redirectError("invalid_request");
        if (url.searchParams.get("code_challenge_method") !== "S256") return redirectError("invalid_request");

        const resource = url.searchParams.get("resource");
        const configuredResource = config.oauth.resource.resource;
        if (!resource || resource !== configuredResource) return redirectError("invalid_target");

        const scopes = parseRequestedScopes(url.searchParams.get("scope"), config, client);
        if (!scopes) return redirectError("invalid_scope");

        const code = codes.create({
          clientId: client.client_id,
          redirectUri,
          resource,
          scopes,
          codeChallenge,
          codeChallengeMethod: "S256",
          subject: asConfig.subject!,
          expiresAt: Date.now() + (asConfig.authorization_code_ttl_seconds * 1000),
        });

        const location = new URL(redirectUri);
        location.searchParams.set("code", code);
        if (state) location.searchParams.set("state", state);
        return c.redirect(location.toString(), 302);
      });

      app.post("/oauth/token", async (c) => {
        const form = await c.req.parseBody();
        const grantType = stringFormValue(form.grant_type);
        const code = stringFormValue(form.code);
        const redirectUri = stringFormValue(form.redirect_uri);
        const clientId = stringFormValue(form.client_id);
        const codeVerifier = stringFormValue(form.code_verifier);
        const resource = stringFormValue(form.resource);

        if (grantType !== "authorization_code") return c.json({ error: "unsupported_grant_type" }, 400);
        if (!code || !redirectUri || !clientId || !codeVerifier || !resource) {
          return c.json({ error: "invalid_request" }, 400);
        }

        const client = await clients.get(clientId);
        if (!client) return c.json({ error: "invalid_client" }, 400);

        let record;
        try {
          record = codes.get(code);
        } catch (error) {
          const message = error instanceof Error ? error.message : "invalid authorization code";
          logger.warn("oauth token code rejected", { message });
          return c.json({ error: "invalid_grant" }, 400);
        }

        if (
          record.clientId !== clientId ||
          record.redirectUri !== redirectUri ||
          record.resource !== resource ||
          !isValidPkceVerifier(codeVerifier) ||
          !verifyPkceS256(codeVerifier, record.codeChallenge)
        ) {
          return c.json({ error: "invalid_grant" }, 400);
        }

        codes.markUsed(code);

        const accessToken = await issueAccessToken({
          clientId,
          scopes: record.scopes,
        }, config, keys);

        return c.json({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: asConfig.access_token_ttl_seconds,
          scope: record.scopes.join(" "),
        });
      });
    },
  };
}

function validateRegistration(body: RegisterRequest, config: LevitateConfig): string | undefined {
  const redirectUris = body.redirect_uris;
  if (!Array.isArray(redirectUris) || !redirectUris.length || !redirectUris.every((uri) => typeof uri === "string")) {
    return "invalid_redirect_uri";
  }

  if (!redirectUris.every((uri) => isAllowedRedirectUri(uri, config))) {
    return "invalid_redirect_uri";
  }

  if (!isExactStringArray(body.grant_types, ["authorization_code"])) {
    return "invalid_client_metadata";
  }

  if (!isExactStringArray(body.response_types, ["code"])) {
    return "invalid_client_metadata";
  }

  if (body.token_endpoint_auth_method !== "none") {
    return "invalid_client_metadata";
  }

  if (typeof body.scope === "string") {
    const scopes = body.scope.split(" ").map((scope) => scope.trim()).filter(Boolean);
    if (!scopes.every((scope) => config.oauth.as.scopes_supported.includes(scope))) {
      return "invalid_client_metadata";
    }
  }

  return undefined;
}

function isAllowedRedirectUri(uri: string, config: LevitateConfig): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  return config.oauth.as.allowed_redirect_uri_prefixes.some((prefix) => {
    let allowed: URL;
    try {
      allowed = new URL(prefix);
    } catch {
      return false;
    }
    if (allowed.protocol !== "https:" || parsed.origin !== allowed.origin) return false;
    if (parsed.pathname === allowed.pathname) return true;
    if (allowed.pathname.endsWith("/")) return parsed.pathname.startsWith(allowed.pathname);
    return parsed.pathname.startsWith(`${allowed.pathname}/`);
  });
}

function isExactRegisteredRedirectUri(client: RegisteredClient, redirectUri: string): boolean {
  return client.redirect_uris.includes(redirectUri);
}

function parseRequestedScopes(scope: string | null, config: LevitateConfig, client: RegisteredClient): string[] | undefined {
  const requested = scope
    ? scope.split(" ").map((entry) => entry.trim()).filter(Boolean)
    : config.oauth.as.default_scopes;
  const allowedForClient = client.scope
    ? client.scope.split(" ").map((entry) => entry.trim()).filter(Boolean)
    : config.oauth.as.default_scopes;
  if (!requested.length) return undefined;
  if (!requested.every((entry) => config.oauth.as.scopes_supported.includes(entry))) return undefined;
  if (!requested.every((entry) => allowedForClient.includes(entry))) return undefined;
  return requested;
}

function stringFormValue(value: FormDataEntryValue | FormDataEntryValue[] | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function isValidPkceVerifier(value: string): boolean {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(value);
}

function isValidPkceS256Challenge(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}

function isExactStringArray(value: unknown, expected: string[]): boolean {
  return Array.isArray(value)
    && value.length === expected.length
    && expected.every((entry) => value.includes(entry))
    && value.every((entry) => typeof entry === "string");
}
