import { randomUUID } from "node:crypto";
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

interface PendingAuthorization {
  id: string;
  clientId: string;
  clientName?: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  codeChallenge: string;
  state?: string;
  expiresAt: number;
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
  const pendingAuthorizations = new PendingAuthorizationStore();

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

        const pending: PendingAuthorization = {
          id: randomUUID(),
          clientId: client.client_id,
          clientName: client.client_name,
          redirectUri,
          resource,
          scopes,
          codeChallenge,
          state,
          expiresAt: Date.now() + (asConfig.authorization_code_ttl_seconds * 1000),
        };

        if (asConfig.approval === "manual") {
          pendingAuthorizations.create(pending);
          return c.html(renderApprovalPage(pending));
        }

        return c.redirect(issueAuthorizationRedirect(pending, codes, config).toString(), 302);
      });

      app.get("/oauth/approval/:id", (c) => {
        const pending = pendingAuthorizations.get(c.req.param("id"));
        if (!pending) return c.html(renderApprovalExpiredPage(), 404);
        return c.html(renderApprovalPage(pending));
      });

      app.post("/oauth/approval/:id", async (c) => {
        const pending = pendingAuthorizations.consume(c.req.param("id"));
        if (!pending) return c.html(renderApprovalExpiredPage(), 404);

        const form = await c.req.parseBody();
        if (stringFormValue(form.decision) !== "approve") {
          const location = new URL(pending.redirectUri);
          location.searchParams.set("error", "access_denied");
          if (pending.state) location.searchParams.set("state", pending.state);
          return c.redirect(location.toString(), 302);
        }

        return c.redirect(issueAuthorizationRedirect(pending, codes, config).toString(), 302);
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

class PendingAuthorizationStore {
  private readonly entries = new Map<string, PendingAuthorization>();

  create(entry: PendingAuthorization): void {
    this.prune();
    this.entries.set(entry.id, entry);
  }

  get(id: string): PendingAuthorization | undefined {
    this.prune();
    const entry = this.entries.get(id);
    if (!entry || entry.expiresAt <= Date.now()) return undefined;
    return entry;
  }

  consume(id: string): PendingAuthorization | undefined {
    const entry = this.get(id);
    if (entry) this.entries.delete(id);
    return entry;
  }

  private prune(): void {
    const now = Date.now();
    for (const [id, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(id);
    }
  }
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
    expiresAt: Date.now() + (config.oauth.as.authorization_code_ttl_seconds * 1000),
  });

  const location = new URL(pending.redirectUri);
  location.searchParams.set("code", code);
  if (pending.state) location.searchParams.set("state", pending.state);
  return location;
}

function renderApprovalPage(pending: PendingAuthorization): string {
  const redirect = new URL(pending.redirectUri);
  const scopes = pending.scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Approve Levitate access</title>
</head>
<body>
  <main>
    <h1>Approve Levitate access</h1>
    <dl>
      <dt>Client</dt>
      <dd>${escapeHtml(pending.clientName ?? pending.clientId)}</dd>
      <dt>Redirect origin</dt>
      <dd>${escapeHtml(redirect.origin)}</dd>
      <dt>Resource</dt>
      <dd>${escapeHtml(pending.resource)}</dd>
      <dt>Scopes</dt>
      <dd><ul>${scopes}</ul></dd>
      <dt>Client registration</dt>
      <dd>dynamic</dd>
    </dl>
    <form method="post" action="/oauth/approval/${escapeHtml(pending.id)}">
      <button type="submit" name="decision" value="approve">Approve</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </form>
  </main>
</body>
</html>`;
}

function renderApprovalExpiredPage(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorization request expired</title>
</head>
<body>
  <main>
    <h1>Authorization request expired</h1>
    <p>Start the connection flow again.</p>
  </main>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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
