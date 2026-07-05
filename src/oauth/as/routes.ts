import { randomUUID, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
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
  const approvalSecret = getApprovalSecret(config);
  const icon = readFile("assets/levitate-icon.png");

  const clients = new JsonClientStore(asConfig.client_store_file);
  const codes = new AuthorizationCodeStore();
  const pendingAuthorizations = new PendingAuthorizationStore();

  return {
    registerRoutes(app: Hono): void {
      app.get("/.well-known/oauth-authorization-server", (c) => {
        const issuer = asConfig.issuer;
        const metadata: Record<string, unknown> = {
          issuer,
          authorization_endpoint: new URL(
            "/oauth/authorize",
            issuer,
          ).toString(),
          token_endpoint: new URL("/oauth/token", issuer).toString(),
          jwks_uri: new URL("/.well-known/jwks.json", issuer).toString(),
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code"],
          token_endpoint_auth_methods_supported: ["none"],
          code_challenge_methods_supported: ["S256"],
          scopes_supported: asConfig.scopes_supported,
        };
        if (asConfig.dcr.enabled) {
          metadata.registration_endpoint = new URL(
            "/oauth/register",
            issuer,
          ).toString();
        }
        return c.json(metadata);
      });

      app.get("/.well-known/jwks.json", (c) => c.json(keys.jwks));

      app.get("/oauth/assets/levitate-icon.png", async (c) => {
        try {
          return c.body(await icon, 200, { "content-type": "image/png" });
        } catch {
          return c.notFound();
        }
      });

      app.post("/oauth/register", async (c) => {
        if (!asConfig.dcr.enabled)
          return c.json({ error: "registration_disabled" }, 404);

        let body: RegisterRequest;
        try {
          body = await c.req.json<RegisterRequest>();
        } catch {
          logger.warn("oauth client registration body rejected", {
            error: "invalid_client_metadata",
          });
          return c.json({ error: "invalid_client_metadata" }, 400);
        }

        const validationError = validateRegistration(body, config);
        if (validationError) {
          logger.warn("oauth client registration rejected", {
            error: validationError,
            metadata: body,
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
            error: "invalid_request",
            grantType,
            hasCode: Boolean(code),
            redirectUri,
            clientId,
            hasCodeVerifier: Boolean(codeVerifier),
            resource,
          });
          return c.json({ error: "invalid_request" }, 400);
        }

        const client = await clients.get(clientId);
        if (!client || client.revoked_at) {
          logger.warn("oauth token request rejected", {
            error: "invalid_client",
            clientId,
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
          logger.warn("oauth token request rejected", {
            error: "invalid_grant",
            clientId,
            codeClientId: record.clientId,
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
    expiresAt:
      Date.now() + config.oauth.as.authorization_code_ttl_seconds * 1000,
  });

  const location = new URL(pending.redirectUri);
  location.searchParams.set("code", code);
  if (pending.state) location.searchParams.set("state", pending.state);
  return location;
}

function getApprovalSecret(config: LevitateConfig): string | undefined {
  const envName = config.oauth.as.approval_secret_env;
  if (config.oauth.as.approval !== "manual") return undefined;
  if (!envName)
    throw new Error(
      "oauth.as.approval_secret_env is required when oauth.as.approval is manual",
    );
  const secret = process.env[envName];
  if (!secret) throw new Error(`missing oauth approval secret env ${envName}`);
  return secret;
}

function isApprovalSecretValid(
  value: string | undefined,
  expected: string,
): boolean {
  if (!value) return false;
  const actual = Buffer.from(value);
  const configured = Buffer.from(expected);
  if (actual.length !== configured.length) return false;
  return timingSafeEqual(actual, configured);
}

function renderApprovalPage(
  pending: PendingAuthorization,
  error?: string,
): string {
  const redirect = new URL(pending.redirectUri);
  const scopes = pending.scopes
    .map((scope) => `<li>${escapeHtml(scope)}</li>`)
    .join("");
  const errorBlock = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Approve Levitate access</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
  <style>
    :root {
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f6f7f9;
      color: #18202a;
    }
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 32px 16px;
      background:
        radial-gradient(circle at 20% 0%, rgba(44, 110, 203, 0.10), transparent 32%),
        linear-gradient(180deg, #ffffff 0%, #eef2f7 100%);
    }
    main {
      width: min(680px, 100%);
      border: 1px solid #d8dee8;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.94);
      box-shadow: 0 22px 70px rgba(31, 45, 61, 0.14);
      overflow: hidden;
    }
    header {
      display: flex;
      gap: 18px;
      align-items: center;
      padding: 28px 32px 22px;
      border-bottom: 1px solid #e6ebf2;
      background: linear-gradient(135deg, #ffffff 0%, #f3f7fb 100%);
    }
    img {
      width: 64px;
      height: 64px;
      border-radius: 16px;
      box-shadow: 0 10px 26px rgba(20, 53, 96, 0.16);
    }
    h1 {
      margin: 0;
      font-size: 24px;
      line-height: 1.15;
      letter-spacing: 0;
    }
    .subtitle {
      margin: 6px 0 0;
      color: #617083;
      font-size: 14px;
    }
    section { padding: 24px 32px 30px; }
    dl {
      display: grid;
      grid-template-columns: 150px 1fr;
      gap: 14px 18px;
      margin: 0 0 24px;
      padding: 0;
    }
    dt {
      color: #617083;
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
    }
    dd {
      margin: 0;
      min-width: 0;
      color: #202a36;
      word-break: break-word;
    }
    ul {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      list-style: none;
      padding: 0;
      margin: 0;
    }
    li {
      border: 1px solid #ccd6e2;
      border-radius: 999px;
      padding: 4px 10px;
      background: #f8fafc;
      font-size: 13px;
      font-weight: 650;
    }
    label {
      display: block;
      margin-bottom: 8px;
      color: #354255;
      font-size: 13px;
      font-weight: 700;
    }
    input {
      width: 100%;
      height: 44px;
      border: 1px solid #bdc8d6;
      border-radius: 10px;
      padding: 0 12px;
      font: inherit;
      background: #ffffff;
    }
    input:focus {
      outline: 3px solid rgba(44, 110, 203, 0.18);
      border-color: #2c6ecb;
    }
    .error {
      margin: 0 0 14px;
      border: 1px solid #f1b9b9;
      border-radius: 10px;
      padding: 10px 12px;
      background: #fff4f4;
      color: #9a2d2d;
      font-size: 14px;
      font-weight: 650;
    }
    .actions {
      display: flex;
      gap: 12px;
      justify-content: flex-end;
      margin-top: 18px;
    }
    button {
      min-width: 110px;
      height: 42px;
      border: 1px solid #b9c4d2;
      border-radius: 10px;
      padding: 0 18px;
      font: inherit;
      font-weight: 750;
      cursor: pointer;
      background: #ffffff;
      color: #243142;
    }
    button[value="approve"] {
      border-color: #1f66c1;
      background: #1f66c1;
      color: #ffffff;
    }
    .secret-field {
      position: relative;
    }
    .secret-field input[type="password"],
    .secret-field input[type="text"] {
      width: 100%;
      padding-right: 46px;
    }
    .secret-toggle {
      position: absolute;
      top: 50%;
      right: 12px;
      width: 32px;
      min-width: 32px;
      height: 32px;
      padding: 0;
      transform: translateY(-50%);
      border: 0;
      background: transparent;
      color: #a6b0be;
      cursor: pointer;
    }
    .secret-toggle:hover,
    .secret-toggle:focus {
      color: #637083;
      outline: none;
    }
    @media (max-width: 560px) {
      header { padding: 22px; }
      section { padding: 22px; }
      dl { grid-template-columns: 1fr; gap: 6px; }
      .actions { flex-direction: column-reverse; }
      button { width: 100%; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <img src="/oauth/assets/levitate-icon.png" alt="" aria-hidden="true">
      <div>
        <h1>Approve Levitate access</h1>
        <p class="subtitle">Confirm this OAuth client before Levitate issues an authorization code.</p>
      </div>
    </header>
    <section>
      <dl>
        <dt>Client</dt>
        <dd>${escapeHtml(pending.clientName ?? pending.clientId)}</dd>
        <dt>Redirect origin</dt>
        <dd>${escapeHtml(redirect.origin)}</dd>
        <dt>Resource</dt>
        <dd>${escapeHtml(pending.resource)}</dd>
        <dt>Scopes</dt>
        <dd><ul>${scopes}</ul></dd>
        <dt>Registration</dt>
        <dd>Dynamic Client Registration</dd>
      </dl>
      ${errorBlock}
      <form method="post" action="/oauth/approval/${escapeHtml(pending.id)}">
        <label for="approval_secret">Approval secret</label>
        <div class="secret-field">
          <input id="approval_secret" name="approval_secret" type="password" autocomplete="current-password">
          <button type="button" id="toggle_secret" class="secret-toggle" aria-label="Reveal approval secret" aria-pressed="false">
            <i class="fa-solid fa-eye" aria-hidden="true"></i>
          </button>
        </div>
        <div class="actions">
          <button type="submit" name="decision" value="deny" formnovalidate>Cancel</button>
          <button type="submit" name="decision" value="approve">Approve</button>
        </div>
      </form>
    </section>
  </main>
  <script>
    const input = document.getElementById("approval_secret");
    const button = document.getElementById("toggle_secret");
    const icon = button.querySelector("i");
    button.addEventListener("click", () => {
      const revealing = input.type === "password";
      input.type = revealing ? "text" : "password";
      button.setAttribute("aria-label", revealing ? "Hide approval secret" : "Reveal approval secret");
      button.setAttribute("aria-pressed", revealing ? "true" : "false");
      icon.className = revealing ? "fa-solid fa-eye-slash" : "fa-solid fa-eye";
    });
  </script>
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

function validateRegistration(
  body: RegisterRequest,
  config: LevitateConfig,
): string | undefined {
  const redirectUris = body.redirect_uris;
  if (
    !Array.isArray(redirectUris) ||
    !redirectUris.length ||
    !redirectUris.every((uri) => typeof uri === "string")
  ) {
    return "invalid_redirect_uri";
  }

  if (!redirectUris.every((uri) => isAllowedRedirectUri(uri, config))) {
    return "invalid_redirect_uri";
  }

  if (
    body.grant_types !== undefined &&
    !isSupportedGrantTypes(body.grant_types)
  ) {
    return "invalid_client_metadata";
  }

  if (
    body.response_types !== undefined &&
    !isExactStringArray(body.response_types, ["code"])
  ) {
    return "invalid_client_metadata";
  }

  if (
    body.token_endpoint_auth_method !== undefined &&
    body.token_endpoint_auth_method !== "none"
  ) {
    return "invalid_client_metadata";
  }

  if (typeof body.scope === "string") {
    const scopes = body.scope
      .split(" ")
      .map((scope) => scope.trim())
      .filter(Boolean);
    if (
      !scopes.every((scope) => config.oauth.as.scopes_supported.includes(scope))
    ) {
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
    if (allowed.protocol !== "https:" || parsed.origin !== allowed.origin)
      return false;
    if (parsed.pathname === allowed.pathname) return true;
    if (allowed.pathname.endsWith("/"))
      return parsed.pathname.startsWith(allowed.pathname);
    return parsed.pathname.startsWith(`${allowed.pathname}/`);
  });
}

function isExactRegisteredRedirectUri(
  client: RegisteredClient,
  redirectUri: string,
): boolean {
  return client.redirect_uris.includes(redirectUri);
}

function parseRequestedScopes(
  scope: string | null,
  config: LevitateConfig,
  client: RegisteredClient,
): string[] | undefined {
  const requested = scope
    ? scope
        .split(" ")
        .map((entry) => entry.trim())
        .filter(Boolean)
    : config.oauth.as.default_scopes;
  const allowedForClient = client.scope
    ? client.scope
        .split(" ")
        .map((entry) => entry.trim())
        .filter(Boolean)
    : config.oauth.as.scopes_supported;
  if (!requested.length) return undefined;
  if (
    !requested.every((entry) =>
      config.oauth.as.scopes_supported.includes(entry),
    )
  )
    return undefined;
  if (!requested.every((entry) => allowedForClient.includes(entry)))
    return undefined;
  return requested;
}

function stringFormValue(
  value: FormDataEntryValue | FormDataEntryValue[] | undefined,
): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function isValidPkceVerifier(value: string): boolean {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(value);
}

function isValidPkceS256Challenge(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}

function isExactStringArray(value: unknown, expected: string[]): boolean {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    expected.every((entry) => value.includes(entry)) &&
    value.every((entry) => typeof entry === "string")
  );
}

function isSupportedGrantTypes(value: unknown): boolean {
  if (
    !Array.isArray(value) ||
    !value.every((entry) => typeof entry === "string")
  )
    return false;
  return (
    value.includes("authorization_code") &&
    value.every(
      (entry) => entry === "authorization_code" || entry === "refresh_token",
    )
  );
}
