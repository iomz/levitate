import type { LevitateConfig } from "../../config.js";
import type { OAuthClient } from "./store.js";

export interface RegisterRequest {
  client_name?: unknown;
  redirect_uris?: unknown;
  grant_types?: unknown;
  response_types?: unknown;
  token_endpoint_auth_method?: unknown;
  scope?: unknown;
}

export function validateRegistration(
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

export function isAllowedRedirectUri(uri: string, config: LevitateConfig): boolean {
  return matchesHttpsUrlPrefix(
    uri,
    config.oauth.as.allowed_redirect_uri_prefixes,
  );
}

export function matchesHttpsUrlPrefix(value: string, prefixes: string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  )
    return false;
  return prefixes.some((prefix) => {
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

export function isExactRegisteredRedirectUri(
  client: OAuthClient,
  redirectUri: string,
): boolean {
  return client.redirect_uris.includes(redirectUri);
}

export function parseRequestedScopes(
  scope: string | null,
  config: LevitateConfig,
  client: OAuthClient,
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

export function stringFormValue(
  value: FormDataEntryValue | FormDataEntryValue[] | undefined,
): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function isValidPkceVerifier(value: string): boolean {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(value);
}

export function isValidPkceS256Challenge(value: string): boolean {
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
    value.length === 1 && value[0] === "authorization_code"
  );
}
