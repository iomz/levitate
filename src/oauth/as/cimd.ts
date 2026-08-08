import type { LevitateConfig } from "../../config.js";
import type { Logger } from "../../logging.js";
import { isAllowedRedirectUri, matchesHttpsUrlPrefix } from "./validation.js";
import type { ClientLookup, OAuthClient } from "./store.js";

const FETCH_TIMEOUT_MS = 3_000;
const MAX_DOCUMENT_BYTES = 64 * 1024;
const DEFAULT_CACHE_SECONDS = 300;
const MAX_CACHE_SECONDS = 3_600;

interface CacheEntry {
  client: OAuthClient;
  expiresAt: number;
}

interface CimdDocument {
  client_id?: unknown;
  client_name?: unknown;
  redirect_uris?: unknown;
  grant_types?: unknown;
  response_types?: unknown;
  token_endpoint_auth_method?: unknown;
  token_endpoint_auth_methods_supported?: unknown;
  scope?: unknown;
}

export class CompositeClientLookup implements ClientLookup {
  constructor(
    private readonly registeredClients: ClientLookup,
    private readonly cimdClients?: ClientLookup,
  ) {}

  async get(clientId: string): Promise<OAuthClient | undefined> {
    return (
      (await this.registeredClients.get(clientId)) ??
      (await this.cimdClients?.get(clientId))
    );
  }
}

export class CimdClientResolver implements ClientLookup {
  private readonly cache = new Map<string, CacheEntry>();

  constructor(
    private readonly config: LevitateConfig,
    private readonly logger: Logger,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async get(clientId: string): Promise<OAuthClient | undefined> {
    const asConfig = this.config.oauth.as;
    if (!asConfig.cimd.enabled || !isAllowedClientId(clientId, this.config)) {
      return undefined;
    }

    const cached = this.cache.get(clientId);
    if (cached && cached.expiresAt > Date.now()) return cached.client;
    this.cache.delete(clientId);

    try {
      const response = await this.fetchImpl(clientId, {
        headers: { accept: "application/json" },
        redirect: "error",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!response.ok) throw new Error(`http_${response.status}`);
      const contentType = response.headers.get("content-type") ?? "";
      if (!/^application\/(?:[a-z0-9.+-]*\+)?json\b/i.test(contentType)) {
        throw new Error("invalid_content_type");
      }

      const body = await readBoundedBody(response);
      let document: CimdDocument;
      try {
        document = JSON.parse(body) as CimdDocument;
      } catch {
        throw new Error("invalid_json");
      }
      const client = validateDocument(clientId, document, this.config);
      const cacheSeconds = getCacheSeconds(response.headers.get("cache-control"));
      if (cacheSeconds > 0) {
        this.cache.set(clientId, {
          client,
          expiresAt: Date.now() + cacheSeconds * 1_000,
        });
      }
      return client;
    } catch (error) {
      this.logger.warn("oauth cimd client rejected", {
        clientOrigin: new URL(clientId).origin,
        reason: error instanceof Error ? error.message : String(error),
      });
      return undefined;
    }
  }
}

function isAllowedClientId(clientId: string, config: LevitateConfig): boolean {
  let parsed: URL;
  try {
    parsed = new URL(clientId);
  } catch {
    return false;
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.pathname === "/" ||
    parsed.search ||
    parsed.hash ||
    parsed.username ||
    parsed.password ||
    parsed.toString() !== clientId
  )
    return false;
  return matchesHttpsUrlPrefix(
    clientId,
    config.oauth.as.cimd.allowed_client_id_prefixes,
  );
}

function validateDocument(
  clientId: string,
  document: CimdDocument,
  config: LevitateConfig,
): OAuthClient {
  if (document.client_id !== clientId) throw new Error("client_id_mismatch");
  if (typeof document.client_name !== "string" || !document.client_name.trim()) {
    throw new Error("invalid_client_name");
  }
  if (
    !Array.isArray(document.redirect_uris) ||
    !document.redirect_uris.length ||
    !document.redirect_uris.every(
      (uri) => typeof uri === "string" && isAllowedRedirectUri(uri, config),
    )
  )
    throw new Error("invalid_redirect_uris");
  if (
    document.grant_types !== undefined &&
    (!isStringArray(document.grant_types) ||
      !document.grant_types.includes("authorization_code"))
  )
    throw new Error("unsupported_grant_types");
  if (
    document.response_types !== undefined &&
    (!isStringArray(document.response_types) ||
      !document.response_types.includes("code"))
  )
    throw new Error("unsupported_response_types");
  if (!supportsPublicClient(document)) {
    throw new Error("unsupported_token_endpoint_auth_method");
  }
  if (document.scope !== undefined && typeof document.scope !== "string") {
    throw new Error("invalid_scope");
  }
  if (typeof document.scope === "string") {
    const scopes = document.scope.split(" ").filter(Boolean);
    if (!scopes.every((scope) => config.oauth.as.scopes_supported.includes(scope))) {
      throw new Error("unsupported_scope");
    }
  }

  return {
    client_id: clientId,
    client_name: document.client_name,
    redirect_uris: document.redirect_uris as string[],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    scope: typeof document.scope === "string" ? document.scope : undefined,
  };
}

function supportsPublicClient(document: CimdDocument): boolean {
  if (document.token_endpoint_auth_method === "none") return true;
  return (
    isStringArray(document.token_endpoint_auth_methods_supported) &&
    document.token_endpoint_auth_methods_supported.includes("none")
  );
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

async function readBoundedBody(response: Response): Promise<string> {
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_DOCUMENT_BYTES) {
    throw new Error("document_too_large");
  }
  if (!response.body) throw new Error("empty_document");

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_DOCUMENT_BYTES) {
      await reader.cancel();
      throw new Error("document_too_large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

function getCacheSeconds(cacheControl: string | null): number {
  if (!cacheControl) return DEFAULT_CACHE_SECONDS;
  if (/\b(?:no-store|no-cache)\b/i.test(cacheControl)) return 0;
  const maxAge = cacheControl.match(/(?:^|,)\s*max-age=(\d+)/i)?.[1];
  if (!maxAge) return DEFAULT_CACHE_SECONDS;
  return Math.min(Number(maxAge), MAX_CACHE_SECONDS);
}
