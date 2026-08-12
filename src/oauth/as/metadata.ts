import { readFile } from "node:fs/promises";
import type { Hono } from "hono";
import type { LevitateConfig } from "../../config.js";
import type { AuthorizationServerKeys } from "./keys.js";

export function registerMetadataRoutes(app: Hono, config: LevitateConfig, keys: AuthorizationServerKeys): void {
  const asConfig = config.oauth.as;
  const iconUrls = [
    new URL("../../../assets/levitate-icon.png", import.meta.url),
    new URL("../../../../assets/levitate-icon.png", import.meta.url),
  ];
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
      grant_types_supported: ["authorization_code", "refresh_token"],
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
    if (asConfig.cimd.enabled) {
      metadata.client_id_metadata_document_supported = true;
    }
    return c.json(metadata);
  });

  app.get("/.well-known/jwks.json", (c) => c.json(keys.jwks));

  app.get("/oauth/assets/levitate-icon.png", async (c) => {
    for (const iconUrl of iconUrls) {
      try {
        return c.body(await readFile(iconUrl), 200, { "content-type": "image/png" });
      } catch {
        // Try source and compiled module layouts before returning 404.
      }
    }
    return c.notFound();
  });


}
