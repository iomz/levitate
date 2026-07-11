import { Hono } from "hono";
import { AuthorizationCodeStore } from "./codes.js";
import type { AuthorizationServerKeys } from "./keys.js";
import { JsonClientStore } from "./store.js";
import type { LevitateConfig } from "../../config.js";
import type { Logger } from "../../logging.js";
import { getApprovalSecret, PendingAuthorizationStore } from "./approval.js";
import { registerAuthorizationRoutes } from "./authorization.js";
import { registerMetadataRoutes } from "./metadata.js";
import { registerClientRegistrationRoute } from "./registration.js";
import { registerTokenRoute } from "./token-endpoint.js";

export interface OAuthAuthorizationServer {
  registerRoutes(app: Hono<any>): void;
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

  const clients = new JsonClientStore(asConfig.client_store_file);
  const codes = new AuthorizationCodeStore();
  const pendingAuthorizations = new PendingAuthorizationStore();

  return {
    registerRoutes(app: Hono<any>): void {
      registerMetadataRoutes(app, config, keys);
      registerClientRegistrationRoute(app, config, clients, logger);

      registerAuthorizationRoutes(
        app,
        config,
        clients,
        codes,
        pendingAuthorizations,
        approvalSecret,
        logger,
      );
      registerTokenRoute(app, config, keys, clients, codes, logger);
    },
  };
}
