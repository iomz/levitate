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
import { OAuthRateLimiter } from "./rate-limit.js";
import { CimdClientResolver, CompositeClientLookup } from "./cimd.js";
import { JsonRefreshTokenStore } from "./refresh-tokens.js";

export interface OAuthAuthorizationServer {
  registerRoutes(app: Hono<any>): void;
  close(): void;
}

export function createOAuthAuthorizationServer(
  config: LevitateConfig,
  keys: AuthorizationServerKeys,
  logger: Logger,
  fetchImpl: typeof fetch = fetch,
): OAuthAuthorizationServer | undefined {
  const asConfig = config.oauth.as;
  if (!asConfig.enabled) return undefined;
  if (!asConfig.issuer || !asConfig.subject || !asConfig.client_store_file) {
    throw new Error("oauth authorization server config is incomplete");
  }
  const approvalSecret = getApprovalSecret(config);

  const registeredClients = new JsonClientStore(asConfig.client_store_file);
  const cimdClients = asConfig.cimd.enabled
    ? new CimdClientResolver(config, logger, fetchImpl)
    : undefined;
  const clients = new CompositeClientLookup(registeredClients, cimdClients);
  const refreshTokens = new JsonRefreshTokenStore(
    asConfig.refresh_token_store_file ?? `${asConfig.client_store_file}.refresh-tokens.json`,
  );
  const codes = new AuthorizationCodeStore();
  const pendingAuthorizations = new PendingAuthorizationStore();
  const rateLimitConfig = asConfig.rate_limits;
  const rateLimiter = rateLimitConfig
    ? new OAuthRateLimiter(rateLimitConfig.window_seconds, rateLimitConfig)
    : undefined;
  const cleanupInterval = setInterval(() => {
    const authorizationCodes = codes.pruneExpired();
    const approvals = pendingAuthorizations.pruneExpired();
    void refreshTokens.pruneExpired().then((refreshTokenCount) => {
      if (refreshTokenCount) {
        logger.debug("oauth refresh token state pruned", { refreshTokens: refreshTokenCount });
      }
    }).catch((error) => {
      logger.warn("oauth refresh token pruning failed", {
        message: error instanceof Error ? error.message : String(error),
      });
    });
    if (authorizationCodes || approvals) {
      logger.debug("oauth ephemeral state pruned", {
        authorizationCodes,
        approvals,
      });
    }
  }, Math.min(asConfig.authorization_code_ttl_seconds, 60) * 1000);
  cleanupInterval.unref();

  return {
    registerRoutes(app: Hono<any>): void {
      registerMetadataRoutes(app, config, keys);
      registerClientRegistrationRoute(app, config, registeredClients, logger, rateLimiter);

      registerAuthorizationRoutes(
        app,
        config,
        clients,
        codes,
        pendingAuthorizations,
        approvalSecret,
        logger,
        rateLimiter,
      );
      registerTokenRoute(app, config, keys, clients, codes, refreshTokens, logger, rateLimiter);
    },
    close(): void {
      clearInterval(cleanupInterval);
      codes.pruneExpired();
      pendingAuthorizations.pruneExpired();
      void refreshTokens.pruneExpired().catch((error) => {
        logger.warn("oauth refresh token pruning failed", {
          message: error instanceof Error ? error.message : String(error),
        });
      });
    },
  };
}
