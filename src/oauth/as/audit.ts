import { createHmac, randomBytes } from "node:crypto";
import type { Context } from "hono";

const CLIENT_ID_AUDIT_KEY = randomBytes(32);

export function oauthAudit(
  c: Context<any>,
  event: string,
  outcome: string,
): Record<string, unknown> {
  return {
    event,
    outcome,
    requestId: c.get("requestId"),
  };
}

export function oauthClientAuditFields(
  clientId: string | null | undefined,
): Record<string, unknown> {
  if (!clientId) return {};
  try {
    const url = new URL(clientId);
    if (url.protocol === "https:" && !url.username && !url.password) {
      return { clientOrigin: url.origin };
    }
  } catch {
    // Hash opaque or malformed submitted identifiers below.
  }
  return {
    clientIdHash: createHmac("sha256", CLIENT_ID_AUDIT_KEY)
      .update(clientId)
      .digest("hex")
      .slice(0, 16),
  };
}
