import type { Context } from "hono";

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
