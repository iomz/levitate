import { describe, expect, it } from "vitest";
import {
  PendingAuthorizationStore,
  type PendingAuthorization,
} from "../src/oauth/as/approval.js";
import { AuthorizationCodeStore } from "../src/oauth/as/codes.js";

describe("oauth ephemeral stores", () => {
  it("prunes expired authorization codes explicitly", () => {
    const store = new AuthorizationCodeStore();
    const expiresAt = Date.now() + 1_000;
    const code = store.create({
      clientId: "client",
      redirectUri: "https://example.com/callback",
      resource: "https://example.com/mcp",
      scopes: ["read"],
      codeChallenge: "challenge",
      codeChallengeMethod: "S256",
      subject: "user",
      expiresAt,
    });

    expect(store.pruneExpired(expiresAt - 1)).toBe(0);
    expect(store.pruneExpired(expiresAt)).toBe(1);
    expect(() => store.get(code)).toThrow("invalid authorization code");
  });

  it("prunes expired pending approvals explicitly", () => {
    const store = new PendingAuthorizationStore();
    const expiresAt = Date.now() + 1_000;
    const pending: PendingAuthorization = {
      id: "pending",
      clientId: "client",
      registrationMethod: "dcr",
      redirectUri: "https://example.com/callback",
      resource: "https://example.com/mcp",
      scopes: ["read"],
      codeChallenge: "challenge",
      expiresAt,
    };

    store.create(pending);

    expect(store.pruneExpired(expiresAt - 1)).toBe(0);
    expect(store.pruneExpired(expiresAt)).toBe(1);
    expect(store.get(pending.id)).toBeUndefined();
  });
});
