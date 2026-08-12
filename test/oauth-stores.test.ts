import { describe, expect, it } from "vitest";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PendingAuthorizationStore,
  type PendingAuthorization,
} from "../src/oauth/as/approval.js";
import { AuthorizationCodeStore } from "../src/oauth/as/codes.js";
import { JsonRefreshTokenStore } from "../src/oauth/as/refresh-tokens.js";

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

  it("persists hashed rotating refresh tokens with private permissions", async () => {
    const directory = await mkdtemp(join(tmpdir(), "levitate-refresh-store-"));
    const path = join(directory, "refresh-tokens.json");
    const issuedAt = new Date("2026-08-12T00:00:00.000Z");
    const store = new JsonRefreshTokenStore(path);
    const issued = await store.issue({
      client_id: "client",
      resource: "https://example.com/mcp",
      subject: "user",
      scopes: ["read", "write"],
    }, 3_600, issuedAt);

    expect(await readFile(path, "utf8")).not.toContain(issued.token);
    expect((await stat(path)).mode & 0o777).toBe(0o600);

    const reloaded = new JsonRefreshTokenStore(path);
    const rotated = await reloaded.rotate(issued.token, {
      clientId: "client",
      scopes: ["read"],
    }, 3_600, new Date("2026-08-12T00:01:00.000Z"));
    expect(rotated.record.scopes).toEqual(["read"]);
    expect(rotated.record.expires_at).toBe("2026-08-12T01:01:00.000Z");

    await expect(reloaded.rotate(issued.token, {
      clientId: "client",
    }, 3_600, new Date("2026-08-12T00:02:00.000Z"))).rejects.toThrow("refresh token reused");
    await expect(reloaded.rotate(rotated.token, {
      clientId: "client",
    }, 3_600, new Date("2026-08-12T00:03:00.000Z"))).rejects.toThrow("refresh token invalid");
  });
});
