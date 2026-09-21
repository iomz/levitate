import { describe, expect, it } from "vitest";
import { buildPrincipal } from "../src/auth/principal.js";
import type { AuthResult } from "../src/auth/types.js";

const asserted = new Date("2026-09-21T09:30:00.000Z");

describe("principal construction", () => {
  it("maps an OIDC result to a user principal", () => {
    const result = buildPrincipal(oidc(), asserted);

    expect(result.principal).toEqual({
      issuer: "https://idp.example.com",
      subject: "idp-subject",
      subject_type: "user",
      auth_kind: "oidc",
      client_id: "idp-client",
      email: "person@example.com",
      scopes: ["levitate:read", "levitate:call"],
      asserted_at: "2026-09-21T09:30:00.000Z",
    });
  });

  it("maps a Levitate AS result to an owner principal", () => {
    const result = buildPrincipal(levitate(), asserted);

    expect(result.principal).toEqual({
      issuer: "https://levitate.example.com",
      subject: "local-owner",
      subject_type: "owner",
      auth_kind: "levitate",
      client_id: "https://chatgpt.com/connector",
      scopes: ["gateway:access"],
      asserted_at: "2026-09-21T09:30:00.000Z",
    });
  });

  it("refuses bearer authentication rather than inventing an identity", () => {
    const result = buildPrincipal({
      kind: "bearer",
      subject: "bearer-token",
      scopes: [],
      issuer: "https://levitate.example.com",
    }, asserted);

    expect(result.principal).toBeUndefined();
    expect(result.refusal).toContain("identifies no principal");
  });

  it("refuses an unrecognized auth kind instead of defaulting to user", () => {
    const result = buildPrincipal({
      kind: "future-mode",
      subject: "someone",
      scopes: [],
      issuer: "https://levitate.example.com",
    } as unknown as AuthResult, asserted);

    expect(result.principal).toBeUndefined();
    expect(result.refusal).toContain("identifies no principal");
  });

  it("refuses when the identity key is incomplete", () => {
    expect(buildPrincipal({ ...oidc(), subject: undefined }, asserted).refusal)
      .toContain("no usable subject");
    expect(buildPrincipal({ ...oidc(), issuer: undefined }, asserted).refusal)
      .toContain("no usable issuer");
  });

  it("refuses malformed values instead of coercing them into a principal", () => {
    const cases: [string, unknown, string][] = [
      ["scopes missing", { ...oidc(), scopes: undefined }, "malformed scopes"],
      ["scopes as a string", { ...oidc(), scopes: "not-an-array" }, "malformed scopes"],
      ["scopes with a non-string entry", { ...oidc(), scopes: ["ok", 7] }, "malformed scopes"],
      ["scopes as an object", { ...oidc(), scopes: { 0: "a", length: 1 } }, "malformed scopes"],
      ["subject as a number", { ...oidc(), subject: 42 }, "no usable subject"],
      ["subject empty", { ...oidc(), subject: "" }, "no usable subject"],
      ["issuer as an object", { ...oidc(), issuer: { toString: () => "https://evil" } }, "no usable issuer"],
      ["email as an object", { ...oidc(), email: { toString: () => "a@b.c" } }, "malformed email"],
      ["email as a number", { ...oidc(), email: 1 }, "malformed email"],
      ["client id as an array", { ...oidc(), clientId: ["a"] }, "malformed client id"],
    ];

    for (const [label, auth, expected] of cases) {
      const result = buildPrincipal(auth as AuthResult, asserted);
      expect(result.principal, label).toBeUndefined();
      expect(result.refusal, label).toContain(expected);
    }
  });

  it("does not turn a string of scopes into one scope per character", () => {
    const result = buildPrincipal({ ...oidc(), scopes: "admin" } as unknown as AuthResult, asserted);

    expect(result.principal).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain('"a","d","m"');
  });

  it("keeps the refusal reason free of authentication material", () => {
    const result = buildPrincipal({
      kind: "bearer",
      subject: "secret-looking-subject",
      issuer: "https://levitate.example.com",
      scopes: [],
    }, asserted);

    expect(result.refusal).toBe("auth kind identifies no principal");
    expect(result.refusal).not.toContain("secret-looking-subject");
  });

  it("emits exactly the allowlisted fields and no authentication material", () => {
    // Fields an AuthResult could carry, or grow, that must never be asserted.
    const contaminated = {
      ...oidc(),
      audience: "https://levitate.example.com/mcp",
      accessToken: "secret-access-token",
      refreshToken: "secret-refresh-token",
      authorization: "Bearer secret-access-token",
      claims: { sub: "idp-subject", secret_claim: "do-not-propagate" },
      codeVerifier: "pkce-verifier",
    } as unknown as AuthResult;

    const { principal } = buildPrincipal(contaminated, asserted);

    expect(Object.keys(principal ?? {}).sort()).toEqual([
      "asserted_at",
      "auth_kind",
      "client_id",
      "email",
      "issuer",
      "scopes",
      "subject",
      "subject_type",
    ]);
    const serialized = JSON.stringify(principal);
    for (const secret of [
      "secret-access-token",
      "secret-refresh-token",
      "do-not-propagate",
      "pkce-verifier",
      "Bearer ",
    ]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("omits optional fields the authenticator did not resolve", () => {
    const { principal } = buildPrincipal({
      kind: "oidc",
      subject: "idp-subject",
      issuer: "https://idp.example.com",
      scopes: [],
    }, asserted);

    expect(principal).not.toHaveProperty("email");
    expect(principal).not.toHaveProperty("client_id");
    expect(principal?.scopes).toEqual([]);
  });

  it("copies scopes rather than aliasing the authentication result", () => {
    const auth = oidc();
    const { principal } = buildPrincipal(auth, asserted);

    auth.scopes.push("levitate:admin");

    expect(principal?.scopes).toEqual(["levitate:read", "levitate:call"]);
  });

  it("stamps assertion time from the moment of the call", () => {
    const before = Date.now();
    const { principal } = buildPrincipal(oidc());
    const stamped = Date.parse(principal?.asserted_at ?? "");

    expect(stamped).toBeGreaterThanOrEqual(before);
    expect(stamped).toBeLessThanOrEqual(Date.now());
    expect(principal?.asserted_at).toMatch(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/);
  });
});

function oidc(): AuthResult {
  return {
    kind: "oidc",
    subject: "idp-subject",
    email: "person@example.com",
    clientId: "idp-client",
    issuer: "https://idp.example.com",
    scopes: ["levitate:read", "levitate:call"],
  };
}

function levitate(): AuthResult {
  return {
    kind: "levitate",
    subject: "local-owner",
    clientId: "https://chatgpt.com/connector",
    issuer: "https://levitate.example.com",
    scopes: ["gateway:access"],
  };
}
