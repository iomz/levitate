import { describe, expect, it } from "vitest";
import { BearerAuthenticator, validateBearerAuthorization } from "../src/auth/bearer.js";

describe("bearer auth", () => {
  it("accepts valid bearer token", async () => {
    const auth = new BearerAuthenticator("secret");
    const result = await auth.authenticate(new Request("http://localhost/mcp", {
      headers: { authorization: "Bearer secret" },
    }));

    expect(result).toEqual({ kind: "bearer", subject: "bearer-token", scopes: [] });
  });

  it("rejects invalid bearer token", async () => {
    const auth = new BearerAuthenticator("secret");
    await expect(auth.authenticate(new Request("http://localhost/mcp", {
      headers: { authorization: "Bearer wrong" },
    }))).rejects.toThrow("invalid bearer token");
  });

  it("validates authorization header helper", () => {
    expect(validateBearerAuthorization("Bearer secret", "secret"))
      .toEqual({ kind: "bearer", subject: "bearer-token", scopes: [] });
    expect(() => validateBearerAuthorization(null, "secret")).toThrow();
  });
});
