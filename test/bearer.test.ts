import { describe, expect, it } from "vitest";
import { BearerAuthenticator, validateBearerAuthorization } from "../src/auth/bearer.js";

describe("bearer auth", () => {
  it("accepts valid bearer token", async () => {
    const auth = new BearerAuthenticator("secret");
    const result = await auth.authenticate(new Request("http://localhost/mcp", {
      headers: { authorization: "Bearer secret" },
    }));

    expect(result.subject).toBe("bearer-token");
  });

  it("rejects invalid bearer token", async () => {
    const auth = new BearerAuthenticator("secret");
    await expect(auth.authenticate(new Request("http://localhost/mcp", {
      headers: { authorization: "Bearer wrong" },
    }))).rejects.toThrow("invalid bearer token");
  });

  it("validates authorization header helper", () => {
    expect(validateBearerAuthorization("Bearer secret", "secret").subject)
      .toBe("bearer-token");
    expect(() => validateBearerAuthorization(null, "secret")).toThrow();
  });
});
