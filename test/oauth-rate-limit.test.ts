import { describe, expect, it } from "vitest";
import { OAuthRateLimiter } from "../src/oauth/as/rate-limit.js";

describe("oauth rate limiter", () => {
  it("limits subjects independently within fixed windows", () => {
    const limiter = new OAuthRateLimiter(60, {
      registration: 1,
      authorization: 1,
      token: 1,
      approval: 1,
    });

    expect(limiter.consume("token", "client-a", 1_000)).toBeUndefined();
    expect(limiter.consume("token", "client-a", 1_001)).toBe(60);
    expect(limiter.consume("token", "client-b", 1_001)).toBeUndefined();
    expect(limiter.consume("token", "client-a", 61_000)).toBeUndefined();
  });
});
