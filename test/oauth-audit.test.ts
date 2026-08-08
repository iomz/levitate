import { describe, expect, it } from "vitest";
import { oauthClientAuditFields } from "../src/oauth/as/audit.js";

describe("oauth client audit fields", () => {
  it("logs only origins for submitted URL client IDs", () => {
    expect(oauthClientAuditFields("https://chatgpt.com/oauth/client.json?secret=value")).toEqual({
      clientOrigin: "https://chatgpt.com",
    });
  });

  it("hashes opaque or credential-bearing submitted client IDs", () => {
    const opaque = oauthClientAuditFields("private-client-value");
    const credentialBearing = oauthClientAuditFields("https://user:secret@example.com/client.json");

    expect(opaque).toEqual({ clientIdHash: expect.stringMatching(/^[a-f0-9]{16}$/) });
    expect(credentialBearing).toEqual({ clientIdHash: expect.stringMatching(/^[a-f0-9]{16}$/) });
    expect(JSON.stringify([opaque, credentialBearing])).not.toContain("private-client-value");
    expect(JSON.stringify([opaque, credentialBearing])).not.toContain("secret");
  });
});
