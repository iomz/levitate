import { describe, expect, it } from "vitest";
import { parseConfigText } from "../src/config.js";

describe("config parsing", () => {
  it("parses required MVP config", () => {
    const config = parseConfigText(`
[server]
name = "brain"
host = "127.0.0.1"
port = 8787

[stdio]
command = "node"
args = ["server.js"]

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[tools]
allow = ["search"]
deny = ["delete_note"]
`);

    expect(config.server.name).toBe("brain");
    expect(config.stdio.command).toBe("node");
    expect(config.auth.mode).toBe("bearer");
    expect(config.tools.allow).toEqual(["search"]);
    expect(config.tools.deny).toEqual(["delete_note"]);
  });

  it("rejects bearer auth without token source", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "bearer"
`)).toThrow();
  });

  it("parses oidc auth config", () => {
    const config = parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "oidc"
issuer = "https://auth.example.test/"
audience = "https://levitate.example.test"
jwks_uri = "https://auth.example.test/.well-known/jwks.json"
allowed_subjects = ["client-id@clients"]
`);

    expect(config.auth.mode).toBe("oidc");
    if (config.auth.mode === "oidc") {
      expect(config.auth.jwks_uri).toBe("https://auth.example.test/.well-known/jwks.json");
      expect(config.auth.allowed_subjects).toEqual(["client-id@clients"]);
    }
  });

  it("rejects oidc issuer without https", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "oidc"
issuer = "http://auth.example.test/"
audience = "https://levitate.example.test"
jwks_uri = "https://auth.example.test/.well-known/jwks.json"
`)).toThrow("OIDC URLs must use https");
  });

  it("rejects oidc jwks uri without https", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "oidc"
issuer = "https://auth.example.test/"
audience = "https://levitate.example.test"
jwks_uri = "http://auth.example.test/.well-known/jwks.json"
`)).toThrow("OIDC URLs must use https");
  });
});
