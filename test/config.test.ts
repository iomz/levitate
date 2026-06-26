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
});
