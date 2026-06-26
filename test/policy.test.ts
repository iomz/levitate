import { describe, expect, it } from "vitest";
import { deniedReason, filterTools, isToolAllowed } from "../src/mcp/policy.js";

describe("tool policy", () => {
  const tools = [
    { name: "search" },
    { name: "read_note" },
    { name: "delete_note" },
  ];

  it("prefers allowlist and applies denylist guard", () => {
    const policy = {
      allow: ["search", "delete_note"],
      deny: ["delete_note"],
    };

    expect(filterTools(tools, policy)).toEqual([{ name: "search" }]);
    expect(isToolAllowed("read_note", policy)).toBe(false);
    expect(isToolAllowed("delete_note", policy)).toBe(false);
  });

  it("reports denial reason", () => {
    expect(deniedReason("read_note", {
      allow: ["search"],
      deny: [],
    })).toBe("tool not in allowlist");

    expect(deniedReason("delete_note", {
      deny: ["delete_note"],
    })).toBe("tool in denylist");
  });
});
