import { describe, expect, it } from "vitest";
import { LEVITATE_META_PREFIX, stripReservedMeta } from "../src/mcp/meta.js";

describe("reserved metadata stripping", () => {
  it("drops metadata claiming Levitate's namespace", () => {
    const { params, strippedKeys } = stripReservedMeta({
      name: "fake_allowed",
      _meta: {
        [`${LEVITATE_META_PREFIX}principal`]: { subject: "attacker" },
        [`${LEVITATE_META_PREFIX}anything-else`]: true,
      },
    });

    expect(params._meta).toBeUndefined();
    expect(strippedKeys).toEqual([
      `${LEVITATE_META_PREFIX}principal`,
      `${LEVITATE_META_PREFIX}anything-else`,
    ]);
  });

  it("preserves every other metadata entry exactly", () => {
    const progressToken = 7;
    const { params, strippedKeys } = stripReservedMeta({
      name: "fake_allowed",
      _meta: {
        progressToken,
        "com.example/trace": { id: "trace-1" },
        "io.modelcontextprotocol/related-task": { taskId: "task-1" },
        [`${LEVITATE_META_PREFIX}principal`]: { subject: "attacker" },
      },
    });

    expect(params._meta).toEqual({
      progressToken,
      "com.example/trace": { id: "trace-1" },
      "io.modelcontextprotocol/related-task": { taskId: "task-1" },
    });
    expect(strippedKeys).toEqual([`${LEVITATE_META_PREFIX}principal`]);
  });

  it("leaves untouched requests unchanged", () => {
    const original = {
      name: "fake_allowed",
      _meta: { "com.example/trace": "trace-1" },
    };

    const { params, strippedKeys } = stripReservedMeta(original);

    expect(params).toBe(original);
    expect(strippedKeys).toEqual([]);
  });

  it("handles requests carrying no metadata", () => {
    const original: { name: string; _meta?: { [key: string]: unknown } } = {
      name: "fake_allowed",
    };

    const { params, strippedKeys } = stripReservedMeta(original);

    expect(params).toBe(original);
    expect(strippedKeys).toEqual([]);
  });

  it("ignores case, so a variant cannot slip past a careless backend", () => {
    const { params, strippedKeys } = stripReservedMeta({
      _meta: { "IO.GitHub.Iomz.Levitate/Principal": { subject: "attacker" } },
    });

    expect(params._meta).toBeUndefined();
    expect(strippedKeys).toEqual(["IO.GitHub.Iomz.Levitate/Principal"]);
  });

  it("does not mutate the caller's request", () => {
    const meta = { [`${LEVITATE_META_PREFIX}principal`]: { subject: "attacker" } };
    const original = { name: "fake_allowed", _meta: meta };

    stripReservedMeta(original);

    expect(original._meta).toBe(meta);
    expect(Object.keys(meta)).toEqual([`${LEVITATE_META_PREFIX}principal`]);
  });
});
