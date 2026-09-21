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

  it("preserves a JSON-parsed __proto__ entry as an own property", () => {
    const meta = JSON.parse('{"__proto__":{"polluted":true},"com.example/trace":"t1"}');
    meta[`${LEVITATE_META_PREFIX}principal`] = { subject: "attacker" };

    const { params, strippedKeys } = stripReservedMeta({ name: "fake_allowed", _meta: meta });

    const sanitized = params._meta ?? {};
    expect(Object.prototype.hasOwnProperty.call(sanitized, "__proto__")).toBe(true);
    expect(Object.keys(sanitized)).toEqual(["__proto__", "com.example/trace"]);
    expect(Object.getPrototypeOf(sanitized)).toBe(Object.prototype);
    expect(strippedKeys).toEqual([`${LEVITATE_META_PREFIX}principal`]);
  });

  it("keeps _meta when __proto__ is the only entry left after stripping", () => {
    const meta = JSON.parse('{"__proto__":{"polluted":true}}');
    meta[`${LEVITATE_META_PREFIX}principal`] = { subject: "attacker" };

    const { params } = stripReservedMeta({ name: "fake_allowed", _meta: meta });

    expect(params._meta).toBeDefined();
    expect(Object.keys(params._meta ?? {})).toEqual(["__proto__"]);
  });

  it("does not mutate the caller's request", () => {
    const meta = { [`${LEVITATE_META_PREFIX}principal`]: { subject: "attacker" } };
    const original = { name: "fake_allowed", _meta: meta };

    stripReservedMeta(original);

    expect(original._meta).toBe(meta);
    expect(Object.keys(meta)).toEqual([`${LEVITATE_META_PREFIX}principal`]);
  });
});
