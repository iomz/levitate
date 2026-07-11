import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { JsonClientStore } from "../src/oauth/as/store.js";

describe("JSON OAuth client store", () => {
  it("serializes concurrent writes through one store instance", async () => {
    const directory = await mkdtemp(join(tmpdir(), "levitate-client-store-"));
    const path = join(directory, "clients.json");
    const store = new JsonClientStore(path);

    await Promise.all([
      store.add(client("one")),
      store.add(client("two")),
      store.add(client("three")),
    ]);

    expect((await store.list()).map((entry) => entry.client_name)).toEqual([
      "one",
      "two",
      "three",
    ]);
    await expect(readFile(path, "utf8")).resolves.toContain('"clients"');
  });

  it("persists client revocation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "levitate-client-store-"));
    const path = join(directory, "clients.json");
    const store = new JsonClientStore(path);
    const registered = await store.add(client("one"));

    await store.revoke(registered.client_id);

    const reloaded = new JsonClientStore(path);
    expect((await reloaded.get(registered.client_id))?.revoked_at).toBeTruthy();
  });
});

function client(name: string) {
  return {
    client_name: name,
    redirect_uris: [`https://example.com/${name}`],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none" as const,
  };
}
