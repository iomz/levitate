import type { LevitateConfig } from "../../config.js";
import { JsonClientStore, type RegisteredClient } from "./store.js";

export async function runOAuthClientsCommand(
  config: LevitateConfig,
  args: string[],
  stdout: Pick<NodeJS.WriteStream, "write"> = process.stdout,
): Promise<void> {
  const command = args[0];
  const clientId = args[1];
  const store = getClientStore(config);

  if (command === "list") {
    stdout.write(`${JSON.stringify((await store.list()).map(clientSummary), null, 2)}\n`);
    return;
  }

  if (command === "show" && clientId) {
    const client = await store.get(clientId);
    if (!client) throw new Error(`oauth client not found: ${clientId}`);
    stdout.write(`${JSON.stringify(clientSummary(client), null, 2)}\n`);
    return;
  }

  if (command === "revoke" && clientId) {
    const client = await store.revoke(clientId);
    if (!client) throw new Error(`oauth client not found: ${clientId}`);
    stdout.write(`${JSON.stringify(clientSummary(client), null, 2)}\n`);
    return;
  }

  throw new Error("usage: levitate oauth clients list|show <client_id>|revoke <client_id>");
}

function getClientStore(config: LevitateConfig): JsonClientStore {
  const path = config.oauth.as.client_store_file;
  if (!path) throw new Error("oauth.as.client_store_file is required for oauth client management");
  return new JsonClientStore(path);
}

function clientSummary(client: RegisteredClient): Record<string, unknown> {
  return {
    client_id: client.client_id,
    client_name: client.client_name,
    redirect_uris: client.redirect_uris,
    grant_types: client.grant_types,
    response_types: client.response_types,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    scope: client.scope,
    created_at: client.created_at,
    revoked_at: client.revoked_at,
  };
}
