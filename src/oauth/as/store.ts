import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

export interface OAuthClient {
  client_id: string;
  client_name?: string;
  registration_method?: "cimd" | "dcr";
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: "none";
  scope?: string;
  revoked_at?: string;
}

export interface RegisteredClient extends OAuthClient {
  created_at: string;
}

interface ClientStoreFile {
  clients: RegisteredClient[];
}

export interface ClientLookup {
  get(clientId: string): Promise<OAuthClient | undefined>;
}

export interface ClientStore extends ClientLookup {
  add(client: Omit<RegisteredClient, "client_id" | "created_at">): Promise<RegisteredClient>;
  list(): Promise<RegisteredClient[]>;
  revoke(clientId: string): Promise<RegisteredClient | undefined>;
}

export class JsonClientStore implements ClientStore {
  private readonly path: string;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(path: string) {
    this.path = resolve(path);
  }

  async add(client: Omit<RegisteredClient, "client_id" | "created_at">): Promise<RegisteredClient> {
    return this.withWriteLock(async () => {
      const data = await this.read();
      const registered: RegisteredClient = {
        ...client,
        client_id: randomUUID(),
        created_at: new Date().toISOString(),
        registration_method: "dcr",
      };
      data.clients.push(registered);
      await this.write(data);
      return registered;
    });
  }

  async get(clientId: string): Promise<RegisteredClient | undefined> {
    const data = await this.read();
    const client = data.clients.find((entry) => entry.client_id === clientId);
    return client
      ? { ...client, registration_method: client.registration_method ?? "dcr" }
      : undefined;
  }

  async list(): Promise<RegisteredClient[]> {
    const data = await this.read();
    return data.clients;
  }

  async revoke(clientId: string): Promise<RegisteredClient | undefined> {
    return this.withWriteLock(async () => {
      const data = await this.read();
      const client = data.clients.find((entry) => entry.client_id === clientId);
      if (!client) return undefined;
      client.revoked_at ??= new Date().toISOString();
      await this.write(data);
      return client;
    });
  }

  private async read(): Promise<ClientStoreFile> {
    try {
      const text = await readFile(this.path, "utf8");
      const parsed = JSON.parse(text) as Partial<ClientStoreFile>;
      return {
        clients: Array.isArray(parsed.clients) ? parsed.clients as RegisteredClient[] : [],
      };
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") {
        return { clients: [] };
      }
      throw error;
    }
  }

  private async write(data: ClientStoreFile): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tempPath = `${this.path}.${process.pid}.${Date.now()}.${randomUUID()}.tmp`;
    await writeFile(tempPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
    await rename(tempPath, this.path);
  }

  private async withWriteLock<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.writeChain.then(operation, operation);
    this.writeChain = run.then(() => undefined, () => undefined);
    return run;
  }
}
