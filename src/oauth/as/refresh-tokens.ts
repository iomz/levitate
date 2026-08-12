import { randomBytes, randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { hashValue } from "./codes.js";

const REPLAY_DETECTION_WINDOW_MS = 24 * 60 * 60 * 1000;

export interface RefreshTokenRecord {
  token_hash: string;
  family_id: string;
  client_id: string;
  resource: string;
  subject: string;
  scopes: string[];
  created_at: string;
  expires_at: string;
  used_at?: string;
  revoked_at?: string;
}

interface RefreshTokenStoreFile {
  refresh_tokens: RefreshTokenRecord[];
}

export interface RefreshTokenGrant {
  token: string;
  record: RefreshTokenRecord;
}

export class RefreshTokenError extends Error {
  constructor(public readonly reason: "invalid" | "invalid_scope" | "reused") {
    super(`refresh token ${reason}`);
  }
}

export class JsonRefreshTokenStore {
  private readonly path: string;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(path: string) {
    this.path = resolve(path);
  }

  async issue(
    input: Pick<RefreshTokenRecord, "client_id" | "resource" | "subject" | "scopes">,
    ttlSeconds: number,
    now = new Date(),
  ): Promise<RefreshTokenGrant> {
    return this.withWriteLock(async () => {
      const data = await this.read();
      data.refresh_tokens = retainedRecords(data.refresh_tokens, now);
      const grant = createGrant(input, randomUUID(), new Date(now.getTime() + ttlSeconds * 1000), now);
      data.refresh_tokens.push(grant.record);
      await this.write(data);
      return grant;
    });
  }

  async rotate(
    token: string,
    input: { clientId: string; resource?: string; scopes?: string[] },
    ttlSeconds: number,
    now = new Date(),
  ): Promise<RefreshTokenGrant> {
    return this.withWriteLock(async () => {
      const data = await this.read();
      data.refresh_tokens = retainedRecords(data.refresh_tokens, now);
      const record = data.refresh_tokens.find((entry) => entry.token_hash === hashValue(token));
      if (!record || Date.parse(record.expires_at) <= now.getTime() || record.revoked_at) {
        throw new RefreshTokenError("invalid");
      }
      if (record.used_at) {
        const revokedAt = now.toISOString();
        for (const entry of data.refresh_tokens) {
          if (entry.family_id === record.family_id) entry.revoked_at ??= revokedAt;
        }
        await this.write(data);
        throw new RefreshTokenError("reused");
      }
      if (
        record.client_id !== input.clientId ||
        (input.resource !== undefined && record.resource !== input.resource)
      ) {
        throw new RefreshTokenError("invalid");
      }
      const scopes = input.scopes ?? record.scopes;
      if (!scopes.length || !scopes.every((scope) => record.scopes.includes(scope))) {
        throw new RefreshTokenError("invalid_scope");
      }

      record.used_at = now.toISOString();
      const grant = createGrant(
        {
          client_id: record.client_id,
          resource: record.resource,
          subject: record.subject,
          scopes,
        },
        record.family_id,
        new Date(now.getTime() + ttlSeconds * 1000),
        now,
      );
      data.refresh_tokens.push(grant.record);
      await this.write(data);
      return grant;
    });
  }

  async pruneExpired(now = new Date()): Promise<number> {
    return this.withWriteLock(async () => {
      const data = await this.read();
      const retained = retainedRecords(data.refresh_tokens, now);
      const removed = data.refresh_tokens.length - retained.length;
      if (removed) await this.write({ refresh_tokens: retained });
      return removed;
    });
  }

  private async read(): Promise<RefreshTokenStoreFile> {
    try {
      const parsed = JSON.parse(await readFile(this.path, "utf8")) as Partial<RefreshTokenStoreFile>;
      return {
        refresh_tokens: Array.isArray(parsed.refresh_tokens)
          ? parsed.refresh_tokens as RefreshTokenRecord[]
          : [],
      };
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") {
        return { refresh_tokens: [] };
      }
      throw error;
    }
  }

  private async write(data: RefreshTokenStoreFile): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tempPath = `${this.path}.${process.pid}.${Date.now()}.${randomUUID()}.tmp`;
    await writeFile(tempPath, `${JSON.stringify(data, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(tempPath, this.path);
    await chmod(this.path, 0o600);
  }

  private async withWriteLock<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.writeChain.then(operation, operation);
    this.writeChain = run.then(() => undefined, () => undefined);
    return run;
  }
}

function retainedRecords(
  records: RefreshTokenRecord[],
  now: Date,
): RefreshTokenRecord[] {
  const replayCutoff = now.getTime() - REPLAY_DETECTION_WINDOW_MS;
  return records.filter((entry) =>
    Date.parse(entry.expires_at) > now.getTime() &&
    !entry.revoked_at &&
    (!entry.used_at || Date.parse(entry.used_at) > replayCutoff)
  );
}

function createGrant(
  input: Pick<RefreshTokenRecord, "client_id" | "resource" | "subject" | "scopes">,
  familyId: string,
  expiresAt: Date,
  now: Date,
): RefreshTokenGrant {
  const token = randomBytes(32).toString("base64url");
  return {
    token,
    record: {
      token_hash: hashValue(token),
      family_id: familyId,
      ...input,
      scopes: [...input.scopes],
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    },
  };
}
