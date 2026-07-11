import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export interface AuthorizationCodeRecord {
  codeHash: string;
  clientId: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  codeChallenge: string;
  codeChallengeMethod: "S256";
  subject: string;
  expiresAt: number;
  usedAt?: number;
}

export class AuthorizationCodeStore {
  private readonly codes = new Map<string, AuthorizationCodeRecord>();

  create(record: Omit<AuthorizationCodeRecord, "codeHash" | "usedAt">): string {
    this.pruneExpired();
    const code = randomBytes(32).toString("base64url");
    this.codes.set(hashValue(code), {
      ...record,
      codeHash: hashValue(code),
    });
    return code;
  }

  get(code: string): AuthorizationCodeRecord {
    this.pruneExpired();
    const codeHash = hashValue(code);
    const record = this.codes.get(codeHash);
    if (!record) throw new Error("invalid authorization code");
    if (record.usedAt) throw new Error("authorization code already used");
    if (record.expiresAt <= Date.now()) {
      this.codes.delete(codeHash);
      throw new Error("authorization code expired");
    }
    return record;
  }

  markUsed(code: string): void {
    const record = this.get(code);
    record.usedAt = Date.now();
  }

  pruneExpired(now = Date.now()): number {
    let removed = 0;
    for (const [codeHash, record] of this.codes.entries()) {
      if (record.expiresAt <= now) {
        this.codes.delete(codeHash);
        removed += 1;
      }
    }
    return removed;
  }
}

export function hashValue(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function verifyPkceS256(verifier: string, challenge: string): boolean {
  const actual = Buffer.from(hashValue(verifier));
  const expected = Buffer.from(challenge);
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}
