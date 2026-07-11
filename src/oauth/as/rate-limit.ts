export type OAuthRateLimitBucket =
  | "registration"
  | "authorization"
  | "token"
  | "approval";

interface WindowEntry {
  count: number;
  resetsAt: number;
}

export class OAuthRateLimiter {
  private readonly entries = new Map<string, WindowEntry>();

  constructor(
    private readonly windowSeconds: number,
    private readonly limits: Record<OAuthRateLimitBucket, number>,
  ) {}

  consume(bucket: OAuthRateLimitBucket, subject: string, now = Date.now()): number | undefined {
    this.prune(now);
    const key = `${bucket}:${subject}`;
    const current = this.entries.get(key);
    if (!current) {
      this.entries.set(key, {
        count: 1,
        resetsAt: now + this.windowSeconds * 1000,
      });
      return undefined;
    }
    if (current.count >= this.limits[bucket]) {
      return Math.max(1, Math.ceil((current.resetsAt - now) / 1000));
    }
    current.count += 1;
    return undefined;
  }

  private prune(now: number): void {
    for (const [key, entry] of this.entries) {
      if (entry.resetsAt <= now) this.entries.delete(key);
    }
  }
}
