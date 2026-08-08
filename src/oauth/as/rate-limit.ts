export type OAuthRateLimitBucket =
  | "registration"
  | "authorization"
  | "token"
  | "approval";

interface WindowEntry {
  count: number;
  resetsAt: number;
}

const DEFAULT_MAX_TRACKED_SUBJECTS = 1_024;
const OVERFLOW_SUBJECT = "__overflow__";

export class OAuthRateLimiter {
  private readonly entries = new Map<string, WindowEntry>();

  constructor(
    private readonly windowSeconds: number,
    private readonly limits: Record<OAuthRateLimitBucket, number>,
    private readonly maxTrackedSubjects = DEFAULT_MAX_TRACKED_SUBJECTS,
  ) {}

  consume(bucket: OAuthRateLimitBucket, subject: string, now = Date.now()): number | undefined {
    this.prune(now);
    const requestedKey = `${bucket}:${subject}`;
    const key = !this.entries.has(requestedKey) && this.countSubjects(bucket) >= this.maxTrackedSubjects
      ? `${bucket}:${OVERFLOW_SUBJECT}`
      : requestedKey;
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

  private countSubjects(bucket: OAuthRateLimitBucket): number {
    const prefix = `${bucket}:`;
    const overflowKey = `${bucket}:${OVERFLOW_SUBJECT}`;
    let count = 0;
    for (const key of this.entries.keys()) {
      if (key.startsWith(prefix) && key !== overflowKey) count += 1;
    }
    return count;
  }
}
