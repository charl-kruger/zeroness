/**
 * A pure token-bucket rate limiter. Time is injectable (`now`) so it is fully
 * deterministic under test. Not persisted — the caller owns lifetime.
 */
export interface TokenBucketState {
  tokens: number;
  lastRefillMs: number;
}

export class TokenBucket {
  constructor(
    private readonly capacity: number,
    private readonly refillPerSec: number,
    private state: TokenBucketState = { tokens: capacity, lastRefillMs: Date.now() },
  ) {}

  /** Attempt to spend one token. Returns true if allowed, false if exhausted. */
  tryConsume(now = Date.now()): boolean {
    const elapsedSec = Math.max(0, (now - this.state.lastRefillMs) / 1000);
    this.state.tokens = Math.min(this.capacity, this.state.tokens + elapsedSec * this.refillPerSec);
    this.state.lastRefillMs = now;
    if (this.state.tokens >= 1) {
      this.state.tokens -= 1;
      return true;
    }
    return false;
  }
}
