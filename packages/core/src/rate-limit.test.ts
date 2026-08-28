import { describe, it, expect } from "vitest";
import { TokenBucket } from "./rate-limit";

describe("TokenBucket", () => {
  it("allows up to the burst capacity, then blocks", () => {
    const b = new TokenBucket(3, 1, { tokens: 3, lastRefillMs: 0 });
    expect(b.tryConsume(0)).toBe(true);
    expect(b.tryConsume(0)).toBe(true);
    expect(b.tryConsume(0)).toBe(true);
    expect(b.tryConsume(0)).toBe(false); // exhausted
  });

  it("refills over time at refillPerSec", () => {
    const b = new TokenBucket(3, 2, { tokens: 0, lastRefillMs: 0 });
    expect(b.tryConsume(0)).toBe(false);      // empty
    expect(b.tryConsume(1000)).toBe(true);    // +2 tokens after 1s, spend 1
    expect(b.tryConsume(1000)).toBe(true);    // spend the 2nd
    expect(b.tryConsume(1000)).toBe(false);   // empty again
  });

  it("never exceeds capacity on refill", () => {
    const b = new TokenBucket(3, 100, { tokens: 3, lastRefillMs: 0 });
    expect(b.tryConsume(10_000)).toBe(true);
    expect(b.tryConsume(10_000)).toBe(true);
    expect(b.tryConsume(10_000)).toBe(true);
    expect(b.tryConsume(10_000)).toBe(false);
  });
});
