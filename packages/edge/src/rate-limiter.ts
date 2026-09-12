export interface RateLimitOptions {
  windowMs?: number;
  maxRequests?: number;
  maxKeys?: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  retryAfterMs: number;
}

interface WindowState {
  startedAtMs: number;
  count: number;
}

const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_MAX_REQUESTS = 120;
const DEFAULT_MAX_KEYS = 10_000;

export class FixedWindowRateLimiter {
  private readonly windowMs: number;
  private readonly maxRequests: number;
  private readonly maxKeys: number;
  private readonly windows = new Map<string, WindowState>();

  constructor(options: RateLimitOptions = {}) {
    this.windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
    this.maxRequests = options.maxRequests ?? DEFAULT_MAX_REQUESTS;
    this.maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
    if (!Number.isSafeInteger(this.windowMs) || this.windowMs < 1_000 || this.windowMs > 86_400_000 ||
        !Number.isSafeInteger(this.maxRequests) || this.maxRequests < 1 || this.maxRequests > 100_000 ||
        !Number.isSafeInteger(this.maxKeys) || this.maxKeys < 1 || this.maxKeys > 1_000_000) {
      throw new Error("Rate-limit bounds are outside the supported range");
    }
  }

  consume(key: string, nowMs = Date.now()): RateLimitDecision {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(key) || !Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw new Error("Rate-limit identity or clock value is invalid");
    }
    this.prune(nowMs);
    let state = this.windows.get(key);
    if (!state) {
      if (this.windows.size >= this.maxKeys) {
        return { allowed: false, remaining: 0, retryAfterMs: this.windowMs };
      }
      state = { startedAtMs: nowMs, count: 0 };
      this.windows.set(key, state);
    }
    if (nowMs - state.startedAtMs >= this.windowMs) {
      state.startedAtMs = nowMs;
      state.count = 0;
    }
    if (state.count >= this.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: Math.max(1, this.windowMs - (nowMs - state.startedAtMs))
      };
    }
    state.count += 1;
    return {
      allowed: true,
      remaining: this.maxRequests - state.count,
      retryAfterMs: 0
    };
  }

  size(): number {
    return this.windows.size;
  }

  private prune(nowMs: number): void {
    for (const [key, state] of this.windows) {
      if (nowMs - state.startedAtMs >= this.windowMs) this.windows.delete(key);
    }
  }
}
