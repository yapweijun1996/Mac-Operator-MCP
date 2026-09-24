import type { JwtRevocationContext } from "./jwt-verifier.js";

export interface OAuthGrantStatus {
  active: boolean;
  scopes: readonly string[];
}

export type OAuthGrantStatusReader = (context: JwtRevocationContext) => Promise<OAuthGrantStatus>;

/** Read the owner-authenticated grant status without converting transport errors into authority loss. */
export function createOAuthGrantStatusReader(options: { url: URL; key: Buffer; fetch?: typeof fetch }): OAuthGrantStatusReader {
  if (options.url.protocol !== "https:" || options.url.username || options.url.password || options.url.hash || options.key.length !== 32) {
    throw new Error("Invalid OAuth grant status configuration");
  }
  return async (context: JwtRevocationContext): Promise<OAuthGrantStatus> => {
    const response = await (options.fetch ?? fetch)(options.url, {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(3000),
      headers: { "content-type": "application/json", authorization: `Bearer ${options.key.toString("hex")}` },
      body: JSON.stringify({ sessionId: context.sessionId, subject: context.subject })
    });
    if (!response.ok || (response.url && response.url !== options.url.href) ||
        !response.headers.get("content-type")?.startsWith("application/json") || !response.body) {
      await response.body?.cancel(); throw new Error("OAuth grant status response is unavailable");
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const result = await reader.read();
        if (result.done) break;
        size += result.value.length;
        if (size > 4096) throw new Error("OAuth grant status response is oversized");
        chunks.push(result.value);
      }
    } finally { await reader.cancel(); }
    let value: unknown;
    try { value = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { throw new Error("OAuth grant status response is invalid JSON"); }
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("OAuth grant status response is malformed");
    const record = value as { active?: unknown; scopes?: unknown };
    if (Object.keys(record).sort().join(",") !== "active,scopes" || typeof record.active !== "boolean" ||
        !Array.isArray(record.scopes) || record.scopes.length > 32 || record.scopes.some(scope => typeof scope !== "string" || scope.length > 128)) {
      throw new Error("OAuth grant status response is malformed");
    }
    return { active: record.active, scopes: Object.freeze([...record.scopes] as string[]) };
  };
}

/** Check current issuer authority for every token use; outages never permit access. */
export function createOAuthGrantRevocationCheck(options: { url: URL; key: Buffer; fetch?: typeof fetch }) {
  const readStatus = createOAuthGrantStatusReader(options);
  return async (context: JwtRevocationContext): Promise<boolean> => {
    try {
      const status = await readStatus(context);
      return isOAuthGrantRevoked(context, status);
    } catch { return true; }
  };
}

export function isOAuthGrantRevoked(context: JwtRevocationContext, status: OAuthGrantStatus): boolean {
  return !status.active || context.scopes.some(scope => !status.scopes.includes(scope));
}

export interface OAuthGrantRevocationMonitorOptions {
  readStatus: OAuthGrantStatusReader;
  onRevoked: (context: JwtRevocationContext) => Promise<void>;
  intervalMs?: number;
  maxSessions?: number;
  now?: () => number;
}

/**
 * Poll only recently accepted, bounded sessions so an idle active Job can still
 * observe an explicit issuer revocation without waiting for another request.
 * Transport failures retain the session for retry and never become revocation.
 */
export class OAuthGrantRevocationMonitor {
  private readonly sessions = new Map<string, JwtRevocationContext>();
  private readonly inFlight = new Set<string>();
  private readonly intervalMs: number;
  private readonly maxSessions: number;
  private readonly now: () => number;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running = false;
  private polling = false;

  constructor(private readonly options: OAuthGrantRevocationMonitorOptions) {
    this.intervalMs = boundedInteger(options.intervalMs ?? 5_000, 250, 60_000, "OAuth revocation monitor interval");
    this.maxSessions = boundedInteger(options.maxSessions ?? 128, 1, 1_024, "OAuth revocation monitor session limit");
    this.now = options.now ?? Date.now;
  }

  track(context: JwtRevocationContext): void {
    const key = `${context.subject}:${context.sessionId}`;
    if (!this.sessions.has(key) && this.sessions.size >= this.maxSessions) {
      this.pruneExpired();
      if (this.sessions.size >= this.maxSessions) throw new Error("OAuth revocation monitor capacity exceeded");
    }
    this.sessions.set(key, Object.freeze({ ...context, scopes: Object.freeze([...context.scopes]) }));
  }

  /**
   * Accept an owner-authenticated issuer push and keep the existing retry
   * semantics if Edge cannot reach the Broker yet.
   */
  async notifyRevoked(context: JwtRevocationContext): Promise<void> {
    const key = `${context.subject}:${context.sessionId}`;
    try {
      await this.options.onRevoked(context);
      this.sessions.delete(key);
    } catch (error) {
      this.track(context);
      throw error;
    }
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.schedule();
  }

  stop(): void {
    this.running = false;
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    this.sessions.clear();
    this.inFlight.clear();
  }

  private schedule(): void {
    if (!this.running) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.poll().finally(() => this.schedule());
    }, this.intervalMs);
    this.timer.unref?.();
  }

  private async poll(): Promise<void> {
    if (this.polling) return;
    this.polling = true;
    try {
      this.pruneExpired();
      for (const [key, context] of this.sessions) {
        if (!this.running || this.inFlight.has(key)) continue;
        this.inFlight.add(key);
        try {
          const status = await this.options.readStatus(context);
          if (status.active && context.scopes.every(scope => status.scopes.includes(scope))) continue;
          await this.options.onRevoked(context);
          this.sessions.delete(key);
        } catch {
          // Keep the session for a bounded retry. Only an explicit status result
          // or a successful Broker revocation removes it from the monitor.
        } finally {
          this.inFlight.delete(key);
        }
      }
    } finally {
      this.polling = false;
    }
  }

  private pruneExpired(): void {
    const nowSeconds = Math.floor(this.now() / 1_000);
    for (const [key, context] of this.sessions) if (context.expiresAt <= nowSeconds) this.sessions.delete(key);
  }
}

function boundedInteger(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`${label} is invalid`);
  return value;
}
