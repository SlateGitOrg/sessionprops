/**
 * A reference auth server with seeded session flaws.
 *
 * The flaws are documented so the suite's detection power is demonstrable. A
 * property-based suite that finds nothing is indistinguishable from one that
 * cannot find anything, and the only way to tell them apart is to point it at
 * a system whose bugs you already know.
 */

export type Flaw =
  | 'NO_ROTATION_ON_ELEVATION'
  | 'LOGOUT_CLIENT_SIDE_ONLY'
  | 'SURVIVES_PASSWORD_CHANGE'
  | 'NO_IDLE_TIMEOUT'
  | 'NO_ABSOLUTE_TIMEOUT'
  | 'UNLIMITED_CONCURRENT_SESSIONS'
  | 'PREDICTABLE_SESSION_ID';

export interface SessionRecord {
  id: string;
  userId: string;
  elevated: boolean;
  createdAt: number;
  lastSeenAt: number;
  revoked: boolean;
  passwordEpoch: number;
}

export interface ServerConfig {
  readonly flaws: ReadonlySet<Flaw>;
  readonly idleTimeoutMs?: number;
  readonly absoluteTimeoutMs?: number;
  readonly maxConcurrentSessions?: number;
}

export const HARDENED: ServerConfig = {
  flaws: new Set(),
  idleTimeoutMs: 15 * 60_000,
  absoluteTimeoutMs: 8 * 3_600_000,
  maxConcurrentSessions: 3,
};

export const VULNERABLE: ServerConfig = {
  flaws: new Set<Flaw>([
    'NO_ROTATION_ON_ELEVATION', 'LOGOUT_CLIENT_SIDE_ONLY',
    'SURVIVES_PASSWORD_CHANGE', 'NO_IDLE_TIMEOUT', 'NO_ABSOLUTE_TIMEOUT',
    'UNLIMITED_CONCURRENT_SESSIONS', 'PREDICTABLE_SESSION_ID',
  ]),
  idleTimeoutMs: 15 * 60_000,
  absoluteTimeoutMs: 8 * 3_600_000,
  maxConcurrentSessions: 3,
};

export class AuthServer {
  private sessions = new Map<string, SessionRecord>();
  private passwordEpoch = new Map<string, number>();
  private counter = 0;
  private now = 0;
  readonly config: ServerConfig;

  constructor(config: ServerConfig) {
    this.config = config;
  }

  advance(ms: number): void {
    this.now += ms;
  }
  get clock(): number {
    return this.now;
  }

  private mint(): string {
    this.counter++;
    if (this.config.flaws.has('PREDICTABLE_SESSION_ID')) {
      // Sequential, so a session id can simply be guessed.
      return `sess-${this.counter}`;
    }
    const rand = `${Math.random()}${Math.random()}${this.counter}`;
    let h = 0;
    for (let i = 0; i < rand.length; i++) h = (Math.imul(31, h) + rand.charCodeAt(i)) | 0;
    return `sess-${(h >>> 0).toString(36)}-${this.counter.toString(36)}`;
  }

  login(userId: string): string {
    const epoch = this.passwordEpoch.get(userId) ?? 0;

    if (!this.config.flaws.has('UNLIMITED_CONCURRENT_SESSIONS')) {
      const live = [...this.sessions.values()]
        .filter((s) => s.userId === userId && !s.revoked)
        .sort((a, b) => a.createdAt - b.createdAt);
      const max = this.config.maxConcurrentSessions ?? 3;
      while (live.length >= max) {
        const oldest = live.shift()!;
        oldest.revoked = true;
      }
    }

    const id = this.mint();
    this.sessions.set(id, {
      id, userId, elevated: false, createdAt: this.now, lastSeenAt: this.now,
      revoked: false, passwordEpoch: epoch,
    });
    return id;
  }

  /** Step up to a privileged session (re-auth, MFA, sudo mode). */
  elevate(sessionId: string): string | null {
    const s = this.sessions.get(sessionId);
    if (!s || !this.isValid(sessionId)) return null;

    if (this.config.flaws.has('NO_ROTATION_ON_ELEVATION')) {
      // The flaw: the identifier a pre-elevation attacker may already hold now
      // carries elevated privileges.
      s.elevated = true;
      return sessionId;
    }
    s.revoked = true;
    const id = this.mint();
    this.sessions.set(id, {
      id, userId: s.userId, elevated: true, createdAt: s.createdAt,
      lastSeenAt: this.now, revoked: false, passwordEpoch: s.passwordEpoch,
    });
    return id;
  }

  logout(sessionId: string): void {
    if (this.config.flaws.has('LOGOUT_CLIENT_SIDE_ONLY')) return;
    const s = this.sessions.get(sessionId);
    if (s) s.revoked = true;
  }

  changePassword(userId: string): void {
    this.passwordEpoch.set(userId, (this.passwordEpoch.get(userId) ?? 0) + 1);
    if (this.config.flaws.has('SURVIVES_PASSWORD_CHANGE')) return;
    for (const s of this.sessions.values()) {
      if (s.userId === userId) s.revoked = true;
    }
  }

  /**
   * Validate WITHOUT touching `lastSeenAt`.
   *
   * The invariant checker needs this. Asserting with `isValid` refreshes the
   * idle window on every session on every check, so the idle timeout can never
   * fire and the test silently measures nothing. An assertion that mutates the
   * system under test is not an assertion.
   */
  peekValid(sessionId: string): boolean {
    const s = this.sessions.get(sessionId);
    if (!s || s.revoked) return false;

    const currentEpoch = this.passwordEpoch.get(s.userId) ?? 0;
    if (!this.config.flaws.has('SURVIVES_PASSWORD_CHANGE') &&
        s.passwordEpoch !== currentEpoch) {
      return false;
    }
    if (!this.config.flaws.has('NO_IDLE_TIMEOUT')) {
      const idle = this.config.idleTimeoutMs ?? Infinity;
      if (this.now - s.lastSeenAt > idle) return false;
    }
    if (!this.config.flaws.has('NO_ABSOLUTE_TIMEOUT')) {
      const abs = this.config.absoluteTimeoutMs ?? Infinity;
      if (this.now - s.createdAt > abs) return false;
    }
    return true;
  }

  peekElevated(sessionId: string): boolean {
    return this.peekValid(sessionId) && !!this.sessions.get(sessionId)?.elevated;
  }

  /** When was this session last seen? Used by the model, not by the app. */
  lastSeen(sessionId: string): number | null {
    return this.sessions.get(sessionId)?.lastSeenAt ?? null;
  }

  /** Validate, and touch `lastSeenAt` as a real request would. */
  isValid(sessionId: string): boolean {
    const s = this.sessions.get(sessionId);
    if (!s || s.revoked) return false;

    const currentEpoch = this.passwordEpoch.get(s.userId) ?? 0;
    if (!this.config.flaws.has('SURVIVES_PASSWORD_CHANGE') &&
        s.passwordEpoch !== currentEpoch) {
      return false;
    }
    if (!this.config.flaws.has('NO_IDLE_TIMEOUT')) {
      const idle = this.config.idleTimeoutMs ?? Infinity;
      if (this.now - s.lastSeenAt > idle) return false;
    }
    if (!this.config.flaws.has('NO_ABSOLUTE_TIMEOUT')) {
      const abs = this.config.absoluteTimeoutMs ?? Infinity;
      if (this.now - s.createdAt > abs) return false;
    }
    s.lastSeenAt = this.now;
    return true;
  }

  isElevated(sessionId: string): boolean {
    const s = this.sessions.get(sessionId);
    return this.isValid(sessionId) && !!s?.elevated;
  }

  liveSessionsFor(userId: string): number {
    return [...this.sessions.values()]
      .filter((s) => s.userId === userId && this.peekValid(s.id)).length;
  }

  knownIds(): string[] {
    return [...this.sessions.keys()];
  }
}
