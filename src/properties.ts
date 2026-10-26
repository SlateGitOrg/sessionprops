import { AuthServer, type Flaw, type ServerConfig } from './server.ts';

/**
 * Session security as INVARIANTS, checked by generated operation sequences.
 *
 * An example-based auth test checks that login works, then logout works, in
 * that order, once. Session bugs do not live there. They live in the sequence
 * nobody wrote down: elevate, then replay the pre-elevation identifier; change
 * the password, then use the session from the other device; idle past the
 * timeout, then act.
 *
 * So the properties are stated as things that must hold FOR ALL sequences, and
 * a stateful model generates those sequences. When one breaks, the counter-
 * example is SHRUNK to a minimal reproduction - because a 200-step trace is a
 * curiosity and a 4-step trace is a bug report somebody fixes this afternoon.
 */

export type Op =
  | { kind: 'login'; user: string }
  | { kind: 'elevate'; handleIndex: number }
  | { kind: 'logout'; handleIndex: number }
  | { kind: 'changePassword'; user: string }
  | { kind: 'advance'; ms: number }
  | { kind: 'use'; handleIndex: number };

export interface Invariant {
  readonly id: string;
  readonly asvs: string;
  readonly description: string;
  /** Returns a violation message, or null. */
  check(trace: TraceState): string | null;
}

export interface TraceState {
  readonly server: AuthServer;
  /** Every identifier ever issued, in order. */
  readonly handles: string[];
  /** Identifiers observed before an elevation, per user. */
  readonly preElevation: Map<string, Set<string>>;
  readonly loggedOut: Set<string>;
  readonly passwordChangedAt: Map<string, number>;
  readonly issuedAt: Map<string, number>;
  /** Which user each identifier belongs to. Without this the
   *  password-change invariant flags Bob's session when Alice changes hers. */
  readonly ownerOf: Map<string, string>;
  /** Identifiers that have been exercised since issue. */
  readonly touched: Set<string>;
  /** Identifiers that became elevated through their OWN legitimate elevation.
   *  Excluding these matters: a session elevated an hour ago is not evidence
   *  of a rotation failure in an unrelated elevation later on. */
  readonly elevatedIds: Set<string>;
}

export const INVARIANTS: readonly Invariant[] = [
  {
    id: 'rotation-on-elevation',
    asvs: 'ASVS 3.3.3',
    description:
      'no identifier observed before an elevation is ever accepted as ' +
      'elevated afterwards',
    check(t) {
      for (const [user, ids] of t.preElevation) {
        for (const id of ids) {
          if (t.server.peekElevated(id)) {
            return `pre-elevation id ${id} for ${user} is now elevated`;
          }
        }
      }
      return null;
    },
  },
  {
    id: 'logout-is-server-side',
    asvs: 'ASVS 3.3.1',
    description: 'a logged-out identifier is never valid again',
    check(t) {
      for (const id of t.loggedOut) {
        if (t.server.peekValid(id)) return `logged-out id ${id} still validates`;
      }
      return null;
    },
  },
  {
    id: 'password-change-revokes-all',
    asvs: 'ASVS 3.3.2',
    description: 'changing a password invalidates every existing session',
    check(t) {
      for (const [user, when] of t.passwordChangedAt) {
        for (const id of t.handles) {
          if (t.ownerOf.get(id) !== user) continue;
          const issued = t.issuedAt.get(id) ?? 0;
          if (issued >= when) continue;
          if (t.server.peekValid(id)) {
            return `session ${id} for ${user} survived a password change`;
          }
        }
      }
      return null;
    },
  },
  {
    id: 'idle-timeout',
    asvs: 'ASVS 3.3.4',
    description: 'a session idle beyond the timeout is not accepted',
    check(t) {
      const idle = t.server.config.idleTimeoutMs;
      if (idle === undefined) return null;
      for (const id of t.handles) {
        const seen = t.server.lastSeen(id);
        if (seen === null) continue;
        const idleFor = t.server.clock - seen;
        if (idleFor > idle && t.server.peekValid(id)) {
          return `session ${id} idle for ${idleFor}ms is still valid`;
        }
      }
      return null;
    },
  },
  {
    id: 'absolute-timeout',
    asvs: 'ASVS 3.3.4',
    description: 'a session older than the absolute timeout is not accepted',
    check(t) {
      const abs = t.server.config.absoluteTimeoutMs;
      if (abs === undefined) return null;
      for (const id of t.handles) {
        const issued = t.issuedAt.get(id) ?? 0;
        if (t.server.clock - issued > abs && t.server.peekValid(id)) {
          return `session ${id} outlived the absolute timeout`;
        }
      }
      return null;
    },
  },
  {
    id: 'concurrent-session-limit',
    asvs: 'ASVS 3.3.5',
    description: 'a user never holds more live sessions than the configured cap',
    check(t) {
      const cap = t.server.config.maxConcurrentSessions;
      if (cap === undefined) return null;
      const users = new Set<string>();
      for (const id of t.handles) users.add(id);
      for (const user of ['alice', 'bob']) {
        const n = t.server.liveSessionsFor(user);
        if (n > cap) return `${user} holds ${n} live sessions, cap is ${cap}`;
      }
      return null;
    },
  },
  {
    id: 'unpredictable-identifiers',
    asvs: 'ASVS 3.2.2',
    description: 'session identifiers are not guessable from another one',
    check(t) {
      const ids = t.server.knownIds();
      if (ids.length < 2) return null;
      const sequential = ids.every((id, i) => id === `sess-${i + 1}`);
      return sequential ? 'session ids are sequential and trivially guessable' : null;
    },
  },
];

function freshState(config: ServerConfig): TraceState {
  return {
    server: new AuthServer(config),
    handles: [],
    preElevation: new Map(),
    loggedOut: new Set(),
    passwordChangedAt: new Map(),
    issuedAt: new Map(),
    ownerOf: new Map(),
    touched: new Set(),
    elevatedIds: new Set(),
  };
}

export interface Violation {
  readonly invariant: string;
  readonly asvs: string;
  readonly message: string;
  readonly trace: readonly Op[];
}

export function runTrace(config: ServerConfig, ops: readonly Op[]): Violation | null {
  const t = freshState(config);

  for (const op of ops) {
    switch (op.kind) {
      case 'login': {
        const id = t.server.login(op.user);
        t.handles.push(id);
        t.issuedAt.set(id, t.server.clock);
        t.ownerOf.set(id, op.user);
        break;
      }
      case 'elevate': {
        const id = t.handles[op.handleIndex % Math.max(1, t.handles.length)];
        if (!id) break;
        const user = t.ownerOf.get(id) ?? 'alice';
        // Every identifier for THIS user that exists right now is, by
        // definition, one an attacker could already be holding.
        const before = t.preElevation.get(user) ?? new Set<string>();
        for (const h of t.handles) {
          if (t.ownerOf.get(h) !== user) continue;
          if (t.elevatedIds.has(h)) continue;
          before.add(h);
        }
        t.preElevation.set(user, before);

        const next = t.server.elevate(id);
        if (next) {
          t.handles.push(next);
          t.issuedAt.set(next, t.server.clock);
          t.ownerOf.set(next, user);
          t.elevatedIds.add(next);
          // Only a GENUINELY new identifier is post-elevation evidence. If the
          // server handed back the same id, that is not a rotation - it is the
          // violation itself, and removing it here would delete the evidence.
          if (next !== id) before.delete(next);
        }
        break;
      }
      case 'logout': {
        const id = t.handles[op.handleIndex % Math.max(1, t.handles.length)];
        if (!id) break;
        t.server.logout(id);
        t.loggedOut.add(id);
        break;
      }
      case 'changePassword': {
        t.server.changePassword(op.user);
        t.passwordChangedAt.set(op.user, t.server.clock);
        break;
      }
      case 'advance':
        t.server.advance(op.ms);
        break;
      case 'use': {
        const id = t.handles[op.handleIndex % Math.max(1, t.handles.length)];
        if (id) {
          if (t.server.isValid(id)) t.touched.add(id);
        }
        break;
      }
    }

    for (const inv of INVARIANTS) {
      const message = inv.check(t);
      if (message) {
        return { invariant: inv.id, asvs: inv.asvs, message, trace: [...ops] };
      }
    }
  }
  return null;
}

// --- generation and shrinking ----------------------------------------------

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let x = Math.imul(a ^ (a >>> 15), 1 | a);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

export function generateTrace(rnd: () => number, length: number): Op[] {
  const users = ['alice', 'bob'];
  const ops: Op[] = [{ kind: 'login', user: 'alice' }];
  for (let i = 1; i < length; i++) {
    const r = rnd();
    const user = users[Math.floor(rnd() * users.length)]!;
    const idx = Math.floor(rnd() * 6);
    if (r < 0.22) ops.push({ kind: 'login', user });
    else if (r < 0.42) ops.push({ kind: 'elevate', handleIndex: idx });
    else if (r < 0.57) ops.push({ kind: 'logout', handleIndex: idx });
    else if (r < 0.70) ops.push({ kind: 'changePassword', user });
    else if (r < 0.85) {
      ops.push({ kind: 'advance', ms: Math.floor(rnd() * 40) * 60_000 });
    } else ops.push({ kind: 'use', handleIndex: idx });
  }
  return ops;
}

/**
 * Delta-debugging shrink: repeatedly try removing operations, keeping any
 * removal that still reproduces the violation.
 */
export function shrink(config: ServerConfig, ops: readonly Op[]): Op[] {
  let current = [...ops];
  const stillFails = (candidate: Op[]) => {
    const v = runTrace(config, candidate);
    return v !== null;
  };
  if (!stillFails(current)) return current;

  let improved = true;
  while (improved) {
    improved = false;
    for (let i = 0; i < current.length; i++) {
      const candidate = [...current.slice(0, i), ...current.slice(i + 1)];
      if (candidate.length && stillFails(candidate)) {
        current = candidate;
        improved = true;
        break;
      }
    }
  }
  return current;
}

export function search(
  config: ServerConfig, { runs = 400, length = 40, seed = 1 } = {},
): { violation: Violation; minimal: Op[] } | null {
  const rnd = mulberry32(seed);
  for (let i = 0; i < runs; i++) {
    const ops = generateTrace(rnd, length);
    const violation = runTrace(config, ops);
    if (violation) {
      return { violation, minimal: shrink(config, ops) };
    }
  }
  return null;
}

export function flawsDetectable(): readonly Flaw[] {
  return [
    'NO_ROTATION_ON_ELEVATION', 'LOGOUT_CLIENT_SIDE_ONLY',
    'SURVIVES_PASSWORD_CHANGE', 'NO_ABSOLUTE_TIMEOUT',
    'UNLIMITED_CONCURRENT_SESSIONS', 'PREDICTABLE_SESSION_ID',
  ];
}
