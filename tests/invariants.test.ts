import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { AuthServer, HARDENED, VULNERABLE, type Flaw } from '../src/server.ts';
import { search, runTrace, shrink, INVARIANTS } from '../src/properties.ts';

function withOnly(flaw: Flaw) {
  // Timeouts are shortened for the absolute-timeout flaw so a 50-step trace
  // can actually reach them. The property holds for any configured values;
  // an 8-hour window simply is not reachable inside a short generated trace,
  // and a search that cannot reach the bug is not evidence the bug is absent.
  if (flaw === 'NO_ABSOLUTE_TIMEOUT') {
    return {
      ...HARDENED, flaws: new Set<Flaw>([flaw]),
      idleTimeoutMs: 45 * 60_000, absoluteTimeoutMs: 60 * 60_000,
    };
  }
  return { ...HARDENED, flaws: new Set<Flaw>([flaw]) };
}

describe('THE META-TEST: the suite must have power', () => {
  test('it reports NOTHING against a hardened implementation', () => {
    // Without this, a suite that always fails would look like a success.
    const found = search(HARDENED, { runs: 300, length: 40, seed: 7 });
    assert.equal(found, null,
      `false positive on a hardened server: ${found?.violation.message}`);
  });

  test('it finds a violation against the fully vulnerable implementation', () => {
    const found = search(VULNERABLE, { runs: 100, length: 30, seed: 3 });
    assert.ok(found, 'the suite found nothing on a deliberately broken server');
  });

  const detectable: Flaw[] = [
    'NO_ROTATION_ON_ELEVATION', 'LOGOUT_CLIENT_SIDE_ONLY',
    'SURVIVES_PASSWORD_CHANGE', 'NO_ABSOLUTE_TIMEOUT',
    'UNLIMITED_CONCURRENT_SESSIONS', 'PREDICTABLE_SESSION_ID',
  ];
  for (const flaw of detectable) {
    test(`detects ${flaw} in isolation`, () => {
      const found = search(withOnly(flaw), { runs: 400, length: 50, seed: 11 });
      assert.ok(found, `seeded flaw ${flaw} was not detected`);
    });
  }
});

describe('shrinking produces a usable bug report', () => {
  test('a long random trace shrinks to a short reproduction', () => {
    const found = search(withOnly('NO_ROTATION_ON_ELEVATION'),
      { runs: 400, length: 60, seed: 5 });
    assert.ok(found);
    assert.ok(found!.minimal.length < found!.violation.trace.length,
      'shrinking did not reduce the trace');
    assert.ok(found!.minimal.length <= 8,
      `minimal trace is ${found!.minimal.length} steps; a developer needs ~4`);
  });

  test('the shrunk trace still reproduces the violation', () => {
    const config = withOnly('LOGOUT_CLIENT_SIDE_ONLY');
    const found = search(config, { runs: 400, length: 60, seed: 9 });
    assert.ok(found);
    assert.ok(runTrace(config, found!.minimal),
      'the shrunk trace must still fail, or it is not a reproduction');
  });

  test('shrinking a passing trace changes nothing', () => {
    const ops = [{ kind: 'login' as const, user: 'alice' }];
    assert.deepEqual(shrink(HARDENED, ops), ops);
  });

  test('the violation names the ASVS control', () => {
    const found = search(withOnly('SURVIVES_PASSWORD_CHANGE'),
      { runs: 400, length: 40, seed: 2 });
    assert.ok(found);
    assert.match(found!.violation.asvs, /ASVS \d/);
  });
});

describe('the invariants, checked directly', () => {
  test('elevation rotates the identifier on a hardened server', () => {
    const s = new AuthServer(HARDENED);
    const a = s.login('alice');
    const b = s.elevate(a);
    assert.ok(b);
    assert.notEqual(a, b, 'the pre-elevation id must not remain usable');
    assert.equal(s.isValid(a), false);
    assert.equal(s.isElevated(b!), true);
  });

  test('elevation does NOT rotate when the flaw is enabled', () => {
    const s = new AuthServer(withOnly('NO_ROTATION_ON_ELEVATION'));
    const a = s.login('alice');
    assert.equal(s.elevate(a), a);
    assert.equal(s.isElevated(a), true, 'the old id now carries privilege');
  });

  test('logout invalidates server-side', () => {
    const s = new AuthServer(HARDENED);
    const id = s.login('alice');
    s.logout(id);
    assert.equal(s.isValid(id), false);
  });

  test('a password change revokes sessions on every device', () => {
    const s = new AuthServer(HARDENED);
    const phone = s.login('alice');
    const laptop = s.login('alice');
    s.changePassword('alice');
    assert.equal(s.isValid(phone), false);
    assert.equal(s.isValid(laptop), false);
  });

  test('a password change does not affect a different user', () => {
    const s = new AuthServer(HARDENED);
    const alice = s.login('alice');
    const bob = s.login('bob');
    s.changePassword('bob');
    assert.equal(s.isValid(alice), true, 'collateral revocation is its own bug');
    assert.equal(s.isValid(bob), false);
  });

  test('idle timeout expires an untouched session', () => {
    const s = new AuthServer(HARDENED);
    const id = s.login('alice');
    s.advance(16 * 60_000);
    assert.equal(s.isValid(id), false);
  });

  test('activity refreshes the idle window', () => {
    const s = new AuthServer(HARDENED);
    const id = s.login('alice');
    for (let i = 0; i < 10; i++) {
      s.advance(10 * 60_000);
      assert.equal(s.isValid(id), true, 'an active session must not be logged out');
    }
  });

  test('the absolute timeout fires even on an active session', () => {
    const s = new AuthServer(HARDENED);
    const id = s.login('alice');
    for (let i = 0; i < 60; i++) {
      s.advance(10 * 60_000);
      s.isValid(id);
    }
    assert.equal(s.isValid(id), false,
      'an indefinitely refreshed session defeats the point of a timeout');
  });

  test('the concurrent-session cap evicts the oldest', () => {
    const s = new AuthServer(HARDENED);
    const ids = [s.login('alice'), s.login('alice'), s.login('alice')];
    const fourth = s.login('alice');
    assert.equal(s.isValid(ids[0]!), false, 'the oldest should have been evicted');
    assert.equal(s.isValid(fourth), true);
    assert.ok(s.liveSessionsFor('alice') <= 3);
  });

  test('identifiers are not sequential on a hardened server', () => {
    const s = new AuthServer(HARDENED);
    const ids = [s.login('a'), s.login('b'), s.login('c')];
    assert.ok(!ids.every((id, i) => id === `sess-${i + 1}`));
  });

  test('every invariant declares an ASVS reference and a description', () => {
    for (const inv of INVARIANTS) {
      assert.ok(inv.asvs.startsWith('ASVS'), `${inv.id} has no ASVS reference`);
      assert.ok(inv.description.length > 20);
    }
  });
});
