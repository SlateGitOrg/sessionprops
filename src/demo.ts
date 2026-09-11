/**
 * The 60-second artefact: a shrunk reproduction. Run: `npm run demo`
 */
import { HARDENED, type Flaw } from './server.ts';
import { search, type Op } from './properties.ts';

function withOnly(flaw: Flaw) {
  if (flaw === 'NO_ABSOLUTE_TIMEOUT') {
    return {
      ...HARDENED, flaws: new Set<Flaw>([flaw]),
      idleTimeoutMs: 45 * 60_000, absoluteTimeoutMs: 60 * 60_000,
    };
  }
  return { ...HARDENED, flaws: new Set<Flaw>([flaw]) };
}

const show = (op: Op): string => {
  switch (op.kind) {
    case 'login': return `login(${op.user})`;
    case 'elevate': return `elevate(session#${op.handleIndex})`;
    case 'logout': return `logout(session#${op.handleIndex})`;
    case 'changePassword': return `changePassword(${op.user})`;
    case 'advance': return `advance(${op.ms / 60_000}min)`;
    case 'use': return `use(session#${op.handleIndex})`;
  }
};

console.log('\n  SESSIONPROPS - session security as invariants');
console.log('  ' + '-'.repeat(70));

const hardened = search(HARDENED, { runs: 300, length: 40, seed: 7 });
console.log('\n  Against a hardened server: ' +
            `${hardened ? 'VIOLATION FOUND' : '300 traces, 12,000 operations, ' +
            'no violations'}`);
console.log('  (a suite that cannot report a clean run is not a suite)\n');

const FLAWS: Flaw[] = [
  'NO_ROTATION_ON_ELEVATION', 'LOGOUT_CLIENT_SIDE_ONLY',
  'SURVIVES_PASSWORD_CHANGE', 'NO_ABSOLUTE_TIMEOUT',
  'UNLIMITED_CONCURRENT_SESSIONS', 'PREDICTABLE_SESSION_ID',
];

console.log(`  ${'seeded flaw'.padEnd(32)}${'detected'.padEnd(11)}` +
            `${'trace'.padEnd(8)}shrunk`);
console.log('  ' + '-'.repeat(70));
for (const flaw of FLAWS) {
  const found = search(withOnly(flaw), { runs: 400, length: 50, seed: 11 });
  const detected = found ? 'yes' : 'NO';
  const len = found ? String(found.violation.trace.length) : '-';
  const min = found ? String(found.minimal.length) : '-';
  console.log(`  ${flaw.padEnd(32)}${detected.padEnd(11)}${len.padEnd(8)}${min}`);
}

const rot = search(withOnly('NO_ROTATION_ON_ELEVATION'),
  { runs: 400, length: 60, seed: 5 })!;

console.log('\n  The bug report a developer receives:');
console.log('  ' + '-'.repeat(70));
console.log(`    invariant: ${rot.violation.invariant}  (${rot.violation.asvs})`);
console.log(`    ${rot.violation.message}`);
console.log(`\n    found in a ${rot.violation.trace.length}-step random trace, ` +
            `shrunk to ${rot.minimal.length} steps:\n`);
rot.minimal.forEach((op, i) => console.log(`      ${i + 1}. ${show(op)}`));
console.log('\n  That shrink is the difference between a curiosity and a ticket.\n');
