# sessionprops

> Session security as invariants, checked by property-based testing that generates the attack sequence nobody thought of.

`COMPACT` · **Cybersecurity** · Intermediate · ~4-5 days · Fintech - consumer banking login

**Primary language:** TypeScript
**Tags:** `authentication`, `property-testing`, `owasp`, `sessions`, `security-testing`

---

## The problem

Session bugs are invisible in normal use and catastrophic in exploitation: a session ID that survives privilege elevation, a logout that does not invalidate server-side, a token still valid after a password change. Example-based tests check the three sequences a developer thought of, in the order they thought of them.

## ⭐ The differentiator

Encodes session security as **invariants and uses stateful property-based testing to generate adversarial operation sequences** - 'for all sequences of {login, elevate, rotate, logout, password-change}, no pre-elevation session identifier is ever accepted post-elevation'. A generic auth test asserts that login works and logout works, in that order, once. This one searches the space and shrinks any violation to a minimal reproduction.

This is the sentence to lead with when someone asks you to walk through the
project. Everything else in this repo exists to make it true and to prove it.

## Data

Self-contained. A deliberately-flawed reference auth server ships in-repo with a **documented catalogue of seeded session flaws**, so the suite's detection power is demonstrated rather than assumed.

> No paid API key is required to run or demo this project. Where a paid
> service would add value it is wired as an optional enhancement behind an
> interface with an offline mock as the default implementation.

## Stack

- TypeScript
- fast-check (stateful model-based testing)
- Express reference server + Redis session store
- Vitest

## Core capabilities

- Invariant library: fixation resistance, rotation on privilege change, global invalidation, absolute and idle timeout, concurrent-session limits
- Stateful property-based model generating operation sequences against a live server
- Shrinking to a minimal reproducing sequence for any violation
- Pluggable adapter so the suite can be pointed at any application
- Findings report mapping each violation to the relevant OWASP ASVS control

## Repository layout

```
src/invariants/
src/model/
reference-server/         # deliberately flawed, documented
test/
report/
```

## Build plan

1. Write the invariants in English first. If you cannot state one precisely, you cannot test it.
2. Seed the reference server's flaws and record them.
3. Stateful model + shrinking. Shrinking is what makes the output usable by a developer.
4. Adapter interface last, so the suite outlives this one server.

## Testing strategy

The suite *is* the deliverable, so it needs a meta-test: assert it detects **every** seeded flaw, and assert it reports **zero** findings against a hardened reference implementation. Without the second half, a suite that always fails would look like a success.

Tests assert **correctness**, not merely that the code runs. A green suite on
this repo is a claim about behaviour under adversarial conditions; treat any
test that would pass against a deliberately broken implementation as a bug in
the test.

## Quality & safety layer

Runs only against a target you configure explicitly. The reference server is local and deliberately flawed; the README states that pointing this at systems you do not own is unauthorised testing.

## Measurable outcome

> A 200-step random sequence finds a session-fixation flaw and shrinks it to a four-step reproduction a developer can fix the same afternoon.

State it in these terms — business units, not technical ones — in your CV
bullet and in the first thirty seconds of describing the project.

## Interview questions this project answers

- **What is session fixation and how do you prevent it?**
- **Why rotate a session identifier on privilege change?**
- **How would you test an invariant you cannot enumerate?**

## What this deliberately is *not*

- Not a scanner. It is a test suite you run against your own application in CI.


## Run it now

```bash
npm test        # runs the suite; no install step needed
npm run demo    # the 60-second artefact
```

Requires Node 22.6+ (24 recommended). TypeScript runs natively via
type stripping - there is no build step and no `node_modules`.

## Getting started

```bash
git clone <your-fork-url> sessionprops
cd sessionprops
npm install
npm run reference-server &
npm run test:invariants       # finds every seeded flaw
npm run report
```

Docker is supported but optional — every path above works on a plain
Windows/macOS/Linux laptop without a cloud account.

## Definition of done

- [ ] The differentiator above is implemented, and a test proves it
- [ ] The measurable outcome is produced by a command anyone can run
- [ ] `README` explains the one decision a generic version gets wrong
- [ ] CI runs the full suite on every push and is green on `main`
- [ ] A recruiter can see the headline artefact in under 60 seconds

## Licence

MIT — see [LICENSE](LICENSE).
