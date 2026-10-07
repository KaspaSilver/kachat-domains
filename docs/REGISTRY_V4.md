# .kachat registry v4 (proposal)

**Status (2026-10-07):** a design for the owner to review. No contract code yet. v3 stays live
on testnet-10 until a v4 genesis replaces it. Nothing is on mainnet.

**Why v4, and why now.** A template can never change, so every fix means a new registry. Mainnet
has no names yet, so a new version now costs no migration. After launch, it would. v4 gathers the
changes worth making before mainnet into **one** more genesis and **one** audit.

## 1. What changes

| # | Change | Why |
|---|---|---|
| 1 | **Fixed price tables baked into the templates.** No price covenant, no authority key, no shards. | No trusted key: nobody can set prices to zero (squatting) or to huge amounts, and a stolen key can't either. It also drops the 8-shard limit on how many registrations can run at once. Owner's decision, 2026-10-07: cheaper prices instead of a key. |
| 2 | **Two tables: registering and renewing.** Short names cost more to register than to keep. | A high first price stops bots from buying every 1–3 letter name at launch. A low renewal means owners of rare names aren't annoyed every year (the "4000 KAS a year" problem). |
| 3 | **90-day grace and a 30-day renewal window** on mainnet (v3: 10 and 10 days). | Missing a renewal by two weeks should not lose a name. Owner's decision, 2026-10-07. |
| 4 | **Migration by snapshot import** (section 3). | A bug after launch can be fixed by a new version that carries every name over, with no trusted key. |
| 5 | *(Optional)* **`takeover`** on the name (section 4). | Claiming an expired name takes 2 transactions instead of 3 (reclaim, commit, register), and no reclaim step or bounty is needed. |
| 6 | *(Owner decides)* **Where the price goes** (section 5). | v3 pays it to miners as a fee. |

Kept from v3: commit-reveal registration, the gap registry (one owner per name by consensus),
trustless list and buy, seller-bound offers and `decline`, `periodMs` (testnet keeps its
10-minute clock), the 2-period cap ahead of the current period, `reclaim` and `release`.

Considered and dropped:
- **An authority key with a time delay.** It still trusts a key. The owner chose fixed prices.
- **A per-person limit on registrations.** The chain can't tell people apart: one person has as
  many keys as they like. The app's one-at-a-time claim sheet is a UX choice, not a limit.
- **Listing and buying only before expiry.** Script can only say "not before", never "only
  before" (the same reason as in v3). The app shows the expiry on every sale tile and warns.

## 2. Prices

Prices are sompi per period, by name length in bytes. They are baked into `KachatGap.register`
(register table) and `KachatName.extend` / `renew` (renew table). Changing them takes a new version
plus a migration, so they must be right at launch.

**Example only. The owner picks the numbers** (KAS per year; v3 mainnet, for comparison, is one
table of 4000 / 2000 / 1000 / 250 / 35):

| Length | Register | Renew |
|---|---|---|
| 1 | 1000 | 50 |
| 2 | 500 | 25 |
| 3 | 200 | 10 |
| 4 | 50 | 5 |
| 5+ | 5 | 2 |

What to weigh:
- **KAS moves.** A fixed KAS price drifts in dollars. A migration can reset prices, but it moves
  every name, so it's a rare, emergency-only step.
- **Extend.** `extend` (adding a period inside the current one) uses the renew table. Otherwise
  someone could register for one period and extend instead of paying the register price for two.
  That's fine as long as the register price is for a single period: registering for 2 periods
  costs register + renew.

## 3. Migration: a new version imports a snapshot of the old one

An old contract can't know the template of a contract written later. A migration is therefore
either a trusted upgrade key, or the **new** version importing a **snapshot** of the old one.
v4 uses the snapshot.

- **The snapshot.**
  - **Contents:** at one chosen block of the old registry, one leaf per name that is active or in
    grace: `blake3(key ‖ owner ‖ periodStart ‖ expiresAt)`.
  - **Root:** the leaves, sorted by key, form a binary Merkle tree. Its root is baked into the
    new gap template, next to `snapshotDeadline` (a time).
  - **Reproducible:** a CLI command, `kachat-names snapshot <block>`, recomputes the root from
    the chain, so anyone can check that the deployer included every name correctly.
- **`import(name, owner, periodStart, expiresAt, proof)`** on the new gap.
  - **What it creates:** the name in the gap, exactly like `register`, with the snapshot's owner
    and dates.
  - **Proof:** a Merkle path that the leaf is under the root.
  - **Not needed:** a commit or a price. The importer funds the bond and the gap deposit, the
    same 2 KAS as a registration.
  - **Who can call it:** anyone. The name always goes to the snapshot owner, so the app can
    import its own names quietly the next time it opens.
- **Registering a snapshot name is blocked until the deadline.**
  - **Why:** without this, someone could register a name in the new registry before its owner
    imports it.
  - **How:** before `snapshotDeadline`, `register` must carry a **non-membership proof**: the two
    neighbouring leaves around the key, each with its path.
  - **After the deadline** (`tx.time >= snapshotDeadline`, which a CLTV can express), `register`
    skips the proof, and an owner who never imported has lost the name.
- **The old registry stays on chain.** Owners can still `release` there to get their old bond
  back. The app and the indexer read only the new registry.
- **What this means for v4.**
  - The import code lives in the *next* version, so for mainnet v4 needs nothing extra: v5 would
    import v4.
  - What v4 should do is **prove the mechanism now**: `import` and the non-membership check in the
    harness, with the cost of a 20-level proof measured against the script size limits.
  - Then a mainnet bug never waits on designing the escape route.
  - Whether v4 ships `import` live, to carry testnet v3 names over, is the owner's call. The
    recommendation is no: testnet names are disposable.

Open question: whether silverc unrolls a fixed-depth Merkle check within the script size and
operation limits. Prototype this first. If a 20-level proof doesn't fit, use a shallower tree with
wider leaves (several names per leaf).

## 4. `takeover` (optional)

A name entry on `KachatName`, allowed once `tx.time >= expiresAt + grace`:
- **Inputs:** input 0 is the name; input 1 is a mature commit for `(name, newOwner, salt)`, the
  same script and sequence lock as `register`.
- **Outputs:**
  - output 0 is the name's continuation, with the new owner, unlisted, `periodStart = now` and
    `expiresAt = now + years·periodMs`, carrying the bond;
  - output 1 pays the **old bond to the old owner**.
- **Fee:** the register price × years.
- **Gaps are untouched:** the name stays in its slot.
- **Risk:** it changes the owner without the owner's signature, so the expiry check, the commit
  binding and the bond payout are the audit's first targets.
- **Without it,** the app already hides the 3-step reclaim (KaChat "Available" tab, 2026-10-07),
  so this is cleanliness, not a fix.

## 5. Where the price goes (owner decides)

| Option | Effect |
|---|---|
| Miner fee (v3) | Simplest. A miner who mines their own registration gets the price back. The owner judged this unlikely: pools don't take part in ecosystems like this. |
| Burn | An output no key can ever spend. Nobody gets it back, but it stays in the UTXO set forever (it's large, so its storage mass is small). |
| Treasury | A P2PK the project controls. That funds the project, but it's another key to protect, and it reads as a fee to the team. |

The current lean is to keep the miner fee unless there's another reason to change it.

## 6. What v4 means for each part

- **Contracts.**
  - `KachatPrice` goes.
  - `KachatGap` gets the register table, the snapshot root and deadline (when importing), and
    `import`.
  - `KachatName` gets the renew table, the new windows and optionally `takeover`.
  - `KachatOffer` is unchanged apart from the new template hashes.
- **Genesis:** a single registry genesis, with no price genesis. As always, a dry run comes first,
  then the owner's "send it".
- **Manifest:** no `priceCovenantId`. The two tables go in `params`, and the template hashes are
  pinned in the app per deployment, as now.
- **iOS app:**
  - prices come from the manifest again, with no shard read and no "price changed" stage;
  - new windows: `expiresSoonMs` follows `renewWindowMs`;
  - the `import` driver;
  - optionally a `takeover` path in the claim driver.
- **Indexer:**
  - remove the price shards (`/names/prices` serves the manifest tables);
  - add the `import` and `takeover` events.
- **Android, Desktop and the extension:** they haven't ported v3 yet (XP-001), so v4 becomes their
  target directly.
- **Testnet:** v3 names are left behind, as v1's and v2's were.

## 7. Owner decisions before any code

1. The two price tables (section 2).
2. Where the price goes: miner fee, burn or treasury (section 5).
3. `takeover`: yes or no (section 4).
4. Ship `import` live in v4 for testnet v3 names: yes or no (recommended no; the harness
   prototype either way).
5. Testnet clock values for the new windows (proposal: `graceMs` 30 min, `renewWindowMs` 20 min
   on the 10-minute period).

## 8. Order of work

1. Owner decisions (section 7).
2. Prototype the Merkle proof in silverc and the harness. Section 3 depends on it.
3. Contracts, harness scenarios and mutation pairs.
4. CLI: genesis, snapshot, test vectors.
5. Testnet dry run, then "send it".
6. iOS, then the indexer handoff, then Android, Desktop and the extension.
7. An external audit of every entry.
8. Mainnet.
