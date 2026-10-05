# .kachat registry v3

**Status (2026-10-05):** on the `v3` branch. Done:
- the contracts, the engine-backed harness and the mutation check;
- the CLI (`tools/kachat-names-cli`): both geneses, prices, decline, shard reads, and the
  test vectors for the app.

Still to do:
- the app;
- the indexer handoff;
- the testnet geneses (a dry run, then the owner's "send it");
- an audit before mainnet.

v3 replaces v2. Testnet gets a new registry and v2's test names are left behind, as v1's were.

## 1. What changes, and why

| # | Change | Why |
|---|---|---|
| 1 | **Adjustable prices.** A price record (K shards) that registering, extending and renewing read from the chain, and that the authority key can change **instantly, up or down**. There is **one table** for registering and renewing. | In v2 prices are template constants, so they can never change. The owner's decision, 2026-10-05. |
| 2 | **`periodMs`** replaces the hard-coded year. Mainnet uses 1 year; testnet runs a **10-minute clock**. | Expiry, grace, renewal and price changes can then be tested in minutes. |
| 3 | **Offers bound to the seller.** An offer records the owner it was made to. Accepting needs that seller's signature, and the name must still be theirs. | A change of owner ends every earlier offer on chain. It also closes v2's quirk where anyone could match a listing with an offer and keep up to `maxFee`. |
| 4 | **`decline`.** The seller sends an offer back to the buyer at any time. | Owners can turn offers down. The app returns all open offers when the owner transfers, sells or releases. |

Considered and dropped:
- **"Accept only before expiry".** Script can only say "not before" (CLTV); it can't say "only
  before". The app refuses expired offers, anyone can refund them, and with change 3 only the
  seller can accept.
- **A template check on the exit's seat 2.** A template can't contain its own hash. Seat 2 is safe
  anyway: only gaps and names carry the registry id, and a name refuses seat 2, provided the
  manifest's genesis binding is verified. The app and the indexer already verify it.

## 2. The price record: `KachatPrice`

- **Its own covenant.** The price covenant is minted by the **price genesis**, before the
  registry. Its id is `priceCovenantId`, and the gap and name bake it.
  - It is never the registry's covenant, so the registry keeps its "exactly one registry input"
    rule: two paid operations can't share one fee.
- **State** (87 B): `shard int`, `authority byte[32]`, `p1..p5 int`. Prices are sompi per
  period, for names of 1, 2, 3, 4 and 5 or more bytes.
- **Baked parameters:** `shards` (K, 1..8) and `priceValue` (the exact value of every shard).
- **The genesis** creates shards 0..K-1 at outputs 0..K-1, with the params' prices and the
  chosen authority.

| Entry | Who | Rules |
|---|---|---|
| `use()` | anyone | The only price input in its transaction. It continues to exactly one output with the same state and exactly `priceValue`, so it adds nothing to the fee. A gap or a name reads it in the same transaction. |
| `update(newAuthority, n1..n5, sig)` | the authority, on shard 0 | **SIGHASH_ALL.** All K shards are inputs, in shard order. Every shard continues once, in order. Shard 0 writes **every** continuation as `(j, newAuthority, n1..n5)` at `priceValue`. Each price must be `0 ≤ p ≤ 1e17` sompi, and `newAuthority ≠ 0`. A price change passes the current key; a key rotation passes the current prices. |
| `follow()` | shards 1..K-1 | The same shape checks. Shard 0 can only be present in a K-input change through `update`, so every change is signed and consistent. |

Reading a price: the gap's `register(…, priceIdx)` and the name's `extend(years, priceIdx)` /
`renew(years, priceIdx)` call `readInputStateWithTemplate(priceIdx)`. They first check that input's
covenant id is `priceCovId`; that check is what stops a look-alike P2SH from setting a free price.
The fee rule then uses the shard's tier.

**K = 8:** a register, extend or renew takes any shard, so up to 8 can run at the same moment
without conflicting. Someone spending shards in a loop costs themselves fees, and only makes
others retry with another shard.

## 3. Input and output layouts (what the CLI and app build)

| Operation | Inputs | Outputs |
|---|---|---|
| price genesis | 0 deployer funding | 0..K-1 shards (price covenant), change |
| registry genesis | 0 deployer funding | 0 gap `(00..00, ff..ff)` (registry covenant), change |
| register | 0 gap `register(…, priceIdx=2)`, 1 commit, **2 price shard `use`**, 3.. funding | 0 gap `(lo,key)`, 1 gap `(key,hi)`, 2 name, **3 shard continuation**, change |
| extend / renew | 0 name `extend\|renew(years, priceIdx=1)`, **1 price shard `use`**, 2.. funding | 0 name continuation, **1 shard continuation**, change |
| price change | 0 shard 0 `update`, 1..K-1 shards `follow`, K.. authority funding | 0..K-1 shard continuations, change |
| offer accept | 0 name `transfer(buyer, ownerSig)`, 1 offer `accept(0, sellerSig)` | 0 name to the buyer, 1 payout to the owner |
| offer decline | 0 offer `decline(sellerSig)` (alone) | 0 to the buyer |
| unchanged | transfer, list, buy, release, reclaim, withdraw, refund (as in v2) | |

The offer state is 108 B: `key`, `buyer`, `seller`, `refundAfter`. The marker payload is
`kchat:1:offer:<key>:<buyer>:<seller>:<refundAfter>`; the app and indexer contract update
carries this format. Name and gap states are unchanged from v2: 126 B and 66 B.

## 4. Parameters

| | testnet-10 | mainnet |
|---|---|---|
| `periodMs` | 600,000 (10 min) | 31,536,000,000 (1 year) |
| `maxYears` (periods held at most) | 2 (20 min) | 2 |
| `renewWindowMs` | 600,000 (10 min before expiry) | 864,000,000 (10 days) |
| `graceMs` | 600,000 (10 min after expiry) | 864,000,000 (10 days) |
| genesis prices, 1/2/3/4/5+ chars per period | 40 / 20 / 10 / 2.5 / 0.35 TKAS (1/100 of mainnet) | 4,000 / 2,000 / 1,000 / 250 / 35 KAS |
| `priceShards` × `priceValue` | 8 × 1 KAS | 8 × 1 KAS |
| `bond`, `gapValue`, commit, `tCommit`, `offerMaxFee` | 1, 1, 0.2 KAS, 600 DAA, 0.02 KAS | same |

`build.py` enforces:
- `0 < renewWindowMs ≤ periodMs`: a longer window would let `renew` run again right after itself;
- `maxYears × periodMs < 1e12`;
- `1 ≤ priceShards ≤ 8` and `priceValue ≥ 0.2 KAS`;
- every price in `[0, 1e17]`.

## 5. Costs

From `tests/report.rs` on the testnet params. "Min fee" is the relay floor; the price is on top.

| Operation | Size | Min fee |
|---|---|---|
| register | ~11.1 KB | ~0.022 KAS (v2: ~0.016) |
| extend / renew | ~6.3 KB | ~0.013 KAS |
| offer accept | ~5.7 KB | ~0.011 KAS |
| offer decline | ~1.4 KB | ~0.003 KAS (out of the offer, under `maxFee`) |
| price change (8 shards) | ~15.1 KB | ~0.030 KAS |

Template sizes: price 1,691 B, gap 4,498 B, name 4,058 B, offer 1,114 B.

## 6. Trust

- **The authority key is v3's only admin power.** It can set any price, at once, and can rotate
  itself. Keep it offline (KasSigner). The CLI signs through it, and the key never sits on a
  networked machine.
- **If the key is stolen,** the thief can set renewals to the cap. Owners whose renewal is due
  couldn't afford it until the owner lowers prices again, if they still hold the key.
- **If the key is lost,** prices are frozen at their last values.
- Everything else stays as trustless as v2: ownership, trading, offers and expiry are covenant
  rules, and nobody can seize, freeze or move a name.

## 7. Work left, in order

1. **Mutation check** (`scripts/mutation-check.sh`, 90 mutations): every surviving mutation is
   either explained as redundant or covered by a new test.
2. **CLI: done.**
   - **New commands:** `authority-keygen`, `price-genesis`, `genesis` (the registry; its dry run
     previews both geneses), `prices`, `set-prices <5 TKAS> | --times N/D`, `set-authority`,
     `decline-offer`, and `--backdate-minutes`.
   - **Paid operations:** register, extend and renew read a random live shard.
   - **Offers** are made to the name's owner.
   - **The manifest** carries `priceGenesis` and verifies both covenant-id bindings.
   - **The walker** follows the shards.
   - **Rehearsal:** `e2e-plan` simulates the whole testnet rehearsal: 25 transactions, about
     69 TKAS needed.
   - **Test vectors:** `kachat-names-vectors` writes the app's vectors: 38 transactions plus the
     codecs, with recommended compute budgets updated for v3.
   - **Mainnet:** the authority signs on KasSigner. This CLI is testnet-only and uses a local
     authority key.
3. **App:**
   - builder port and vectors;
   - shard pick and retry;
   - prices read from the record;
   - Decline, plus the automatic decline on transfer, sale or release;
   - the 7-day offer cap;
   - the manifest switch.
4. **Indexer handoff:**
   - follow the price covenant and serve `/names/prices`;
   - the offer `seller` and decline events.
5. **Testnet:** price genesis and registry genesis, each a dry run first, then the owner's "send it".
6. **Audit,** then the mainnet geneses only on the owner's go-ahead.
