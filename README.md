# kachat-names

Phase 1 of the `.kachat` name service (design: `KaChat/KACHAT_NAMES.md`): the Kaspa covenant
contracts in Silverscript, and a Rust harness that runs every entry through rusty-kaspa's own
consensus transaction validator. **Local only - nothing here has been deployed to any network.**

```
contracts/      KachatGap.sil  KachatName.sil  KachatOffer.sil
params/         testnet10.json  mainnet.json       (same numbers; registryCovenantId set after genesis)
artifacts/      <net>/KachatName.json KachatGap.json build-info.json   (scripts/build.sh output)
scripts/        build.sh build.py mutation-check.sh
harness/        Rust crate: src/lib.rs (kit), src/scenarios.rs (valid txs), tests/*.rs
tools/          disasm.py (+ opcode table of rusty-kaspa a41a333)
```

## Contracts

All three are `pragma silverscript ^0.1.0`, compiled with silverc **v1.0.0, commit
`3ed973335b59269293564805cc2c58a14595ec03`**. Gaps and names share one **registry covenant id**
(KIP-20) minted by the genesis transaction; offers are plain P2SH. Template references go one way
only - gap -> name template hash, offer -> registry id + name template hash, name -> nothing - so
there is no template-hash cycle.

### KachatGap - the registry interval `(lo, hi)`
State (66 B): `lo byte[32]`, `hi byte[32]`. Genesis state `(00..00, ff..ff)`.

| Entry | Seat | Checks |
|---|---|---|
| `register(byte[] name, byte[32] ownerKey, byte[32] salt, int now, int years, byte[] namePrefix, byte[] nameSuffix)` | input 0, the only registry input | 3 registry outputs at exactly 0, 1, 2, all authorized by the gap; name is `a-z0-9-`, 1..32 bytes, no hyphen first/last (256-entry lookup table); `lo < blake3(name) < hi` (unsigned big-endian, 5-step binary search for the first differing byte); `ownerKey != 0`; input 1's script is exactly `P2SH(0x20 c 0x75 0x20 ownerKey 0xac)`, `c = blake3("kachat-commit:v1" ‖ name ‖ ownerKey ‖ salt)`; input 1's relative sequence lock is `>= tCommit` with the disable bit clear; `1 <= years <= maxYears`; `tx.time >= now` (timestamp CLTV); out 0 = gap `(lo, key)` = gapValue, out 1 = gap `(key, hi)` = gapValue, out 2 = name `(key, padded name, ownerKey, 0, now + years·365 d)` = bond, validated against the **baked** name template hash; `Σin − Σout >= price(len) · years` over at most 8 inputs and 8 outputs |
| `merge()` | input 0 of the exit | exactly 3 registry inputs at 0, 1, 2 and 1 registry output at 0, authorized by the gap; seat 1 read with `readInputStateWithTemplate` (baked name template) and `name.key == hi`; seat 2 read as a gap and `succ.lo == hi`; out 0 = gap `(lo, succ.hi)` = gapValue |
| `absorbed()` | input 2 of the exit | same exit shape; authorizes nothing |

### KachatName - one UTXO per name, value = bond
State (117 B): `key byte[32]`, `name byte[32]` (zero padded), `owner byte[32]` (x-only), `price int`
(0 = unlisted), `expiresAt int` (unix ms).

| Entry | Who | Checks |
|---|---|---|
| `transfer(byte[32] newOwner, sig)` | owner | continuation: new owner, price 0, expiry unchanged |
| `list(int price, sig)` | owner | `0 <= price <= 2.9e18`; continuation with the price |
| `buy(byte[32] newOwner)` | anyone | listed; output **continuation + 1** is `P2PK(owner)` with value `>= price`; continuation: new owner, price 0, expiry unchanged |
| `renew(int years)` | anyone | `1 <= years <= maxYears`; `expiresAt <= 1e17`; continuation identical except `expiresAt += years·365 d` (from the old expiry, even when lapsed); `Σin − Σout >= renewPrice(len) · years` (≤ 8 in / 8 out) |
| `release(sig)` | owner | seat 1 of the exit, 3 registry inputs at 0..2, 1 registry output at 0, authorizes nothing |
| `reclaim()` | anyone | same exit seat; `tx.time >= expiresAt + graceMs` (timestamp CLTV); **output 1** is `P2PK(owner)` with value `>= bond` |

Every non-exit entry: exactly one registry input (this name), exactly one registry output, which
it authorizes, with value **exactly** `bond`. Every signature must be SIGHASH_ALL (`0x01`).

### KachatOffer - KAS locked for one name (plain P2SH)
State (75 B), spliced by the app: `key byte[32]`, `buyer byte[32]`, `refundAfter int` (DAA score).
Baked per network: `registryCovId`, name template hash + prefix/suffix lengths, `maxFee`.

| Entry | Who | Checks |
|---|---|---|
| `accept(int nameIdx)` | the name's owner (transfer sig) or a matched `buy` | offer is input `nameIdx + 1`; input `nameIdx` carries the registry id and is a KachatName (template + P2SH) with `key`; it authorizes exactly one output, which is the name with `owner = buyer`, price 0, same name and expiry; output **name continuation + 1** is `P2PK(current owner)` with value `>= offer value − maxFee` |
| `withdraw(sig)` | buyer | SIGHASH_ALL signature by `buyer` |
| `refund()` | anyone | `tx.daa >= refundAfter` (DAA CLTV); **exactly 1 input and 1 output**, output 0 = `P2PK(buyer)` with value `>= offer value − maxFee` |

## Transaction shapes the app must build

All are version-1 transactions with output covenant bindings and per-input compute budgets.

| Operation | Inputs | Outputs | Lock time / sequences |
|---|---|---|---|
| commit | owner funding | `P2SH(0x20 c 0x75 0x20 ownerKey 0xac)` (0.2 KAS) + change | - |
| register | 0 gap (`register`), 1 commit (owner sig + redeem), 2.. funding (≤ 8 inputs total) | 0 gap (lo,key), 1 gap (key,hi), 2 name, 3.. change (≤ 8 outputs) | `lockTime = now` (ms); input 1 `sequence = tCommit` (600); input 0 `sequence = 0`. Valid once the block DAA ≥ commitDaa + 600 **and** the block's past median time > now (median time lags the wall clock by ~2.2 min, so use `now = wall clock − 3 min` to be final at once) |
| transfer / list / buy / renew | 0 name, 1.. funding | 0 continuation, [1 payout for buy], change | - |
| release | 0 gap (lo,key) `merge`, 1 name `release`, 2 gap (key,hi) `absorbed` | 0 merged gap, change | - |
| reclaim | same, name runs `reclaim` | 0 merged gap, **1 bond to the last owner**, 2 caller's bounty (gapValue − fee) | `lockTime = expiresAt + graceMs`, name input `sequence = 0` |
| offer accept | 0 name `transfer(buyer)`, 1 offer `accept(0)` | 0 continuation (buyer), 1 payout to owner | - |
| offer refund | 0 offer `refund` (alone) | 0 to the buyer | `lockTime = refundAfter` (DAA), `sequence = 0` |

## Params (`params/*.json`, identical on testnet-10 and mainnet)

| Param | Value | Baked into |
|---|---|---|
| `bond` | 1 KAS | name, gap |
| `gapValue` | 1 KAS | gap |
| `tCommit` | 600 DAA | gap |
| `maxYears` | 2 (build refuses > 31) | gap, name |
| `graceMs` | 864,000,000 (10 days) | name |
| `prices` (per year, by length 1/2/3/4/5+) | 4000 / 2000 / 1000 / 250 / 35 KAS | gap |
| `renewPrices` (separate params) | 4000 / 2000 / 1000 / 250 / 35 KAS | name |
| `offerMaxFee` | 0.02 KAS | offer |
| year | 365 days = 31,536,000,000 ms (constant) | gap, name |
| loop bounds | 8 inputs, 8 outputs, values ≤ 1e18 sompi each (constants) | gap, name |

Because testnet and mainnet use the same numbers, `KachatName` and `KachatGap` are byte-identical
on both networks; only `KachatOffer` differs (it bakes the registry id, so `build.sh` builds it
once `registryCovenantId` is filled in after the genesis transaction).

## Sizes (bytes) and template hashes

| Template | Size | Prefix / state / suffix | Template hash |
|---|---|---|---|
| KachatGap | 3965 | 1 / 66 / 3898 | `a182d59bbf460baff5ec99ca850b990d45fbafee4dfbe9a3a7a1afe21e7ba8ca` |
| KachatName | 2002 | 1 / 117 / 1884 | `42eddf19e7ea2bc78b9aa97937f21be0505ebcf964653508f74e179dd6c7e39d` |
| KachatOffer | 897 | 1 / 75 / 821 | depends on the registry id |
| commit redeem | 68 | fixed | - |

Dispatch tags: gap `register 8667af5e`, `merge 63d25bc2`, `absorbed dab76355`; name `transfer 794dca54`,
`list 674a8ea4`, `buy 76a02eb9`, `renew b706ac38`, `release 388ad0b4`, `reclaim f56af4df`; offer
`accept 9d4043b4`, `withdraw 80344ff1`, `refund 777f5b11` (pinned by
`tests/genesis.rs::dispatch_tags_are_stable`).

## Cost per operation

From `cargo test --test report -- --nocapture` (masses from rusty-kaspa's `MassCalculator`; min fee
= 100 sompi/gram × max(compute, normalized transient), the post-Toccata relay floor). Budget =
smallest covering compute budget (1 unit = 10,000 script units; 9,999 free per input), measured by
the engine; P2PK funding inputs need 10.

| Operation | Size B | Compute g | Transient g (norm.) | Storage g | Min network fee | Compute budget (script units) |
|---|---|---|---|---|---|---|
| register 5 chars, 1 y | 6712 | 10782 | 13424 | 124323 | 0.0134 KAS | gap.register 6 (65106), commit 10 |
| register 32 chars, 2 y | 6739 | 10909 | 13478 | 126247 | 0.0135 KAS | gap.register 7 (73880), commit 10 |
| register worst case (32 chars, 2 y, 8 in, 8 out) | 7547 | 18157 | 15094 | 154342 | 0.0182 KAS | gap.register 7 (74124) |
| transfer | 2516 | 5346 | 5032 | 5101 | 0.0054 KAS | name.transfer 11 (113393) |
| list | 2488 | 5318 | 4976 | 5101 | 0.0053 KAS | name.list 11 (113355) |
| buy | 2502 | 4692 | 5004 | 39104 | 0.0050 KAS | name.buy 1 (13207) |
| renew 1 y | 2418 | 4248 | 4836 | 42658 | 0.0048 KAS | name.renew 1 (13298) |
| renew worst case (2 y, 8 in, 8 out) | 3450 | 13440 | 6900 | 94774 | 0.0134 KAS | name.renew 1 (13622) |
| release (exit) | 10417 | 12447 | 20834 | 0 | 0.0208 KAS | merge 3 (38758), release 10 (104695), absorbed 0 (8214) |
| reclaim (exit) | 10403 | 11793 | 20806 | 0 | 0.0208 KAS | merge 3 (38746), reclaim 0 (4522), absorbed 0 (8214) |
| offer accept | 3356 | 5486 | 6712 | 39736 | 0.0067 KAS | transfer 11, offer.accept 3 (36403) |
| offer withdraw | 1171 | 2531 | 2342 | 0 | 0.0025 KAS | offer.withdraw 10 (102135) |
| offer refund | 1105 | 1465 | 2210 | 0 | 0.0022 KAS | offer.refund 0 (2053) |

Register and renew additionally leave `price × years` as miner fee (35 KAS … 8,000 KAS). Each
signature check costs 100,000 script units (10 budget units), which dominates every signed entry.
Recommended fixed budgets for the app: register 7, merge 3, absorbed 0, transfer/list 11, buy 1,
renew 1, release 10, reclaim 0, accept 3, withdraw 10, refund 0, commit/P2PK 10.

## Build and test

```bash
./scripts/build.sh                 # needs ~/silverscript at 3ed9733 (refuses anything else); writes artifacts/
cd harness && cargo test           # 120 tests, ~3 s after the first build
cargo test --test report -- --nocapture   # sizes and the cost table above
../scripts/mutation-check.sh       # delete each security check in turn, show which tests catch it
```

The harness depends on the same rusty-kaspa revision silverscript v1.0.0 pins (`a41a333`) and on
silverscript itself at `3ed9733` (git dependencies, `Cargo.lock` copied from silverscript). It
loads `artifacts/testnet10/*.json` (and `tests/genesis.rs` checks they equal a fresh compile of
`contracts/*.sil`), splices state by hand exactly as the app will, mints a real genesis (registry
id from `covenant_id(outpoint, [gap])`), compiles the offer for that id, signs with SIGHASH_ALL,
picks each input's compute budget by measuring it in the engine, and validates with
`TransactionValidator::validate_tx_in_isolation` + `validate_populated_transaction_and_get_fee`
(Full flags: covenant bindings and genesis ids, sequence locks, every input script under its
committed budget). The header-context finality rule (`check_tx_is_finalized`, crate-private
upstream) is reproduced verbatim in `src/lib.rs`. Attack tests assert both that the specific
input's script fails (and not merely on its budget) and that the whole transaction is rejected.

| File | Tests | Covers |
|---|---|---|
| `register.rs` | 34 | every price tier at exactly the price and one sompi short; digits/hyphens; 1..2 years; years 0/−1/3; expiry not matching years; no commit; commit for another owner / name / salt; front-runner swapping the owner; immature commit (consensus sequence lock), short relative lock, disabled lock bit, high sequence bits; `now` in the future / not past the block median time / DAA-domain lock time / finalized gap input / absurd `now`; key outside the gap, on either boundary, and a 96-case differential test of the byte order; bad characters, leading/trailing hyphen, length 0 and 33; extra registry output; moved outputs; wrong values; wrong name state; forged name template; zero owner; gap not at input 0; two registry inputs; 9 inputs / 9 outputs (8 pass) |
| `name.rs` | 32 | transfer (keeps expiry, clears listing, works after expiry); wrong sig; non-ALL sighash types; malformed signatures; zero owner; changed key/name/expiry; bond pinned; name vanishing / splitting / leaving the registry; batching; list/delist; bad prices; buy (overpay ok); unlisted; too little; wrong script ×4; wrong payout index; two buys sharing one payment; tampered continuation; renew 1 and 2 years; exact tier price per year and one short; years 0/−1/3; renew from a lapsed expiry; renew changing anything else; tier from the stored name; expiry cap; two renewals sharing one fee; 9 inputs |
| `exit.rs` | 23 | release; release while listed/expired; wrong sig / sighash; non-adjacent predecessor / successor; forged seat-2 gap (no id / another id); forged seat-1 name; gap at seat 1; releasing one name across another name's seam; wrong merged gap / value; extra registry output; reordered seats; fourth registry input; a name at seat 2 under every entry; reclaim pays the bond; grace is 10 days; before grace (script: `expiresAt+grace−1`, at expiry; consensus: median time not past); DAA-domain lock; finalized input; bond to the caller / short / wrong index / missing; overpaying ok; renewed name not reclaimable at the old time |
| `offer.rs` | 19 | accept; accept on an expired name keeps the expiry; maxFee boundary; paying less / to a stranger / to the buyer / at another index; different name; name not going to the buyer; name outside the registry; two offers on one name; offer away from its name; bad indices; listed name + offer matched by a third party; withdraw; withdraw by owner/stranger/non-ALL; refund after refundAfter; before (script and consensus) / finalized input; refund to a stranger / short / with a skim output; two refunds sharing or burning; refund used as a buy payout |
| `genesis.rs` | 10 | genesis validity; nobody can mint the registry id later; non-registry input cannot rebind; artifacts == fresh compile; testnet == mainnet templates; state does not move the template; hand codecs == ABI codecs (and decode); state spans; commit script spend; dispatch tags |
| `lifecycle.rs` | 1 | genesis → register alice, bob → list, buy, renew (gift), offer + accept → release bob → reclaim alice → the registry is the genesis gap again → alice registers anew; every tx spends the previous txs' real outputs |
| `report.rs` | 1 | the cost table; standardness (P2SH sig-op scan ≤ 15, standard outputs) and mass headroom |

`scripts/mutation-check.sh` deletes or weakens 37 individual checks; every one is caught by at
least one test except five that are redundant by construction (each labelled with what covers it:
the register output count, the explicit input bound, each half of the name's one-input/one-output
pair - removing both is caught - and the offer's key check).

## Deviations from KACHAT_NAMES.md (need a doc update)

1. **Commit maturity is a sequence lock, not `tx.daa >= OpTxInputDaaScore(1) + T_COMMIT`.** That
   DAA-domain CLTV does enforce maturity on its own (CLTV forces `lockTime >= commitDaa + T` and
   consensus finality forces `blockDaa > lockTime`), but yearly names need `tx.time >= now` in the
   same transaction, a transaction has one lock time, and CLTV refuses a domain mismatch. So the gap
   instead requires input 1's relative sequence lock `>= tCommit` with bit 63 clear, which
   consensus `check_sequence_lock` (UTXO context, every input) enforces as
   `blockDaa >= commitDaa + lock`. Tested with the real validator: valid at exactly
   `commitDaa + 600`, rejected one DAA earlier, and short / disabled / high-bit sequences refused
   by the script.
2. `renew` refuses to extend an expiry already beyond 1e17 ms (~3 million years) so the sum can
   never overflow a script integer; the design says "no cap". Unreachable in practice.
3. `GRACE` = 10 days (per the later instruction), not the 30 days in the doc.

## OPEN ISSUES

1. **Not audited.** silverc v1.0.0 is three weeks old; the compiled bytecode was reviewed only
   through these tests and spot disassembly (`tools/disasm.py`). An independent review of the
   `.sil` sources and of the bytecode is still needed before mainnet.
2. **Seat 2 of the exit is trusted by lineage** (`readInputState(2)` without a template check, as in
   dotk): it carries the registry id and a name refuses every entry at seat 2, so it is a gap. This
   holds only if the genesis covenant group contains nothing but the genesis gap - the manifest
   must pin and the app/indexer must verify the genesis binding.
3. **Miner-fee pricing relies on one registry input per transaction.** register, renew, transfer,
   list and buy require exactly one registry input, so two fee-paying operations can never share
   one fee. A miner including its own registrations/renewals gets the price back (accepted).
4. **Bounded loops**: register and renew transactions are limited to 8 inputs and 8 outputs and
   values ≤ 1e18 sompi; the wallet must consolidate funding first (4000 KAS × 2 years = 8,000 KAS).
5. **Key validity**: script cannot check that an owner key is on the curve. `ownerKey`/`newOwner`
   of zero are refused; any other invalid key bricks owner entries until the name lapses, after
   which `reclaim` frees the key (bond goes to the unspendable key). The app must validate keys.
6. **Storage mass**: each 1-KAS covenant output costs ~40k grams of KIP-9 storage mass, so a
   registration is ~125k-155k grams (a quarter of a block's 500k storage budget). Not charged in
   the relay fee today, but block-space heavy; a larger `gapValue`/`bond` reduces it
   proportionally.
7. **Listing + offer matching**: anyone may pair `buy(newOwner = buyer)` with the buyer's offer.
   The seller gets `max(price, offer − maxFee)`, the buyer gets the name for what they offered, and
   the matcher can keep at most `maxFee` (0.02 KAS). The app should warn a buyer whose offer exceeds
   a new listing (tested in `offer.rs`).
8. **Offers follow the key, not the owner**: after a reclaim and re-registration, the new owner can
   accept old offers for that name. Offers are refundable by anyone after `refundAfter`.
9. **Time**: `now` and the reclaim/expiry use the block's past median time (lags wall clock
   ~2.2 min). Registering with `now = wall clock − 3 min` loses those minutes of the paid year.
10. **Mempool policy not exercised**: relay of 35-8,000 KAS fees, the post-Toccata standard-mass
    relaxation window, and mempool handling of the time-locked transactions must be confirmed on
    TN10 (phase 2). The harness checks consensus validity, the P2SH sig-op scan and output
    standardness only.
11. **Compiler quirks met**: the pragma must be `^0.1.0`; hex literals over 8 bytes need a cast
    (`byte[32](0x…)`); `OpTxInputSeq` returns raw `byte[8]` (low 32 bits are widened with a `0x00`
    byte before comparing); `checkSig` on a malformed key/signature is UB in Silverscript terms -
    the emitted `OpCheckSig` fails closed in the engine (tested), and no check depends on it.
12. **Offer artifacts per network** exist only after genesis (`registryCovenantId` in params); the
    harness compiles the offer for its own test registry id.
