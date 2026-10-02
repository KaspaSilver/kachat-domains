# kachat-names

Phase 1 of the `.kachat` name service (design: `KaChat/KACHAT_NAMES.md`): the Kaspa covenant
contracts in Silverscript, and a Rust harness that runs every entry through rusty-kaspa's own
consensus transaction validator. Phase 2 (`kachat-domains` repo, this checkout): the testnet-10
deployment CLI, see [Testnet-10 deployment (phase 2)](#testnet-10-deployment-phase-2).
**Registry v2** (these contracts: `periodStart`, `extend`, a renewal window) is **not deployed**. The
live testnet-10 registry `9444187f…7a51` (genesis 2026-10-01, `params/testnet10.json`
`registryCovenantId`, `manifests/kachat-names-testnet-10.json`) runs the **v1** contracts of commit
`6167c1f`; v2 needs a new genesis (see [Registry v2](#registry-v2)). Nothing is on mainnet.

```
contracts/      KachatGap.sil  KachatName.sil  KachatOffer.sil
params/         testnet10.json  mainnet.json       (same numbers; registryCovenantId set after genesis)
artifacts/      <net>/KachatName.json KachatGap.json build-info.json   (scripts/build.sh output)
scripts/        build.sh build.py mutation-check.sh
harness/        Rust crate: src/lib.rs (kit), src/scenarios.rs (valid txs), tests/*.rs
tools/          disasm.py (+ opcode table of rusty-kaspa a41a333)
tools/kachat-names-cli/   phase 2: the `kachat-names` testnet-10 CLI (Rust, same rusty-kaspa rev)
manifests/      kachat-names-testnet-10.json once a real genesis exists (dryrun/ is scratch, gitignored)
.secrets/       deployer key + salted commits (gitignored, mode 600)    state/  local registry cache (gitignored)
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
| `register(byte[] name, byte[32] ownerKey, byte[32] salt, int now, int years, byte[] namePrefix, byte[] nameSuffix)` | input 0, the only registry input | 3 registry outputs at exactly 0, 1, 2, all authorized by the gap; name is `a-z0-9-`, 1..32 bytes, no hyphen first/last (256-entry lookup table); `lo < blake3(name) < hi` (unsigned big-endian, 5-step binary search for the first differing byte); `ownerKey != 0`; input 1's script is exactly `P2SH(0x20 c 0x75 0x20 ownerKey 0xac)`, `c = blake3("kachat-commit:v1" ‖ name ‖ ownerKey ‖ salt)`; input 1's relative sequence lock is `>= tCommit` with the disable bit clear; `1 <= years <= maxYears`; `tx.time >= now` (timestamp CLTV); out 0 = gap `(lo, key)` = gapValue, out 1 = gap `(key, hi)` = gapValue, out 2 = name `(key, padded name, ownerKey, price 0, periodStart = now, expiresAt = now + years·365 d)` = bond, validated against the **baked** name template hash; `Σin − Σout >= price(len) · years` over at most 8 inputs and 8 outputs |
| `merge()` | input 0 of the exit | exactly 3 registry inputs at 0, 1, 2 and 1 registry output at 0, authorized by the gap; seat 1 read with `readInputStateWithTemplate` (baked name template) and `name.key == hi`; seat 2 read as a gap and `succ.lo == hi`; out 0 = gap `(lo, succ.hi)` = gapValue |
| `absorbed()` | input 2 of the exit | same exit shape; authorizes nothing |

### KachatName - one UTXO per name, value = bond
State (126 B): `key byte[32]`, `name byte[32]` (zero padded), `owner byte[32]` (x-only), `price int`
(0 = unlisted), `periodStart int` (unix ms, start of the current paid period), `expiresAt int`
(unix ms). Spliced as `0x20 key 0x20 name 0x20 owner 0x08 price 0x08 periodStart 0x08 expiresAt`
(ints are 8-byte script numbers, `num8`): price at bytes 100..108, periodStart 109..117,
expiresAt 118..126.

A name is never paid more than `maxYears` (2) past the start of its current period: `extend` adds
years to the period any time, `renew` starts the next period once its window is open
(KACHAT_NAMES.md 4.1).

| Entry | Who | Checks |
|---|---|---|
| `transfer(byte[32] newOwner, sig)` | owner | continuation: new owner, price 0, periodStart and expiry unchanged |
| `list(int price, sig)` | owner | `0 <= price <= 2.9e18`; continuation with the price, periodStart and expiry unchanged |
| `buy(byte[32] newOwner)` | anyone | listed; output **continuation + 1** is `P2PK(owner)` with value `>= price`; continuation: new owner, price 0, periodStart and expiry unchanged |
| `extend(int years)` | anyone (gifts) | any time, no lock; `1 <= years <= maxYears`; `expiresAt <= 1e17`; `expiresAt + years·365 d <= periodStart + maxYears·365 d`; `Σin − Σout >= renewPrice(len) · years` (≤ 8 in / 8 out); continuation identical except `expiresAt += years·365 d` (periodStart kept) |
| `renew(int years)` | anyone (gifts) | `1 <= years <= maxYears`; `expiresAt <= 1e17`; `tx.time >= expiresAt − renewWindowMs` (timestamp CLTV: the window opens 10 days before expiry and stays open in grace and after lapse, until a reclaim); `Σin − Σout >= renewPrice(len) · years` (≤ 8 in / 8 out); continuation identical except `periodStart = expiresAt` (the old expiry) and `expiresAt += years·365 d`, so no time is lost or gained |
| `release(sig)` | owner | seat 1 of the exit, 3 registry inputs at 0..2, 1 registry output at 0, authorizes nothing |
| `reclaim()` | anyone | same exit seat; `tx.time >= expiresAt + graceMs` (timestamp CLTV); **output 1** is `P2PK(owner)` with value `>= bond` |

Every non-exit entry: exactly one registry input (this name), exactly one registry output, which
it authorizes, with value **exactly** `bond`. Every signature must be SIGHASH_ALL (`0x01`).

### KachatOffer - KAS locked for one name (plain P2SH)
State (75 B), spliced by the app: `key byte[32]`, `buyer byte[32]`, `refundAfter int` (DAA score).
Baked per network: `registryCovId`, name template hash + prefix/suffix lengths, `maxFee`.

| Entry | Who | Checks |
|---|---|---|
| `accept(int nameIdx)` | the name's owner (transfer sig) or a matched `buy` | offer is input `nameIdx + 1`; input `nameIdx` carries the registry id and is a KachatName (template + P2SH) with `key`; it authorizes exactly one output, which is the name with `owner = buyer`, price 0, same name, periodStart and expiry; output **name continuation + 1** is `P2PK(current owner)` with value `>= offer value − maxFee` |
| `withdraw(sig)` | buyer | SIGHASH_ALL signature by `buyer` |
| `refund()` | anyone | `tx.daa >= refundAfter` (DAA CLTV); **exactly 1 input and 1 output**, output 0 = `P2PK(buyer)` with value `>= offer value − maxFee` |

## Transaction shapes the app must build

All are version-1 transactions with output covenant bindings and per-input compute budgets.

| Operation | Inputs | Outputs | Lock time / sequences |
|---|---|---|---|
| commit | owner funding | `P2SH(0x20 c 0x75 0x20 ownerKey 0xac)` (0.2 KAS) + change | - |
| register | 0 gap (`register`), 1 commit (owner sig + redeem), 2.. funding (≤ 8 inputs total) | 0 gap (lo,key), 1 gap (key,hi), 2 name, 3.. change (≤ 8 outputs) | `lockTime = now` (ms); input 1 `sequence = tCommit` (600); input 0 `sequence = 0`. Valid once the block DAA ≥ commitDaa + 600 **and** the block's past median time > now (median time lags the wall clock by ~2.2 min, so use `now = wall clock − 3 min` to be final at once) |
| transfer / list / buy / extend | 0 name, 1.. funding | 0 continuation, [1 payout for buy], change | - (lock time 0, sequences 0) |
| renew | 0 name, 1.. funding | 0 continuation, change | `lockTime = max(min(wall − 3 min, medianTime − 1 s), expiresAt − renewWindowMs)` (unix ms), **every input `sequence = 0`** (not `u64::MAX`: the CLTV needs a non-final input). Any lock time `L` with `expiresAt − renewWindowMs <= L < medianTime` is valid; the transaction is final only once the block's past median time passes `L`, so before the window opens there is no valid renew (the mempool keeps no future-dated transactions): refuse it and show when it opens |
| release | 0 gap (lo,key) `merge`, 1 name `release`, 2 gap (key,hi) `absorbed` | 0 merged gap, change | - |
| reclaim | same, name runs `reclaim` | 0 merged gap, **1 bond to the last owner**, 2 caller's bounty (gapValue − fee) | `lockTime = expiresAt + graceMs`, name input `sequence = 0` |
| offer accept | 0 name `transfer(buyer)`, 1 offer `accept(0)` | 0 continuation (buyer), 1 payout to owner | - |
| offer refund | 0 offer `refund` (alone) | 0 to the buyer | `lockTime = refundAfter` (DAA), `sequence = 0` |

**Payloads** (the contracts never read them; counted in mass and fee like any byte). The
transaction that creates an offer carries `kchat:1:offer:<keyHex>:<buyerXonlyHex>:<refundAfterDaa>`
(UTF-8, refundAfter in decimal): offers have no covenant id and a P2SH hides the state, so this
marker is how an indexer finds them; it is trusted only if
`P2SH(offerPrefix ‖ offerState(key, buyer, refundAfter) ‖ offerSuffix)` is one of the outputs.
register, extend, renew, transfer, list, buy, release, reclaim and offer accept carry the informational
`kchat:1:name:<op>:<name>` (op = the entry name, `accept` for an accepted offer; e.g.
`kchat:1:name:extend:alice`). The commit,
genesis, offer withdraw and offer refund carry none; a commit must not, or the salted commit
would reveal the name.

## Params (`params/*.json`, identical on testnet-10 and mainnet)

| Param | Value | Baked into |
|---|---|---|
| `bond` | 1 KAS | name, gap |
| `gapValue` | 1 KAS | gap |
| `tCommit` | 600 DAA | gap |
| `maxYears` | 2 (build refuses > 31) | gap, name |
| `graceMs` | 864,000,000 (10 days) | name |
| `renewWindowMs` | 864,000,000 (10 days): renew is valid from `expiresAt − renewWindowMs` (build refuses ≤ 0 or ≥ a year) | name |
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
| KachatGap | 4014 | 1 / 66 / 3947 | `182c463cf59f6d175f75339e4efc75d2065e8e7bb8dcc515e4769d3ff805dd46` |
| KachatName | 3108 | 1 / 126 / 2981 | `e8ded947687947b565e10cbf6e6fec60e5c90cf992c7bce2298e6dce8db29d16` |
| KachatOffer | 948 | 1 / 75 / 872 | depends on the registry id |
| commit redeem | 68 | fixed | - |

v1 (the live testnet registry): gap 3965 B `a182d59b…a8ca`, name 2002 B `42eddf19…e39d`, offer 897 B.
The name grew by 1,106 B: `extend` is a second entry that sums the miner fee, and Silverscript
inlines `minerFee()` (16 bounded, value-capped iterations) at each call site. Every name spend
reveals the redeem, so each name transaction is ~1.1 kB larger and needs ~6.7k more script units
than in v1.

Dispatch tags: gap `register 8667af5e`, `merge 63d25bc2`, `absorbed dab76355`; name `transfer 794dca54`,
`list 674a8ea4`, `buy 76a02eb9`, `extend 2ce7cceb` (new), `renew b706ac38` (same signature
`renew(int)`, new meaning), `release 388ad0b4`, `reclaim f56af4df`; offer `accept 9d4043b4`,
`withdraw 80344ff1`, `refund 777f5b11` (pinned by `tests/genesis.rs::dispatch_tags_are_stable`).

## Cost per operation

From `cargo test --test report -- --nocapture` (masses from rusty-kaspa's `MassCalculator`; min fee
= 100 sompi/gram × max(compute, normalized transient), the post-Toccata relay floor). Budget =
smallest covering compute budget (1 unit = 10,000 script units; 9,999 free per input), measured by
the engine; P2PK funding inputs need 10.

| Operation | Size B | Compute g | Transient g (norm.) | Storage g | Min network fee | Compute budget (script units) |
|---|---|---|---|---|---|---|
| register 5 chars, 1 y | 7858 | 12028 | 15716 | 124323 | 0.0157 KAS | gap.register 7 (76685), commit 10 |
| register 32 chars, 2 y | 7885 | 12155 | 15770 | 126247 | 0.0158 KAS | gap.register 8 (85459), commit 10 |
| register worst case (32 chars, 2 y, 8 in, 8 out) | 8693 | 19403 | 17386 | 154342 | 0.0194 KAS | gap.register 8 (85703) |
| transfer | 3622 | 6552 | 7244 | 5101 | 0.0072 KAS | name.transfer 12 (120116) |
| list | 3594 | 6524 | 7188 | 5101 | 0.0072 KAS | name.list 12 (120078) |
| buy | 3608 | 5798 | 7216 | 39104 | 0.0072 KAS | name.buy 1 (19930) |
| extend 1 y | 3524 | 5454 | 7048 | 42658 | 0.0070 KAS | name.extend 2 (20054) |
| extend worst case (1 y, 8 in, 8 out) | 4556 | 14646 | 9112 | 86620 | 0.0146 KAS | name.extend 2 (20378) |
| renew 1 y or 2 y (in the window) | 3524 | 5454 | 7048 | 42658 / 43795 | 0.0070 KAS | name.renew 2 (20047) |
| renew worst case (2 y, 8 in, 8 out) | 4556 | 14646 | 9112 | 94774 | 0.0146 KAS | name.renew 2 (20371) |
| release (exit) | 11621 | 13751 | 23242 | 0 | 0.0232 KAS | merge 4 (46786), release 10 (106911), absorbed 0 (8312) |
| reclaim (exit) | 11607 | 13097 | 23214 | 0 | 0.0232 KAS | merge 4 (46774), reclaim 0 (6738), absorbed 0 (8312) |
| offer accept | 4513 | 6943 | 9026 | 39736 | 0.0090 KAS | transfer 12, offer.accept 5 (55332) |
| offer withdraw | 1222 | 2582 | 2444 | 0 | 0.0026 KAS | offer.withdraw 10 (102237) |
| offer refund | 1156 | 1516 | 2312 | 0 | 0.0023 KAS | offer.refund 0 (2155) |

Register, extend and renew additionally leave `price × years` as miner fee (35 KAS … 8,000 KAS;
extend and renew use the `renewPrices` tiers: a 5+-character name costs 35 KAS per year either
way). Each signature check costs 100,000 script units (10 budget units), which dominates every
signed entry. Recommended fixed budgets for the app (v2; v1 in brackets): register 8 [7], merge 4
[3], absorbed 0, transfer/list 12 [11], buy 2 [1] (measured 19,930 units, 69 under budget 1's
19,999: 2 leaves room), extend 2 (new), renew 2 [1], release 10, reclaim 0, accept 5 [3], withdraw
10, refund 0, commit/P2PK 10.

## Build and test

```bash
./scripts/build.sh                 # needs ~/silverscript at 3ed9733 (refuses anything else); writes artifacts/
cd harness && cargo test           # 138 tests, ~4 s after the first build
cargo test --test report -- --nocapture   # sizes and the cost table above
../scripts/mutation-check.sh       # delete each security check in turn, show which tests catch it
cd ../tools/kachat-names-cli && cargo test   # phase-2 CLI: 28 tests (see "Testnet-10 deployment")
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
| `register.rs` | 35 | every price tier at exactly the price and one sompi short; digits/hyphens; 1..2 years; 2 years one sompi short of 2 years' price; years 0/−1/3; expiry not matching years; periodStart = now (any other refused); no commit; commit for another owner / name / salt; front-runner swapping the owner; immature commit (consensus sequence lock), short relative lock, disabled lock bit, high sequence bits; `now` in the future / not past the block median time / DAA-domain lock time / finalized gap input / absurd `now`; key outside the gap, on either boundary, and a 96-case differential test of the byte order; bad characters, leading/trailing hyphen, length 0 and 33; extra registry output; moved outputs; wrong values; wrong name state; forged name template; zero owner; gap not at input 0; two registry inputs; 9 inputs / 9 outputs (8 pass) |
| `name.rs` | 47 | transfer (keeps expiry, clears listing, works after expiry); wrong sig; non-ALL sighash types; malformed signatures; zero owner; changed key/name/expiry; bond pinned; name vanishing / splitting / leaving the registry; batching; list/delist; bad prices; buy (overpay ok); unlisted; too little; wrong script ×4; wrong payout index; two buys sharing one payment; tampered continuation; transfer/list/buy keep periodStart (a moved one refused by each); **extend** 1 → 2 years; past periodStart + 2 y (2 from a 1-year name, any from a 2-year name, 1 ms over, twice); any time incl. grace and lapse; 0/−1/3 years; tier price per year exactly, one sompi short, 2 years one short, tier from the stored name; continuation changing owner/price/periodStart/expiry; expiry cap; **renew** at the window boundary (1 and 2 y); before it (1 ms, a day, long before, no lock time; not final before the median time passes); DAA-domain lock time; finalized name input; in grace and after lapse; new period from the old expiry (lapsed too); keeping the old periodStart or counting from now refused; renew then renew again refused until the next window; renew(1) + extend(1) ok, renew(2) + extend refused; exact tier price and one short; 0/−1/3 years; changing anything else; tier from the stored name; expiry cap; gifts (a non-owner pays both); two renewals / an extend and a renew sharing one fee; 9 inputs |
| `exit.rs` | 23 | release; release while listed/expired; wrong sig / sighash; non-adjacent predecessor / successor; forged seat-2 gap (no id / another id); forged seat-1 name; gap at seat 1; releasing one name across another name's seam; wrong merged gap / value; extra registry output; reordered seats; fourth registry input; a name at seat 2 under every entry; reclaim pays the bond; grace is 10 days; before grace (script: `expiresAt+grace−1`, at expiry; consensus: median time not past); DAA-domain lock; finalized input; bond to the caller / short / wrong index / missing; overpaying ok; renewed name not reclaimable at the old time |
| `offer.rs` | 21 | accept; accept on an expired name keeps the expiry; accept keeps periodStart (a forged one refused by the offer and the name); a matched listing (buy + accept) with a moved periodStart refused by the offer; maxFee boundary; paying less / to a stranger / to the buyer / at another index; different name; name not going to the buyer; name outside the registry; two offers on one name; offer away from its name; bad indices; listed name + offer matched by a third party; withdraw; withdraw by owner/stranger/non-ALL; refund after refundAfter; before (script and consensus) / finalized input; refund to a stranger / short / with a skim output; two refunds sharing or burning; refund used as a buy payout |
| `genesis.rs` | 10 | genesis validity; nobody can mint the registry id later; non-registry input cannot rebind; artifacts == fresh compile; testnet == mainnet templates; state does not move the template; hand codecs == ABI codecs (and decode; 126-byte layout with periodStart at 109..117); state spans; commit script spend; dispatch tags (extend included) |
| `lifecycle.rs` | 1 | genesis → register alice (2 y), bob (1 y) → list, buy alice → a gifter extends bob to 2 y → offer + accept → release bob → alice: extend refused (paid 2 y ahead), renewed in her window (new period from the old expiry), a second renew refused, the new period extended → reclaim alice → the registry is the genesis gap again → alice registers anew; every tx spends the previous txs' real outputs |
| `report.rs` | 1 | the cost table; standardness (P2SH sig-op scan ≤ 15, standard outputs) and mass headroom |

`scripts/mutation-check.sh` deletes or weakens 56 individual checks (v2 adds every extend
and renew check, the renewal window and an off-by-one-ms window, extend's period cap and an
off-by-one-ms cap, and periodStart in register, extend, renew, transfer, list, buy and offer
accept); every one is caught by at least one test except five that are redundant by construction
(each labelled with what covers it: the register output count, the explicit input bound, each half
of the name's one-input/one-output pair - removing both is caught - and the offer's key check).
The v2 run also found two v1 test gaps, now closed: "gap: price × years" had survived since
maxYears became 2 (the test paid for 3 years, which max years already refuses), and extend's
"price × years" needed a test with room for 2 years.

## Testnet-10 deployment (phase 2)

`tools/kachat-names-cli` builds the `kachat-names` binary: the operations of the
[transaction shapes](#transaction-shapes-the-app-must-build) table against a real testnet-10
node. It is a second crate on the harness's rusty-kaspa revision (`a41a333`, rusty-kaspa 2.0.1;
testnet-10 nodes seen on 2026-10-01 run 2.0.1 and 2.1.0) and reuses the harness kit, so every
transaction it prints was built, signed and validated by exactly the code the 138 contract tests
use.

**Safety rules built into the tool**

- **Testnet-10 only.** There is no mainnet mode: the params file, address prefix (`kaspatest:`),
  consensus params (`TESTNET_PARAMS`) and network name are constants. Every command that talks to
  a node first requires it to report network `testnet-10`, be synced and keep a UTXO index;
  `--submit` re-checks the network right before sending. A transfer target must be a
  `kaspatest:` Schnorr (P2PK) address.
- **Dry run by default.** Every spending command builds the transaction, validates it locally
  (`TransactionValidator`: isolation + header finality at the virtual's median time / DAA +
  UTXO context with Full flags, at the node's virtual DAA score), checks mempool standardness
  (P2SH sig-op scan, standard outputs), and prints a summary: inputs with outpoints, values,
  sequences and compute budgets (and script units used), outputs with covenant bindings and
  addresses, fee split into price and network fee, size and compute / transient / storage
  mass, lock time and its domain, and the payload. Only `--submit` broadcasts, and only a transaction that passed
  those checks. Read-only RPCs used: GetServerInfo, GetInfo, GetBlockDagInfo, GetFeeEstimate,
  GetUtxosByAddresses, GetVirtualChainFromBlockV2. The only write is SubmitTransaction.
- **One key.** `keygen` creates a fresh secp256k1 Schnorr key at
  `.secrets/testnet10-deployer.key` (directory 700, file 600, refuses to overwrite, refuses unless
  `.secrets/` is in `.gitignore`) and prints only its `kaspatest:` address. `load` refuses a key
  file readable by others. The deployer is the owner, buyer and payer in every command; the tool
  reads no other key or seed. Salts of pending commits are kept in `.secrets/commits.json` (600).

### Setup

```bash
brew install protobuf                     # protoc, needed by rusty-kaspa's gRPC crates
cd tools/kachat-names-cli && cargo build --release && cd ../..
alias kachat-names=$PWD/tools/kachat-names-cli/target/release/kachat-names
kachat-names keygen                       # once: prints the deployer's kaspatest: address
kachat-names node-info                    # read-only: GetInfo, network, DAA, median time, deployer UTXOs
```

The binary finds the checkout from the current directory (or `--repo`, or
`KACHAT_DOMAINS_ROOT`); nothing in it is an absolute path. Node: `--node grpc://host:16210`, or
discovery through the testnet-10 DNS seeders of rusty-kaspa's `TESTNET_PARAMS`
(`seeder1-tn.kaspad.net`, `dnsseeder-kaspa-testnet.x-con.at`, `n-testnet-10.kaspa.ws`; the
`seeder{1,2}-testnet.kaspad.net` names are tried too but do not resolve today): the first seeded
peer that answers on 16210 and is synced, UTXO-indexed and on testnet-10.

**Deployer:** `kaspatest:qz5xdn6e0clxsyey4k7pzhkrfjnhg6qneac0d0lyl8pk7tya6vyysf8pt3r8m`.
**Fund it with 300 TKAS** (the v2 plan below needs at least 268 TKAS; it spends 213.16 TKAS and
leaves about 86.84 TKAS). `kachat-names balance` shows the UTXOs.

### Registry state without an indexer

A gap or name UTXO sits at the P2SH address of `prefix ‖ state ‖ suffix`, so its address commits
to its whole state: a UTXO at that address carrying the registry covenant id *is* that state,
live. The CLI keeps the decoded states in `state/registry-testnet-10.json` (gitignored),
starting from the manifest's genesis gap, and moves them forward with one decoder
(`Registry::apply`): it reads each registry input's signature script (dispatch tag, arguments,
revealed redeem = the tracked state), predicts every registry output the entry must create, and
accepts the transaction only if those predictions match the bound outputs one to one (anything
unexplained is refused and the state is left untouched). Offers are found through their
`kchat:1:offer:` payload marker, accepted only when an output really is that offer. Two feeds
use it:

- every transaction this CLI submits (applied right after the node accepts it), and
- `kachat-names scan`: walks the selected chain from the checkpoint (the sink seen just before
  the genesis was submitted) with GetVirtualChainFromBlockV2 (High verbosity: accepted
  transactions with inputs, signature scripts and covenant bindings), 20 confirmations deep,
  for everyone else's registry transactions.

`kachat-names status` decodes all gaps, names (owner, listing, expiry phase), tracked offers and
open commits and checks each against GetUtxosByAddresses (live, with the registry covenant id);
it also checks the gaps and names tile the key space. Before spending, every command fetches the
live UTXO of each registry input the same way, so a stale state fails loudly instead of building
on a spent outpoint. Limits: the scan start must still be inside the node's pruning window (scan
at least daily), testnet-10 currently carries ~200 transactions per chain block (a minute of
chain scans in ~3.5 s), and a reorg of an already-scanned block is only reported (`scan
--from-genesis` rebuilds). The indexer replaces all of this later
(`KaChat/KACHAT_NAMES_INDEXER.md` B3/B4 describe the same decoding).

### Genesis, manifest and the offer artifact

```bash
kachat-names genesis                      # dry run against the node (needs the funded deployer)
kachat-names genesis --assume-utxo 300    # dry run before funding: a synthetic 300-TKAS UTXO
kachat-names genesis --submit             # the real one
```

The genesis spends one deployer UTXO; output 0 is the lone gap `(00..00, ff..ff)` bound to
`covenant_id(that outpoint, [(0, gap)])`, output 1 is change, nothing else is authorized
(exactly `genesis_spec`, the shape the harness's genesis tests use). With `--submit` it writes
`manifests/kachat-names-testnet-10.json` (params, compiler, every contract's template hash,
prefix and suffix bytes, dispatch tags and artifact file hashes, the offer's for this registry id, the genesis outpoint, txid and
authorized output, `registryCovenantId`, the scan checkpoint), fills `registryCovenantId` in
`params/testnet10.json` (the only edit to params, by a real genesis only), and initializes the
state. Then build the offer artifact and commit:

```bash
./scripts/build.sh      # now also writes artifacts/testnet10/KachatOffer.json for the registry id
git add params/testnet10.json artifacts/testnet10 manifests/kachat-names-testnet-10.json
```

Every later command verifies the manifest before trusting it: the registry id must equal
`covenant_id(genesis outpoint, [genesis gap])` recomputed from the templates, and the gap, name
and offer template hashes, prefixes and suffixes must match; if `artifacts/testnet10/KachatOffer.json` exists it must be
byte-identical to the in-process compile for that id. The dry run writes the would-be manifest
and `params-testnet10.json` to `manifests/dryrun/` (gitignored) and, when the pinned `silverc` is
present (`$SILVERSCRIPT_DIR`, default `~/silverscript`), runs
`python3 scripts/build.py <silverc> manifests/dryrun/params-testnet10.json manifests/dryrun/artifacts`
and checks the offer it builds equals the in-process compile. Done on 2026-10-01 with
`--assume-utxo 300`: hypothetical registry id `19ef6996…261c5b`, offer 897 B, template hash
`402095d3…16ac`, identical (and the rebuilt gap and name artifacts are byte-identical to the
committed ones). A dry run is allowed next to a deployed registry (it previews a new one and
writes only `manifests/dryrun/`); `--submit` still refuses while a manifest exists or params carry
a `registryCovenantId`. Registry v2, 2026-10-02, `--assume-utxo 300` next to the live v1
registry: hypothetical registry id `3ff8bf5d…c2d4`, offer 948 B, template hash `cbbece64…d98e`,
identical; the would-be manifest records `renewWindowMs` with the other params.

### The end-to-end run

`kachat-names e2e-plan` prints this list; `--simulate` also prints every transaction. The plan
is run in-process first through the same builders with synthetic UTXOs (each transaction
validated by the consensus validator and spending the previous transactions' outputs), which is
where the budget comes from: 20 transactions, prices 210 TKAS (miner fee: three registrations,
one extend, one renew), network fees 0.159 TKAS, 3 TKAS left locked in the registry (two gaps and
alpha-tn's bond), 213.16 TKAS spent in total; the peak need (the 50-TKAS self-purchase after the
registrations, the extend and the renewal) makes 268 TKAS the least funding that completes it,
re-checked by a second simulation. A 4-character
name (250 TKAS a year, plus 2 TKAS bond and gap) does not fit next to the plan, so none is
included. Names are 8 characters (the 5+ tier, 35 TKAS a year). Each command waits until its
transaction's output 0 shows up in the UTXO index before returning, so the next one sees it.

| # | Command (`--submit` each) | What it proves on testnet-10 |
|---|---|---|
| 1 | `genesis`, then `./scripts/build.sh` + commit (v2: first archive the v1 manifest, see [Registry v2](#registry-v2)) | the registry id is minted by one ordinary UTXO; the genesis covenant group holds only the gap; the manifest binding |
| 2-4 | `commit alpha-tn`, `commit bravo-tn`, `commit lapse-tn` | salted commits: only `P2SH(commitment, owner)` is public |
| 5 | wait 600 DAA (~1 min); `status` shows "mature" | the commit sequence lock (consensus `check_sequence_lock`) in the mempool |
| 6 | `register alpha-tn --years 1` | a 35-TKAS miner fee relays and mines; the time-locked register (`lockTime = now` = wall clock − 3 min, never past the median time) is final at once; a ~120k-gram storage-mass transaction relays; compute budgets 7/10/10 |
| 7 | `register bravo-tn --years 2` | 70-TKAS fee; registering into a gap created by a registration |
| 8 | `register lapse-tn --years 1 --backdate-days 741` | a backdated `now` (only "not in the future" is checked): lapsed a year ago |
| 9 | `extend alpha-tn --years 1` | permissionless extend, 1 → 2 years (the most a period holds), no lock time, 35-TKAS fee, periodStart kept |
| 10 | `renew lapse-tn --years 1` | renew after lapse: a timestamp-domain lock time (wall clock − 3 min, past `expiresAt − 10 days`) with non-final sequences relays; 35-TKAS fee; new period from the old expiry, still lapsed |
| 11 | `transfer alpha-tn <deployer address>` | owner SIGHASH_ALL signature, continuation keeps bond, periodStart and expiry |
| 12-13 | `list alpha-tn 50`, `buy alpha-tn` | listing; purchase with the payout right after the continuation (seller = buyer = the deployer, so the 50 TKAS come straight back) |
| 14-15 | `offer bravo-tn 10 --refund-after +100000`, `accept-offer bravo-tn` | an offer P2SH baked with this registry id, announced by its payload marker (the scanner finds it); accept = `transfer(buyer)` + `offer.accept(0)`, fee out of the offer (≤ maxFee 0.02) |
| 16-18 | `offer alpha-tn 5 --refund-after +600`, wait 601 DAA, `refund-offer alpha-tn` | the DAA-domain time-locked refund (1 in / 1 out) is accepted once final |
| 19-20 | `offer alpha-tn 3 --refund-after +100000`, `withdraw-offer alpha-tn` | buyer withdrawal |
| 21 | `release bravo-tn` | the 3-input exit (merge, release, absorbed): bond and a gap value come back |
| 22 | `reclaim lapse-tn` | the permissionless exit, timestamp-domain lock time `expiresAt + grace`: bond to the last owner at output 1, bounty to the caller |
| - | `status --scan` | the scanner rebuilds the same state from the chain; every tracked UTXO is live |

**Reclaim on testnet:** names are yearly and the grace is 10 days, so reclaiming a name that was
registered normally takes 1 year + 10 days on testnet too. Step 8 registers `lapse-tn` with
`now` backdated 741 days (the gap only proves `now` is not in the future), so it expired 376 days
ago and its renewal window is long open; step 10 renews it for a year from that old expiry, which
still leaves `expiresAt + grace` a day in the past, so step 22 can run at once. The prices paid
for it buy years that are already over. **Renew inside its window** (the last 10 days before
expiry, no lapse) needs a name close to its expiry, so the run does not show it on chain; the
harness, the CLI tests and the vectors (`renew in-window`, `renew just-opened`) cover it.

### Mempool questions still open (what the run answers)

1. **Relay of 35-8,000 TKAS fees.** Consensus accepts any fee; whether nodes relay and miners mine
   a transaction whose fee is thousands of times its mass-based fee is what steps 6-10 check for
   35 and 70 TKAS. The 4000 × 2 = 8,000-TKAS case (1-character names) is not exercised: it needs
   8,000 TKAS. SubmitTransaction has no high-fee guard at 2.0.1; wallet libraries that add one
   (and the app) must exempt register, extend and renew.
2. **Standard-mass relaxation.** Before Toccata the mempool caps each mass dimension at 100,000
   grams; a registration has ~120k grams of storage mass (README open issue 6). At 2.0.1 the cap
   is lifted from 30 minutes before Toccata's activation (testnet-10: DAA 467,579,632, May 2026),
   so it should relay; nodes older than the relaxation would drop it. Step 6 is the check.
3. **Time-locked transactions.** The mempool validates against the virtual's median time and DAA
   and rejects a transaction that is not yet final; there is no queue of future-dated
   transactions. So `register` uses `now = min(wall clock − 3 min, median time − 1 s)`, `renew`
   uses `max(that, expiresAt − renewWindowMs)` and `renew --submit` refuses before the window
   opens (saying when), `reclaim` and `refund-offer` are refused locally until their lock time has
   passed (the dry run says how long), and the commit's 600-DAA sequence lock is checked against
   the virtual DAA. Steps 6, 10, 16-18 and 22 confirm the relay side.
4. **Congestion.** Testnet-10 carried ~200 transactions per chain block and up to 4,400 mempool
   transactions on 2026-10-01; the normal feerate estimate was the 100 sompi/gram relay floor.
   The CLI pays `max(estimate, 100) × max(compute, normalized transient mass)` (0.002-0.021 TKAS)
   and states it in every summary.

### Tests

```bash
cd tools/kachat-names-cli
cargo test                                   # 28 tests: builders (21), rpc_paths (2), keys (2), util (3)
cargo test --test live_readonly -- --ignored --nocapture   # read-only, a real testnet-10 node
```

`tests/builders.rs` runs every command's builder against synthetic UTXOs through the consensus
validator (and each input under its committed compute budget), checks the fee is exactly price +
network fee and pays the relay floor, and reuses the harness scenarios: the CLI's register is
byte-identical to `scenarios::register` in its registry part (outputs 0-2, the gap's whole
signature script, lock time, sequences), the genesis gives the harness's registry id for the same
outpoint, and the whole e2e plan runs and balances (and fails with 30 TKAS less than the computed
minimum). It also covers commit maturity, the 8-input bound of register, owner checks, the
offer/reclaim time locks, the decoder refusing a forged registry output, the state JSON round
trip, the `kaspatest:`-only address guard, every payload (and that an offer marker matching no
output is ignored), and pins the signature-script encoding an indexer decodes (see below).
Registry v2: `extend` is refused with the reason past `periodStart + maxYears` (and 0 / 3 years);
`renew` is built but not final before its window (lock time = the opening, a note says when),
final from one millisecond after the opening (lock time = the opening while wall − 3 min is still
before it), then `wall − 3 min`, in grace and long after lapse, with every sequence 0; the decoder
follows extend (periodStart kept) and renew (new period), refuses a forged renew continuation,
and the 126-byte state decodes back.
`tests/rpc_paths.rs` runs every transaction of
the simulated plan through the SubmitTransaction conversion (the node decodes the identical
transaction: id, storage-mass commitment, compute budgets) and through the scanner's
RpcOptionalTransaction view, which rebuilds exactly the state the CLI tracked, offers included
(found by their payload marker alone).
`tests/keys.rs` covers the keygen guards.
`src/bin/kachat-names-vectors.rs` writes test vectors for ports of these builders (the KaChat
app's Swift core, `KaChatTests/KachatNamesVectors.json` there): every e2e-plan transaction plus
edge cases, with the builder inputs and every byte a port must reproduce (preimages, sighashes,
signature scripts, txid, masses, fee), and asserts each measured compute budget fits the fixed
table an app without a script engine commits. `kachat-names-vectors check <file>` validates
transactions a port built with that fixed table (signing its placeholders with the vectors' key).
`tests/live_readonly.rs` (ignored by default) connects to testnet-10 (GetInfo, network, an empty
GetUtxosByAddresses) and walks a minute of chain with the scanner (2026-10-01: 332 chain blocks,
21,727 accepted transactions, 3.5 s, nothing misdecoded).

### Signature-script encoding (what an indexer decodes)

Pinned by `tests/builders.rs::signature_scripts_are_args_then_tag_then_redeem`. Every contract
input's signature script is `<argument pushes, ABI order> <dispatch tag> <redeem>`, all
canonical minimal pushes (silverscript-abi `ScriptBuilder::add_data` / `add_i64`):

- **dispatch tag**: always a 4-byte push (`0x04` + 4 bytes; every contract has several entries).
- **redeem** (`prefix ‖ state ‖ suffix`): `OP_PUSHDATA2` (`0x4d`, 2-byte little-endian length)
  for all three contracts (gap 4,014 B, name 3,108 B, offer 948 B).
- **`byte[32]`**: a 32-byte push (`0x20`). **`sig`**: a 65-byte push (`0x41`), 64-byte Schnorr
  signature + `0x01`. **`byte[]`**: a minimal push of its bytes (register's `namePrefix` is a
  1-byte push of `0x6b`, `nameSuffix` an `OP_PUSHDATA2` of 2,981 bytes; an empty `byte[]` would
  be `OP_0`, a single byte 1-16 `OP_1`..`OP_16`, which a valid name never is).
- **`int`**: a minimal script number, not a fixed width: 0 is `OP_0` (`0x00`), 1-16 are
  `OP_1`..`OP_16` (`0x51`..`0x60`), -1 is `OP_1NEGATE`; anything else a 1-8 byte little-endian
  sign-magnitude push. So `years = 1` is the single opcode `0x51`, `accept(0)` is `0x00`, `now`
  (~1.8e12 ms) a 6-byte push, `list(50 TKAS)` a 5-byte push, `extend(1)` / `renew(2)` the
  single opcodes `0x51` / `0x52`. State ints *inside* the redeem are
  different: always 8 bytes behind an `0x08` push (`num8`).

## Registry v2

The 2-year cap on how far ahead a name is paid (KACHAT_NAMES.md 4.1, decided 2026-10-02), built
as specified:

- **State** +9 bytes: `periodStart` between `price` and `expiresAt` (126 B). The gap's register
  sets it to `now`; transfer, list, buy and offer accept keep it.
- **`extend(years)`** (new, tag `2ce7cceb`): anyone, any time, no lock time, while
  `expiresAt + years·365 d <= periodStart + 2·365 d`; periodStart kept. A 1-year registration can
  be extended once by a year; a 2-year one not at all.
- **`renew(years)`** (tag unchanged, `b706ac38`): 1 or 2 years, only once
  `tx.time >= expiresAt − renewWindowMs` (10 days, timestamp CLTV, also in grace and after lapse);
  `periodStart = expiresAt`, `expiresAt += years·365 d`. A renewal moves the window a year on, so a
  second renewal right after is refused; renew(1) + extend(1) is allowed, renew(2) + extend is not.
  So a name is never paid more than 2 years + 10 days ahead.
- **Param** `renewWindowMs` = 864,000,000 on both networks (baked into the name).

**Deployment.** The live testnet-10 registry `9444187f09a3e77450e125d448b21eb79b3c54b692a5b3f3e8af38343b9a7a51`
is **v1** (contracts and artifacts of commit `6167c1f`; its manifest pins the v1 template hashes
and carries their prefix/suffix bytes; it holds only the genesis gap, no names). These v2
contracts cannot spend v1 UTXOs, and the CLI refuses to work on that registry ("the manifest does
not describe the contracts in artifacts/ ... v2 needs a new genesis"). `params/testnet10.json`
still carries the v1 id, so `scripts/build.sh` currently writes `artifacts/testnet10/KachatOffer.json`
as the **v2** offer baked with the **v1** id: it matches no live name and is replaced at the v2
genesis. The v2 genesis (to be approved) is: move `manifests/kachat-names-testnet-10.json` aside
(e.g. `manifests/v1/`), set `registryCovenantId` back to `null`, delete `state/registry-testnet-10.json`,
then `kachat-names genesis --submit`, `./scripts/build.sh`, commit params + artifacts + manifest,
and run the [end-to-end plan](#the-end-to-end-run) (fund the deployer with at least 268 TKAS).

**What the app and the indexer change.** Name state layout (126 B, periodStart at bytes
109..117, expiresAt moves to 118..126); the new KachatName template (hash `e8ded947…9d16`, prefix
1 B, suffix 2,981 B) and gap template (`182c463c…dd46`); the new entry `extend` (dispatch tag
`2ce7cceb`, one `int` argument, payload `kchat:1:name:extend:<name>`) whose continuation keeps
periodStart; `renew` (`b706ac38`) now starts a new period (`periodStart = old expiresAt`) and
needs the lock time / sequences of the [transaction shapes](#transaction-shapes-the-app-must-build)
table; the fixed compute budgets (register 8, merge 4, transfer/list 12, buy/extend/renew 2,
accept 5); the vectors (`KaChatTests/KachatNamesVectors.json`: `extend`, renew in the window, at the
window opening and in grace, `lockTimeRules`). The app offers "Extend to 2 years" while
`extendable_years > 0`, "Renew" once the median time passes `expiresAt − renewWindowMs`, and
otherwise "Renewal opens on <date>".

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
2. `extend` and `renew` refuse an expiry already beyond 1e17 ms (~3 million years) so the sums
   can never overflow a script integer. Unreachable in practice (the 2-year period cap already
   bounds how far ahead a name is paid).
3. `GRACE` = 10 days (per the later instruction), not the 30 days in the doc.

## OPEN ISSUES

1. **Not audited.** silverc v1.0.0 is three weeks old; the compiled bytecode was reviewed only
   through these tests and spot disassembly (`tools/disasm.py`). An independent review of the
   `.sil` sources and of the bytecode is still needed before mainnet.
2. **Seat 2 of the exit is trusted by lineage** (`readInputState(2)` without a template check, as in
   dotk): it carries the registry id and a name refuses every entry at seat 2, so it is a gap. This
   holds only if the genesis covenant group contains nothing but the genesis gap - the manifest
   must pin and the app/indexer must verify the genesis binding.
3. **Miner-fee pricing relies on one registry input per transaction.** register, extend, renew,
   transfer, list and buy require exactly one registry input, so two fee-paying operations can never share
   one fee. A miner including its own registrations/renewals gets the price back (accepted).
4. **Bounded loops**: register, extend and renew transactions are limited to 8 inputs and 8 outputs and
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
10. **Mempool policy not exercised yet**: relay of 35-8,000 KAS fees, the post-Toccata
    standard-mass relaxation window, and mempool handling of the time-locked transactions must be
    confirmed on TN10. The harness and the CLI check consensus validity, the P2SH sig-op scan and
    output standardness only; the phase-2 run answers the rest (see
    [Mempool questions still open](#mempool-questions-still-open-what-the-run-answers)).
11. **Compiler quirks met**: the pragma must be `^0.1.0`; hex literals over 8 bytes need a cast
    (`byte[32](0x…)`); `OpTxInputSeq` returns raw `byte[8]` (low 32 bits are widened with a `0x00`
    byte before comparing); `checkSig` on a malformed key/signature is UB in Silverscript terms -
    the emitted `OpCheckSig` fails closed in the engine (tested), and no check depends on it.
12. **Offer artifacts per network** exist only after genesis (`registryCovenantId` in params); the
    harness compiles the offer for its own test registry id. Until the v2 genesis,
    `artifacts/testnet10/KachatOffer.json` is the v2 offer for the v1 id (see [Registry v2](#registry-v2)).
13. **Registry v2 is not deployed**: the live testnet registry is v1; v2 needs a new genesis
    (steps in [Registry v2](#registry-v2)).
14. **Name template size**: v2's name is 3,108 B (v1 2,002 B) because `extend` and `renew` each
    inline the miner-fee sum. Every name transaction is ~1.1 kB larger and ~0.002 KAS dearer, and
    some budgets went up by one. A single paid entry (e.g. `pay(int years, bool renewal)`, the
    time lock only when renewing) would save about 1 kB but changes the entry interface; not done.
15. **Renew window for absurd expiries**: if `expiresAt − renewWindowMs` were below the
    lock-time threshold (5e11, i.e. 1985), the CLTV would compare DAA scores, as reclaim's already
    does. Only a registration with a deliberately tiny `now` reaches that, and it only delays the
    window; the CLI refuses such a renew.
