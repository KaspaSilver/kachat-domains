# kachat-domains

The `.kachat` name service on Kaspa covenants:
- the contracts, in Silverscript;
- a Rust harness that runs every entry through rusty-kaspa's own consensus transaction validator;
- the `kachat-names` CLI that deploys and drives a registry, with a Docker image for Kaspa Quick
  Start.

Design: `KaChat/KACHAT_NAMES.md` in the app repo. Spec of the current registry:
[docs/REGISTRY_V4.md](docs/REGISTRY_V4.md).

**Status (2026-10-08):**
- **Registry v4 is live on testnet-10.** Registry `e6b7244831004e1db928458bce570347317b50ff124c010d342d73a6c2017f0d`,
  genesis `5ffdd006…a777`, deployed 2026-10-07. It runs on a **day clock**: mainnet's year
  scaled to 24 hours.
- **Mainnet is not deployed.** It still needs an external audit and the owner's go-ahead.
- **Earlier testnet registries** are archived in `manifests/` (see
  [Registry history](#registry-history)). Their names didn't carry over.

```
contracts/      KachatGap.sil  KachatName.sil  KachatOffer.sil
params/         testnet10.json  mainnet.json        (registryCovenantId set after a genesis)
artifacts/      <net>/KachatName.json KachatGap.json [KachatOffer.json] build-info.json   (scripts/build.sh)
manifests/      kachat-names-testnet-10.json (live) + v1/ v2/ v3/ v4-10min/ (archived; dryrun/ is scratch)
scripts/        build.sh build.py mutation-check.sh
harness/        Rust crate: src/lib.rs (kit), src/scenarios.rs (valid txs), tests/*.rs
tools/          disasm.py (+ opcode table of rusty-kaspa a41a333)
tools/kachat-names-cli/   the `kachat-names` CLI (Rust, same rusty-kaspa rev)
docker/  Dockerfile       the image Kaspa Quick Start builds (docs/KQS.md)
docs/           REGISTRY_V4.md (spec + owner decisions), REGISTRY_V3.md, KQS.md
.secrets/       deployer key + salted commits (gitignored, mode 600)    state/  local registry cache (gitignored)
```

## Contracts (registry v4)

- **Compiler:** all three are `pragma silverscript ^0.1.0`, compiled with silverc **v1.0.0**,
  commit `3ed973335b59269293564805cc2c58a14595ec03`.
- **One registry covenant id (KIP-20).** Gaps and names share it; the genesis transaction mints
  it. Offers are plain P2SH.
- **No template-hash cycle.** References go one way only:
  - gap -> name template hash;
  - offer -> registry id + name template hash;
  - name -> nothing.
- **Settings are baked into the templates.** Prices, `periodMs`, grace and so on are template
  constants. Testnet and mainnet therefore have different templates, and a settings change is a
  new genesis.
- **Every constructor parameter is committed.** `tests/ctor_commitment.rs` guards against
  silverscript#258, where an unused parameter is silently dropped.

### KachatGap - the registry interval `(lo, hi)`
State (66 B): `lo byte[32]`, `hi byte[32]`. Genesis state `(00..00, ff..ff)`.

| Entry | Seat | Checks |
|---|---|---|
| `register(byte[] name, byte[32] ownerKey, byte[32] salt, int now, int years, byte[] namePrefix, byte[] nameSuffix)` | input 0, the only registry input | 3 registry outputs at exactly 0, 1, 2, all authorized by the gap; name is `a-z0-9-`, 1..32 bytes, no hyphen first/last (256-entry table); `lo < blake3(name) < hi` (unsigned big-endian); `ownerKey != 0`; input 1's script is exactly `P2SH(0x20 c 0x75 0x20 ownerKey 0xac)`, `c = blake3("kachat-commit:v1" ‖ name ‖ ownerKey ‖ salt)`; input 1's relative sequence lock `>= tCommit` with the disable bit clear; `1 <= years <= maxYears`; `tx.time >= now` (timestamp CLTV); out 0 = gap `(lo, key)` = gapValue, out 1 = gap `(key, hi)` = gapValue, out 2 = name `(key, padded name, ownerKey, price 0, periodStart = now, expiresAt = now + years·periodMs)` = bond, against the baked name template hash; miner fee `Σin − Σout >= reg(len) + renew(len)·(years − 1)` over at most 8 inputs and 8 outputs |
| `merge()` | input 0 of the exit | exactly 3 registry inputs at 0, 1, 2 and 1 registry output at 0, authorized by the gap; seat 1 read with `readInputStateWithTemplate` (baked name template) and `name.key == hi`; seat 2 read as a gap and `succ.lo == hi`; out 0 = gap `(lo, succ.hi)` = gapValue |
| `absorbed()` | input 2 of the exit | same exit shape; authorizes nothing |

### KachatName - one UTXO per name, value = bond
State (126 B): `key byte[32]`, `name byte[32]` (zero padded), `owner byte[32]` (x-only), `price int`
(0 = unlisted), `periodStart int` (unix ms), `expiresAt int` (unix ms). Spliced as
`0x20 key 0x20 name 0x20 owner 0x08 price 0x08 periodStart 0x08 expiresAt` (ints are 8-byte script
numbers, `num8`): price at bytes 100..108, periodStart 109..117, expiresAt 118..126.

**Paying ahead.** A name is paid per period: a year on mainnet, 24 hours on testnet-10. It is
never paid more than `maxYears` (2) periods past the start of its current period:
- `extend` adds periods at any time;
- `renew` starts the next period once its window has opened.

**When it stops resolving.** The script can only say "not before", so the entries keep working
after `expiresAt`. The app and the indexer keep resolving a name to its owner through the grace
period, and stop once it lapses at `expiresAt + graceMs`. From then on anyone may `reclaim` it.

| Entry | Who | Checks |
|---|---|---|
| `transfer(byte[32] newOwner, sig)` | owner | continuation: new owner, price 0, periodStart and expiry unchanged |
| `list(int price, sig)` | owner | `0 <= price <= 2.9e18`; continuation with the price, periodStart and expiry unchanged |
| `buy(byte[32] newOwner)` | anyone | listed; output **continuation + 1** is `P2PK(owner)` with value `>= price`; continuation: new owner, price 0, periodStart and expiry unchanged |
| `extend(int years)` | anyone (gifts) | any time; `1 <= years <= maxYears`; `expiresAt <= 1e17`; `expiresAt + years·periodMs <= periodStart + maxYears·periodMs`; miner fee `>= renew(len)·years` (≤ 8 in / 8 out); continuation identical except `expiresAt += years·periodMs` |
| `renew(int years)` | anyone (gifts) | `1 <= years <= maxYears`; `expiresAt <= 1e17`; `tx.time >= expiresAt − renewWindowMs` (timestamp CLTV; open in grace and after lapse until a reclaim); miner fee `>= renew(len)·years`; continuation identical except `periodStart = expiresAt` and `expiresAt += years·periodMs` |
| `release(sig)` | owner | seat 1 of the exit; 3 registry inputs at 0..2, 1 registry output at 0, authorizes nothing |
| `reclaim()` | anyone | same exit seat; `tx.time >= expiresAt + graceMs` (timestamp CLTV); **output 1** is `P2PK(owner)` with value `>= bond` |

Every non-exit entry has exactly one registry input (this name) and exactly one registry output,
which it authorizes, with value **exactly** `bond`. Every signature must be SIGHASH_ALL (`0x01`).

### KachatOffer - KAS locked for one name (plain P2SH)
State (108 B), spliced by the app: `key byte[32]`, `buyer byte[32]`, `seller byte[32]` (the name's
owner when the offer was made), `refundAfter int` (DAA score). Baked per deployment: `registryCovId`,
the name template hash + prefix/suffix lengths, `maxFee`.

| Entry | Who | Checks |
|---|---|---|
| `accept(int nameIdx, sig sellerSig)` | the seller | seller signature (SIGHASH_ALL); offer is input `nameIdx + 1`; input `nameIdx` carries the registry id, is a KachatName (template) with `key` and **owner == seller**; it authorizes exactly one output: the name with `owner = buyer`, price 0, same name, periodStart and expiry; output **name continuation + 1** is `P2PK(owner)` with value `>= offer value − maxFee`. A change of owner ends every earlier offer |
| `withdraw(sig)` | buyer | SIGHASH_ALL signature by `buyer` |
| `decline(sig sellerSig)` | the seller | seller signature; **exactly 1 input and 1 output**, output 0 = `P2PK(buyer)` with value `>= offer value − maxFee` |
| `refund()` | anyone | `tx.daa >= refundAfter` (DAA CLTV); exactly 1 input and 1 output, output 0 = `P2PK(buyer)` with value `>= offer value − maxFee` |

## Transaction shapes the app must build

All are version-1 transactions with output covenant bindings and per-input compute budgets.

| Operation | Inputs | Outputs | Lock time / sequences |
|---|---|---|---|
| commit | owner funding | `P2SH(0x20 c 0x75 0x20 ownerKey 0xac)` (0.2 KAS) + change | - |
| register | 0 gap (`register`), 1 commit (owner sig + redeem), 2.. funding (≤ 8 inputs total) | 0 gap (lo,key), 1 gap (key,hi), 2 name, 3.. change (≤ 8 outputs) | `lockTime = now` (ms); input 1 `sequence = tCommit` (600); input 0 `sequence = 0`. Valid once the block DAA ≥ commitDaa + 600 **and** the past median time > now (it lags the wall clock ~2.2 min: use `now = min(wall − 3 min, medianTime − 1 s)`) |
| transfer / list / buy / extend | 0 name, 1.. funding | 0 continuation, [1 payout for buy], change | lock time 0, sequences 0 |
| renew | 0 name, 1.. funding | 0 continuation, change | `lockTime = max(min(wall − 3 min, medianTime − 1 s), expiresAt − renewWindowMs)`, **every input `sequence = 0`** (the CLTV needs a non-final input). Not final before the window opens, and the mempool keeps no future-dated transactions: refuse it and show when it opens |
| release | 0 gap (lo,key) `merge`, 1 name `release`, 2 gap (key,hi) `absorbed` | 0 merged gap, change | - |
| reclaim | same, name runs `reclaim` | 0 merged gap, **1 bond to the last owner**, 2 caller's bounty (gapValue − fee) | `lockTime = expiresAt + graceMs`, name input `sequence = 0` |
| offer accept | 0 name `transfer(buyer)` (owner sig), 1 offer `accept(0, sellerSig)` | 0 continuation (buyer), 1 payout to the owner | - |
| offer decline / refund | 0 offer, alone | 0 back to the buyer | refund: `lockTime = refundAfter` (DAA), `sequence = 0` |

**Payloads.** The contracts never read them; they count in mass and fee like any byte.
- **Offer marker.** The transaction that creates an offer carries
  `kchat:1:offer:<keyHex>:<buyerXonlyHex>:<sellerXonlyHex>:<refundAfterDaa>`. Offers have no
  covenant id and a P2SH hides the state, so this is how an indexer finds them. The marker is
  trusted only if `P2SH(offerPrefix ‖ offerState ‖ offerSuffix)` is one of the outputs.
- **Name operations.** register, extend, renew, transfer, list, buy, release, reclaim and offer
  accept carry the informational `kchat:1:name:<op>:<name>`.
- **No payload:** the commit (it would reveal the name), the genesis, and offer withdraw,
  decline and refund.

## Params

| Param | Mainnet (`params/mainnet.json`) | Testnet-10 (`params/testnet10.json`) | Baked into |
|---|---|---|---|
| `bond` | 1 KAS | 1 TKAS | name, gap |
| `gapValue` | 1 KAS | 1 TKAS | gap |
| `tCommit` | 600 DAA (~1 min) | 600 DAA | gap |
| `maxYears` (periods ahead) | 2 | 2 | gap, name |
| `periodMs` | 31,536,000,000 (365 days) | 86,400,000 (24 h) | gap, name |
| `graceMs` | 7,776,000,000 (90 days) | 21,600,000 (6 h) | name |
| `renewWindowMs` | 2,592,000,000 (30 days) | 7,200,000 (2 h) | name |
| register prices, first period, by length 1/2/3/4/5+ | 4000 / 2000 / 1000 / 250 / 35 KAS | 40 / 20 / 10 / 2.5 / 0.35 TKAS | gap |
| renew prices, each further period | 1000 / 500 / 250 / 62.5 / 8.75 KAS | 10 / 5 / 2.5 / 0.625 / 0.0875 TKAS | gap, name |
| `offerMaxFee` | 0.02 KAS | 0.02 TKAS | offer |
| loop bounds | 8 inputs, 8 outputs, values ≤ 1e18 sompi (constants) | same | gap, name |

`scripts/build.py` refuses:
- `maxYears` outside 1..31;
- `periodMs` outside a minute..a year;
- `maxYears·periodMs >= 1e12`;
- a renewal window longer than a period;
- prices over 1e17 sompi.

## Sizes and template hashes

| Template | Mainnet: size, prefix/state/suffix, hash | Testnet-10: size, prefix/state/suffix, hash |
|---|---|---|
| KachatGap | 4067 B, 1/66/4000, `6d1da31f…84b2` | 4058 B, 1/66/3991, `9f057f40…8bf5` |
| KachatName | 3108 B, 1/126/2981, `13bcd781…e7ed` | 3094 B, 1/126/2967, `c263a8c2…b56b` |
| KachatOffer | built after the genesis (bakes the registry id) | 1114 B, 1/108/1005, `5a7e22af…2a7a` |
| commit redeem | 68 B, fixed | same |

Full hashes are in `artifacts/<net>/build-info.json` and the manifest.

Dispatch tags are the same on both networks, and `tests/genesis.rs` pins them:

| Contract | Entries |
|---|---|
| gap | `register 8667af5e`, `merge 63d25bc2`, `absorbed dab76355` |
| name | `transfer 794dca54`, `list 674a8ea4`, `buy 76a02eb9`, `extend 2ce7cceb`, `renew b706ac38`, `release 388ad0b4`, `reclaim f56af4df` |
| offer | `accept 2e18ed39`, `decline aead5037`, `withdraw 80344ff1`, `refund 777f5b11` |

## Cost per operation

From `cargo test --test report -- --nocapture` (testnet-10 templates, 2026-10-08).
- **Masses** come from rusty-kaspa's `MassCalculator`.
- **Min fee** = 100 sompi/gram × max(compute, normalized transient), the post-Toccata relay floor.
- **Budget** = the smallest covering compute budget, measured by the engine. 1 unit = 10,000
  script units, 9,999 are free per input, and P2PK funding inputs need 10.

| Operation | Size B | Compute g | Transient g (norm.) | Storage g | Min network fee | Compute budget (script units) |
|---|---|---|---|---|---|---|
| register 5 chars, 1 period | 7888 | 12058 | 15776 | 93239 | 0.0158 | gap.register 7 (76979), commit 10 |
| register 32 chars, 2 periods | 7915 | 12185 | 15830 | 93903 | 0.0158 | gap.register 8 (85758), commit 10 |
| register worst case (8 in, 8 out) | 8723 | 19433 | 17446 | 80524 | 0.0194 | gap.register 8 (85992) |
| transfer | 3608 | 6538 | 7216 | 5101 | 0.0072 | name.transfer 12 (120032) |
| list | 3580 | 6410 | 7160 | 5101 | 0.0072 | name.list 11 (119994) |
| buy | 3594 | 5784 | 7188 | 39104 | 0.0072 | name.buy 1 (19846) |
| extend 1 period | 3510 | 5340 | 7020 | 15877 | 0.0070 | name.extend 1 (19958) |
| extend worst case (8 in, 8 out) | 4542 | 14632 | 9084 | 15898 | 0.0146 | name.extend 2 (20270) |
| renew 1 or 2 periods (in the window) | 3510 | 5340 | 7020 | 15877 / 16681 | 0.0070 | name.renew 1 (19952) |
| renew worst case (8 in, 8 out) | 4542 | 14632 | 9084 | 16744 | 0.0146 | name.renew 2 (20264) |
| release (exit) | 11695 | 13825 | 23390 | 0 | 0.0234 | merge 4 (46952), release 10 (106883), absorbed 0 (8400) |
| reclaim (exit) | 11681 | 13171 | 23362 | 0 | 0.0234 | merge 4 (46940), reclaim 0 (6710), absorbed 0 (8400) |
| offer accept | 4731 | 8161 | 9462 | 39736 | 0.0095 | transfer 12 (120032), offer.accept 15 (155857) |
| offer decline | 1388 | 2748 | 2776 | 0 | 0.0028 | offer.decline 10 (102836) |
| offer withdraw | 1388 | 2748 | 2776 | 0 | 0.0028 | offer.withdraw 10 (102569) |
| offer refund | 1322 | 1682 | 2644 | 0 | 0.0026 | offer.refund 0 (2491) |

**Prices on top.** Register, extend and renew also leave the price as miner fee:
- register pays `reg(len) + renew(len)·(years − 1)`;
- extend and renew pay `renew(len)·years`.

**Signatures dominate.** Each signature check costs 100,000 script units (10 budget units).

**Fixed budgets for an app without a script engine** (`RECOMMENDED_BUDGETS` in
`src/bin/kachat-names-vectors.rs`, which checks every measured budget fits): register 8, merge 4,
absorbed 0, transfer/list 12, buy/extend/renew 2, release 10, reclaim 0, accept 17 (measured 15),
decline/withdraw 10, refund 0, commit/P2PK 10.

## Run it (Docker, Kaspa Quick Start)

```bash
docker build -t kachat-domains https://github.com/KaspaSilver/kachat-domains.git#main
docker run --rm kachat-domains verify          # the deployed manifest, checked against contracts/ + params/
docker run --rm -v "$PWD/names:/names" kachat-domains publish   # verify, then copy the manifest out
docker run --rm kachat-domains prices
```

- **`verify`** (also `kachat-names verify` from a checkout) recompiles the contracts in-process.
  The committed artifacts and the manifest must then match: the templates, the genesis binding
  and every param.
- **`verify --live [--indexer <url>] --node <grpc>`** also proves that a list of names is
  exactly the registry on chain. Every gap between the names, and every name with its owner,
  price and dates, must hold a registry UTXO. This is the approach of supertypo/dotk-covenants'
  verifier.
  - **List source:** an indexer's `GET /names/all`, or this CLI's own scan.
  - **Tested:** on testnet-10, 2026-10-08, 3 names and 4 gaps proven.
  - **Pending:** the indexer doesn't serve `/names/all` yet (kachat-indexer
    `docs/KACHAT_NAMES_ALL.md`).
- **Kaspa Quick Start** installs and updates this image as an app: [docs/KQS.md](docs/KQS.md).

## Build and test

```bash
./scripts/build.sh                 # needs ~/silverscript at 3ed9733 (refuses anything else); writes artifacts/
cd harness && cargo test           # 147 tests
cargo test --test report -- --nocapture   # the cost table above
../scripts/mutation-check.sh       # delete each security check in turn, show which tests catch it
cd ../tools/kachat-names-cli && cargo test   # the CLI: 46 tests (+3 live, --ignored)
```

**Toolchain.** `rust-toolchain.toml` pins Rust 1.97.1, and the Dockerfile uses the same version
(a test checks they agree).

**Dependencies.** The harness depends on:
- the rusty-kaspa revision silverscript v1.0.0 pins, `a41a333` (testnet-10 nodes run 2.0.1 and
  2.1.0; 2.1.0 changes nothing that affects these scripts or masses);
- silverscript itself at `3ed9733`.

**What the harness does:**
1. Loads `artifacts/testnet10/*.json`, which must equal a fresh compile of `contracts/*.sil`.
2. Splices state by hand, exactly as the app does.
3. Mints a real genesis and compiles the offer for that registry id.
4. Signs with SIGHASH_ALL and picks each input's compute budget by measuring it in the engine.
5. Validates with `TransactionValidator` (isolation + UTXO context, Full flags).
6. Reproduces the header-context finality rule (`check_tx_is_finalized`, crate-private upstream)
   verbatim.

Attack tests assert both that the specific input's script fails (and not merely on its budget)
and that the whole transaction is rejected.

| File | Tests | Covers |
|---|---|---|
| `register.rs` | 36 | every tier of both tables at exactly the price and one sompi short (the first period at the registration price, the rest at the renewal price); periods 1..2 and 0/−1/3; expiry not matching `now + years·periodMs`; periodStart = now; the commit (missing, another owner / name / salt, a front-runner, immature, short or disabled lock); `now` in the future / DAA-domain lock time / finalized gap input; key outside the gap, on its boundaries, byte order; charset, hyphens, lengths 0 and 33; extra or moved outputs, wrong values, wrong name state, forged name template, zero owner; 9 inputs / 9 outputs |
| `name.rs` | 47 | transfer, list, buy (signatures, sighash types, payout, tampered continuations, periodStart kept); **extend** (the period cap, any time incl. grace and lapse, renewal-table price per period); **renew** (window boundary, before it, in grace and after lapse, new period from the old expiry, renew + extend combinations, renewal-table price); expiry cap; gifts; batching refused |
| `exit.rs` | 23 | release (listed, expired, wrong sig, non-adjacent seats, forged seats, extra output, reordered or fourth input); reclaim (bond to the owner, grace is 6 hours on the testnet clock, before grace by script and by consensus, DAA lock, finalized input, payout errors, renewed name) |
| `offer.rs` | 28 | accept by the seller only (owner changed since the offer, wrong or missing seller signature, matched listings), keeps the paid period; maxFee boundary; payout errors; wrong name; two offers on one name; withdraw; **decline** (seller only, back to the buyer, alone); refund (before / after `refundAfter`, alone, payout errors) |
| `genesis.rs` | 10 | genesis validity; nobody can mint the registry id later; artifacts == fresh compile; the testnet day clock and the mainnet params; state does not move the template; hand codecs == ABI codecs; state spans; commit spend; dispatch tags |
| `ctor_commitment.rs` | 1 | changing any constructor parameter changes the template hash (or only the state span for `init*`): silverscript#258 guard |
| `lifecycle.rs` | 1 | genesis → registrations → list, buy → gift extend → offer + accept → release → renew → reclaim → back to the genesis gap → register anew, every tx spending the previous ones' real outputs |
| `report.rs` | 1 | the cost table; standardness (P2SH sig-op scan ≤ 15, standard outputs) and mass headroom |

**Mutation check.** `scripts/mutation-check.sh` deletes or weakens 73 individual checks, one at a
time, rebuilds and reruns the harness. Last run 2026-10-08 on the day-clock contracts:
**68 killed, 5 survived**. Every survivor is redundant by construction, and each is labelled in
the script with what covers it:
- the register output count (covered by `AuthOutputCount(0) == 3` plus one registry input);
- the explicit 8-input bound (covered by the compiler's loop guard);
- each half of the name's one-input / one-output pair (removing both is caught);
- the offer's wanted-key check (covered by the continuation being validated with the offer's key).

## Testnet-10 deployment

`tools/kachat-names-cli` builds the `kachat-names` binary: the operations of the
[transaction shapes](#transaction-shapes-the-app-must-build) table against a real testnet-10 node.
It reuses the harness kit on the same rusty-kaspa revision. So every transaction it prints was
built, signed and validated by exactly the code the contract tests use.

**Safety rules built into the tool**

- **Testnet-10 only.**
  - There is no mainnet mode. The params file, address prefix (`kaspatest:`), consensus params
    and network name are constants.
  - Every command that talks to a node first requires it to be on `testnet-10`, synced and
    UTXO-indexed, and `--submit` re-checks right before sending.
- **Dry run by default.**
  - Every spending command builds the transaction, validates it locally (isolation + header
    finality + UTXO context), checks mempool standardness, and prints a full summary.
  - Only `--submit` broadcasts, and only a transaction that passed those checks.
  - The one write RPC is SubmitTransaction.
- **One key.**
  - `keygen` creates `.secrets/testnet10-deployer.key` (directory 700, file 600). It refuses to
    overwrite one, and refuses unless `.secrets/` is in `.gitignore`.
  - It prints only the address.
  - Salts of pending commits live in `.secrets/commits.json` (600).

### Setup

```bash
brew install protobuf                     # protoc, needed by rusty-kaspa's gRPC crates
cd tools/kachat-names-cli && cargo build --release && cd ../..
alias kachat-names=$PWD/tools/kachat-names-cli/target/release/kachat-names
kachat-names keygen                       # once: prints the deployer's kaspatest: address
kachat-names node-info                    # read-only: network, DAA, median time, deployer UTXOs
```

- **Checkout.** The binary finds it from the current directory, or from `--repo` or
  `KACHAT_DOMAINS_ROOT`.
- **Node.** Pass `--node grpc://host:16210`, or the CLI discovers one through the testnet-10 DNS
  seeders: the first seeded peer that answers, is synced, is UTXO-indexed and is on testnet-10.
- **Deployer:** `kaspatest:qz5xdn6e0clxsyey4k7pzhkrfjnhg6qneac0d0lyl8pk7tya6vyysf8pt3r8m`.
- **Funding.** A genesis needs 1 TKAS plus a 0.002 TKAS fee. The end-to-end plan needs at least
  59 TKAS; fund 100. `kachat-names balance` shows the UTXOs.

### Registry state without an indexer

A gap or name UTXO sits at the P2SH address of `prefix ‖ state ‖ suffix`. Its address therefore
commits to its whole state: a UTXO at that address carrying the registry covenant id *is* that
state, live.

**Tracking the state.**
- **Where:** the CLI keeps the decoded states in `state/registry-testnet-10.json` (gitignored),
  starting from the manifest's genesis gap.
- **How it moves forward:** one decoder, `Registry::apply`.
  1. It reads each registry input's signature script: dispatch tag, arguments, and the revealed
     redeem (which is the tracked state).
  2. It predicts every registry output the entry must create.
  3. It accepts the transaction only if the predictions match the bound outputs one to one.
     Anything unexplained is refused, and the state is left untouched.
- **Offers** are found through their payload marker, and accepted only when an output really is
  that offer.

**Two feeds:**
- **Every transaction this CLI submits,** applied right after the node accepts it.
- **`kachat-names scan`,** for everyone else's registry transactions:
  - it walks the selected chain from the checkpoint with GetVirtualChainFromBlockV2 (accepted
    transactions with inputs, signature scripts and covenant bindings), 20 confirmations deep;
  - it reads page after page until the node returns no new confirmed chain block (a page is
    ~180 chain blocks);
  - a checkpoint the node doesn't know, such as a pruned one, fails loudly and moves nothing;
  - `scan --from-genesis` rebuilds the state from the manifest's checkpoint.
  - On 2026-10-08 it walked 376,966 chain blocks (a day) in 239 pages in 15 minutes.

**`kachat-names status`:**
- decodes all gaps, names (owner, listing, expiry phase), tracked offers and open commits;
- checks each against GetUtxosByAddresses (live, with the registry covenant id);
- checks that the gaps and names tile the key space.

Before spending, every command fetches the live UTXO of each registry input, so a stale state
fails loudly. `verify --live` proves the whole state against the chain.

### Genesis, manifest and the offer artifact

```bash
kachat-names genesis                      # dry run against the node (needs the funded deployer)
kachat-names genesis --assume-utxo 300    # dry run before funding: a synthetic UTXO
kachat-names genesis --submit             # the real one (only after the owner's "send it")
```

**The genesis transaction.**
- It spends one deployer UTXO.
- Output 0 is the lone gap `(00..00, ff..ff)`, bound to `covenant_id(that outpoint, [(0, gap)])`.
- Output 1 is change. Nothing else is authorized.

**What `--submit` writes:**
- `manifests/kachat-names-testnet-10.json`: params, compiler, every template's hash, prefix and
  suffix bytes and dispatch tags, the genesis outpoint, txid and authorized output,
  `registryCovenantId`, and the scan checkpoint;
- `registryCovenantId`, filled into `params/testnet10.json`;
- the initialized state.

Then build the offer artifact and commit:

```bash
./scripts/build.sh      # now also writes artifacts/testnet10/KachatOffer.json for the registry id
git add params/testnet10.json artifacts/testnet10 manifests/kachat-names-testnet-10.json
```

**Before a new genesis next to a live registry** (a new contract version, or new settings,
which are baked in):
1. Archive the old manifest and state (e.g. `manifests/v4-10min/`, `state/v4-10min/`).
2. Set `registryCovenantId` back to `null`.
3. Rebuild.

`--submit` refuses while a manifest exists or params carry an id. A dry run is allowed next to a
deployed registry: it previews a new one and writes only `manifests/dryrun/`.

**Every later command verifies the manifest before trusting it:**
- the registry id must equal `covenant_id(genesis outpoint, [genesis gap])`, recomputed from the
  templates;
- the template hashes, prefixes and suffixes must match;
- an existing `KachatOffer.json` must be byte-identical to the in-process compile.

### The end-to-end run

`kachat-names e2e-plan` prints this list, and `--simulate` also prints every transaction.

**Budget.** The plan runs in-process first, through the same builders with synthetic UTXOs: each
transaction is validated and spends the previous transactions' outputs. That is where the budget
comes from:

| | TKAS |
|---|---|
| Transactions | 22 |
| Prices (miner fee) | 1.3125 |
| Network fees | 0.165 |
| Left locked in the registry | 3 |
| Spent in total | 4.48 |
| Least funding that completes it | 59 |

Names are 8 characters, the 5+ tier: 0.35 TKAS to register, 0.0875 per further period. Each
command waits until its output shows up in the UTXO index, so the next one sees it.

| # | Command (`--submit` each) | What it proves |
|---|---|---|
| 1 | `genesis`, then `./scripts/build.sh` + commit | the registry id is minted by one ordinary UTXO; the genesis covenant group holds only the gap |
| 2-4 | `commit alpha-tn`, `commit bravo-tn`, `commit lapse-tn` | salted commits: only `P2SH(commitment, owner)` is public |
| 5 | wait 600 DAA (~1 min) | the commit's sequence lock |
| 6 | `register alpha-tn --years 1` | the registration price as miner fee; the time-locked register is final at once |
| 7 | `register bravo-tn --years 2` | the second period at the renewal price; registering into a gap a registration created |
| 8 | `register lapse-tn --years 1 --backdate-minutes 3300` | a backdated `now` (only "not in the future" is checked): expired 31 hours ago, past its 6-hour grace |
| 9 | `extend alpha-tn --years 1` | permissionless extend, 1 → 2 periods, periodStart kept |
| 10 | `renew lapse-tn --years 1` | renew after lapse: a timestamp lock time past `expiresAt − 2 h` with non-final sequences; new period from the old expiry, still lapsed |
| 11 | `transfer alpha-tn <deployer address>` | owner SIGHASH_ALL signature, continuation keeps bond, periodStart and expiry |
| 12-13 | `list alpha-tn 50`, `buy alpha-tn` | listing; purchase with the payout right after the continuation |
| 14-15 | `offer bravo-tn 10 --refund-after +100000`, `accept-offer bravo-tn` | an offer bound to the seller, found by its payload marker; accept = `transfer(buyer)` + `offer.accept(0, sellerSig)` |
| 16-17 | `offer alpha-tn 4 --refund-after +100000`, `decline-offer alpha-tn` | the seller declines: straight back to the buyer |
| 18-20 | `offer alpha-tn 5 --refund-after +600`, wait 601 DAA, `refund-offer alpha-tn` | the DAA-domain time-locked refund |
| 21-22 | `offer alpha-tn 3 --refund-after +100000`, `withdraw-offer alpha-tn` | buyer withdrawal |
| 23 | `release bravo-tn` | the 3-input exit: bond and a gap value come back |
| 24 | `reclaim lapse-tn` | the permissionless exit after grace: bond to the last owner, bounty to the caller |
| - | `status --scan`, `verify --live` | the scanner rebuilds the same state from the chain, and it is exactly the registry |

### Mempool behaviour (testnet-10)

1. **Large fees relay.**
   - **Seen** on the live registry: `k` and `a` (1 character, 2 periods: a 50-TKAS miner fee
     each) and `testing` (0.4375 TKAS) relayed and were mined.
   - **Not exercised:** the largest mainnet-scale fees (up to 8,000 KAS for 1-character names,
     2 periods).
   - **Wallets:** a wallet library with a high-fee guard must exempt register, extend and renew.
2. **Storage mass.** A registration has ~80-95k grams of storage mass. It relays post-Toccata
   (seen on testnet-10).
3. **Time-locked transactions.**
   - The mempool validates against the virtual's median time and DAA, and keeps no future-dated
     transactions.
   - So `register` uses `now = min(wall − 3 min, median time − 1 s)`, and `renew` uses
     `max(that, expiresAt − renewWindowMs)`.
   - `renew --submit` refuses before the window opens, and `reclaim` and `refund-offer` are
     refused locally until their lock time has passed.
4. **Fees.** The CLI pays `max(estimate, 100) × max(compute, normalized transient mass)` and
   states it in every summary.

### CLI tests

```bash
cd tools/kachat-names-cli
cargo test                                   # 46 tests: builders 22, verify 14, rpc_paths 5, keys 2, util 3
cargo test --test live_readonly -- --ignored --nocapture   # read-only, a real testnet-10 node
```

**`tests/builders.rs`** runs every command's builder against synthetic UTXOs through the
consensus validator. It checks:
- the fee is exactly price + network fee;
- the CLI's register matches the harness scenario byte for byte in its registry part;
- the whole e2e plan runs and balances;
- the decoder refuses forged registry outputs;
- every payload;
- the signature-script encoding an indexer decodes.

**`tests/verify.rs`:**
- **Offline `verify` refuses:** a changed manifest param, a changed price, the same change to
  both, a wrong template hash, a wrong registry id and a dry-run manifest.
- **The live proof refuses:** a hidden name, an invented one, a wrong owner, date or price, a UTXO
  of another covenant or value, a duplicate key, and an indexer key that isn't `blake3(name)`.
- **Toolchain:** the Dockerfile's Rust version must match `rust-toolchain.toml`.

**`tests/rpc_paths.rs`:**
- runs every plan transaction through the SubmitTransaction conversion and through the scanner's
  view;
- drives the scanner with a simulated node that pages like rusty-kaspa does: a multi-page walk to
  the tip, a `max_rounds` stop, and an unknown checkpoint.

**Test vectors.** `src/bin/kachat-names-vectors.rs` writes test vectors for ports of these
builders (the KaChat app's Swift core uses them: `KaChatTests/KachatNamesVectors.json` there).
`kachat-names-vectors check <file>` validates transactions a port built with the fixed budget
table.

### Signature-script encoding (what an indexer decodes)

Pinned by `tests/builders.rs::signature_scripts_are_args_then_tag_then_redeem`.

**Layout.** Every contract input's signature script is
`<argument pushes, ABI order> <dispatch tag> <redeem>`, all canonical minimal pushes.

| Field | Encoding |
|---|---|
| dispatch tag | always a 4-byte push (`0x04` + 4 bytes) |
| redeem (`prefix ‖ state ‖ suffix`) | `OP_PUSHDATA2` (`0x4d`, 2-byte little-endian length) for all three contracts |
| `byte[32]` | a 32-byte push (`0x20`) |
| `sig` | a 65-byte push (`0x41`): 64-byte Schnorr signature + `0x01` |
| `byte[]` | a minimal push of its bytes. Register's `namePrefix` is a 1-byte push; `nameSuffix` is an `OP_PUSHDATA2` of 2,967 bytes (testnet) / 2,981 (mainnet) |
| `int` | a minimal script number, not fixed width |

**Ints in detail:**
- 0 is `OP_0`, 1-16 are `OP_1`..`OP_16`, −1 is `OP_1NEGATE`;
- anything else is a 1-8 byte little-endian sign-magnitude push;
- so `years = 1` is the single opcode `0x51`, and `accept(0, …)` starts with `0x00`.

State ints *inside* the redeem are different: always 8 bytes behind an `0x08` push (`num8`).

## Registry history

All on testnet-10. Archived manifests are in `manifests/<dir>/`; the live one is
`manifests/kachat-names-testnet-10.json`. A new version, or new baked settings, needs a new
genesis, and names don't carry over. Migration (a snapshot import into the next version) is
designed in [docs/REGISTRY_V4.md](docs/REGISTRY_V4.md) section 3, but not built yet.

| Registry | Version | Clock | Genesis | Where |
|---|---|---|---|---|
| `9444187f…` | v1 | yearly | `cba68dd1…` | `manifests/v1/` |
| `82f4315c…` | v2: periodStart, `extend`, renewal window | yearly | `e20325f7…` | `manifests/v2/` |
| `90f56bd1…` | v3: price record + authority key, seller-bound offers, `decline`, `periodMs` | 10 min | `fa8b21d2…` | `manifests/v3/`, spec `docs/REGISTRY_V3.md` |
| `bff18554…` | v4: fixed register + renew tables, no price key | 10 min | `b1f28a5f…` | `manifests/v4-10min/` |
| **`e6b72448…`** | **v4** | **24 h** | **`5ffdd006…`** | **live** |

## Deviations from KACHAT_NAMES.md

1. **Commit maturity is a sequence lock**, not `tx.daa >= OpTxInputDaaScore(1) + T_COMMIT`.
   - **Why:** registration needs `tx.time >= now` in the same transaction, and a transaction has
     one lock time.
   - **How:** the gap requires input 1's relative sequence lock `>= tCommit` with bit 63 clear.
     Consensus `check_sequence_lock` enforces it as `blockDaa >= commitDaa + lock`.
   - **Tested:** valid at exactly `commitDaa + 600`, rejected one DAA earlier.
2. **An expiry cap.** `extend` and `renew` refuse an expiry beyond 1e17 ms, so the sums can never
   overflow. The period cap already makes this unreachable.
3. **Grace and renewal window are per-network params**: 90 and 30 days on mainnet, 6 and 2 hours
   on testnet-10.

## OPEN ISSUES

1. **Not audited.**
   - silverc v1.0.0 is a month old.
   - The bytecode was reviewed only through these tests, the mutation check and spot disassembly
     (`tools/disasm.py`).
   - An independent review of the `.sil` sources and the bytecode is needed before mainnet.
2. **Seat 2 of the exit is trusted by lineage.** `readInputState(2)` has no template check, as in
   dotk.
   - It carries the registry id, and a name refuses every entry at seat 2, so it is a gap.
   - This holds only if the genesis covenant group contains nothing but the genesis gap. The
     manifest pins that, and the app and indexer verify the genesis binding.
3. **Miner-fee pricing relies on one registry input per transaction.**
   - register, extend, renew, transfer, list and buy require exactly one, so two fee-paying
     operations can never share one fee.
   - A miner that includes its own registrations gets the price back (accepted).
4. **Bounded loops.** Register, extend and renew are limited to 8 inputs and 8 outputs, with
   values ≤ 1e18 sompi each. The wallet must consolidate funding first.
5. **Key validity.** Script cannot check that an owner key is on the curve.
   - Zero keys are refused.
   - Any other invalid key bricks the owner entries until the name lapses; then `reclaim` frees
     it, and the bond goes to the unspendable key.
   - The app must validate keys.
6. **Storage mass.** Each 1-KAS covenant output costs ~40k grams of KIP-9 storage mass, so a
   registration is ~80-95k grams, block-space heavy. A larger `gapValue`/`bond` reduces it.
7. **Time.** `now` and the time locks use the block's past median time, which lags the wall clock
   ~2.2 min. Registering with `now = wall − 3 min` loses those minutes of the paid period.
8. **Compiler quirks.**
   - The pragma must be `^0.1.0`.
   - Hex literals over 8 bytes need a cast.
   - `OpTxInputSeq` returns raw `byte[8]`.
   - `checkSig` on a malformed key fails closed (tested).
   - **silverscript#258:** an unused constructor parameter is silently dropped. It's still open
     upstream; `tests/ctor_commitment.rs` guards against it.
9. **Name template size.** The name is ~3.1 kB because `extend` and `renew` each inline the
   miner-fee sum. A single paid entry would save ~1 kB, but it changes the entry interface; not
   done.
10. **Migration isn't built.** A bug found after mainnet needs a new version that imports a
    snapshot of this one (design: [docs/REGISTRY_V4.md](docs/REGISTRY_V4.md) section 3). The
    Merkle import and its script-size check are not prototyped yet.
11. **rusty-kaspa pin.** The harness and the CLI stay on `a41a333`, the revision silverscript
    v1.0.0 pins. Moving to 2.1.0 waits for a silverscript release on it.
