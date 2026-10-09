# Mainnet launch (2026-10-09)

**Status: LIVE since 2026-10-09 20:39 UTC ("`.kachat` mainnet v1").**
- **Registry** `348bd2c81170f267a2a7039cbf3a6f275e80b189d6c956183ea73ff3ffde75a4`.
- **Genesis** `a0281841bf77807a7780f13cc84c0a3e4cd8df3d076b7f052ffc9c898cca90ff`, funded by
  `5fa3f07f…8a36:0`, deployer `kaspa:qqgcspk6s0t9q87a2rf28wjcpzse5sgvwnsu8jpvr9rmqt2zcf6avdu9xs0he`.
- **Templates:** gap `d70afe60…` (4,216 B), name `259e0250…` (3,406 B), offer `7e7f2461…`
  (1,117 B). Manifest: `manifests/kachat-names-mainnet.json`.

It runs the **registry v4 contracts** (`contracts/KachatGap.sil`, `KachatName.sil`,
`KachatOffer.sil` under `params/mainnet.json`). Users see it as "mainnet v1". The manifest's
`registryVersion` stays `4`, because the apps and the indexer decode by it. Registry v5
(`docs/REGISTRY_V5.md`) is the escape route: if mainnet ever needs a fix or new prices, a v5
registry imports a snapshot of v4, and every name keeps its owner and paid period.

**The owner's launch plan (2026-10-09):**
1. The owner registers 2 names from a personal iPhone build and tests.
2. An app update shows a **1-week countdown**, in which no app searches or registers names.
3. Then it's public.

There's **no on-chain lock**: the registry is open from the genesis, so the countdown gates the
official apps only (the owner's choice). The **external audit** follows the launch (the owner
waived it as a launch gate).

## 1. Before the genesis

| # | Gate | Who | State |
|---|---|---|---|
| 1 | Pre-mainnet audit (2026-10-09): C2 fixed in the contracts, T1-T3 tests and mutations added, CLI mainnet mode (R1), manifest written before the acceptance wait (R2) | this repo | done |
| 2 | **Testnet runs the final code.** Migrated 2026-10-09 from `fdc403f5…` to `1283f749…bfa2` (all 6 names, same owners and dates). The apps run on it, an app `release` (k) went through, and the testnet indexer is proven against the chain (`verify --live --indexer`) | done |
| 3 | **External audit** of the three contracts at the launch commit | owner | after launch (waived as a gate) |
| 4 | **Docker image built** from the launch commit, and `verify` passing in it | owner / KQS | to do |
| 5 | Mainnet params final: prices, `offerMaxFee` 0.1 KAS, `registryCovenantId: null` | owner | done |
| 6 | App release ready: mainnet template pins and the manifest, the launch-day retry (C3), the offer guards (C1) | iOS / Android / Desktop | to do |
| 7 | Mainnet indexer follower ready, and KQS publishing `kachat-names-mainnet.json` (`docs/KQS.md` section 5) | indexer / KQS | to do |
| 8 | The owner's explicit go-ahead | owner | done: genesis 2026-10-09 |

**Checks at the launch commit** (all must pass):

```bash
./scripts/build.sh                                  # artifacts for both networks
cd harness && cargo test --release                  # every test, the v5 gap (testnet)
KACHAT_GAP=v4 cargo test --release                  # every test, the v4 gap (mainnet's)
cargo test --release --test mainnet                 # mainnet params: prices, clock, caps
cd .. && ./scripts/mutation-check.sh                # every check caught by a test, or labelled redundant
cd tools/kachat-names-cli && cargo test --release
```

## 2. The genesis

All on mainnet, with the owner's own node (`--utxoindex`, synced).

```bash
kachat-names --network mainnet keygen               # .secrets/mainnet-deployer.key (mode 600); prints the address
kachat-names --network mainnet address
```

1. **Fund the deployer:** the owner sends about **1.2 KAS** to the printed `kaspa:` address. The
   genesis locks 1 KAS (the genesis gap's `gapValue`); the rest pays the fee and comes back as
   change. Nobody else sends KAS.
2. **Dry run:**
   ```bash
   kachat-names --network mainnet --node grpc://<own node>:16110 genesis
   ```
   It writes `manifests/dryrun/kachat-names-mainnet.json` and would-be params, and rebuilds the
   artifacts for the would-be registry id. Read the summary: the registry id, the gap value, the
   fee, the change back to the deployer.
3. **The owner says "send it".** Then:
   ```bash
   kachat-names --network mainnet --node grpc://<own node>:16110 --max-fee 0.1 genesis --submit
   ```
   - `--submit` on mainnet refuses to run without `--node` and `--max-fee`.
   - The manifest, the registry id in `params/mainnet.json` and `state/` are written right after
     the node takes the transaction, before the acceptance wait.
4. **Build the offer** for the registry id, verify and commit:
   ```bash
   ./scripts/build.sh
   kachat-names --network mainnet verify
   kachat-names --network mainnet --node grpc://<own node>:16110 status --scan
   git add params/mainnet.json artifacts/mainnet manifests/kachat-names-mainnet.json
   ```
   Commit, then push on the owner's OK.

## 3. After the genesis

- **Hand over the manifest:**
  - KQS: **Update** publishes `kachat-names-mainnet.json` to the mainnet indexer.
  - The apps: the manifest and template pins ship in their next release.
- **Prove the indexer** once it follows the registry:
  `kachat-names --network mainnet --node grpc://<own node>:16110 verify --live --indexer <mainnet indexer>`.
- **Mainnet vectors** for the apps: generate them from the deployed manifest, as on testnet.

## 4. Launch day

There is one gap at the start, `(00..00, ff..ff)`. Each registration splits a gap, so the first
registrations race for the same UTXO.

- **A losing registration reveals its name** (C3). The commit transaction is public, and so is the
  failed register. Someone watching can commit to the same name and register it in a later gap.
  - The app retries at once, against the gap that now holds the name's key (the owner chose
    this: no spacer names).
  - The commit stays valid, so the retry needs no new commit.
- Registration costs are the price as miner fee plus the network fee. For example, `a` for two
  years is exactly 5,000 KAS (4,000 KAS registration plus 1,000 KAS renewal). Mainnet relays it:
  there's no high-fee rule, and the 100k standard mass cap is lifted after Toccata.

## 5. Known limits (the app's side)

| # | Limit | The app |
|---|---|---|
| C1 | **A seller can accept an offer on a lapsed name, then reclaim it.** Script can't say "not after", so `accept` works after the name lapsed. The seller takes the offer, then reclaims the name at once. The buyer gets only the 1 KAS bond back. | Don't allow offers on names past `expiresAt`. Give every offer a `refundAfter` before its name's grace ends. Refund or withdraw open offers once their name enters grace. |
| C3 | Launch-day races reveal names (section 4). | Retry at once. |
| C4 | A v5 snapshot stays valid forever. After a migration, the sponsor (or the snapshot owner) can re-import a snapshot name its owner released in the new registry, back to that owner, until its old expiry. | Treat released snapshot names as reserved for their snapshot owner until their snapshot expiry. |
| C5 | Anyone can run `reclaim` and take its bounty (the freed gap value less the fee). | Expected. Say so in the UI. |
| C6 | An offer is bound to a seller key. If the name leaves the seller and comes back to them, the old offer can be accepted again. | Show only offers made since the current owner got the name. Remind buyers to withdraw. |
| C7 | The commit is signed with SIGHASH_ALL. | Sign the commit input with SIGHASH_ALL. |

## 6. If mainnet needs a change

Contracts are immutable and there's no upgrade key. A fix, a price change or any other baked value
means a new registry that imports a snapshot of this one: `docs/REGISTRY_V5.md` section 8.
