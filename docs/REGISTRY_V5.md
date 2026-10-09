# Registry v5: migration (2026-10-09)

Status:
- **Built and tested in-process.** The contract, harness, mutation check and CLI are done, and so
  is a full drill in the CLI's simulator.
- **Not deployed.** The next step is the testnet drill (section 6), after a dry run and the
  owner's "send it".

**Why.**
- A registry can't be upgraded: contracts are immutable, and there is no upgrade key, by design.
- So a fix, a price change or any other change to a baked value means a new registry.
- v5 is v4 plus the one thing that makes that safe: the new registry **imports a snapshot of the
  old one**, so every name keeps its owner and its paid period.

## 1. What changes from v4

Only the gap. The name and offer contracts are v4's, unchanged.

| | v4 | v5 |
|---|---|---|
| Gap source | `contracts/KachatGap.sil` | `contracts/v5/KachatGap.sil` |
| Gap size | 4,058 B (testnet) | 7,747 B: the 20-level proof loop and a second inlined name check |
| New constructor values | - | `snapshotRoot`, `snapshotDeadline`, `snapshotSponsor` (all read by the code; `tests/ctor_commitment.rs` checks they're committed) |
| `register` | as before | also refused while `now < snapshotDeadline` |
| `import` | - | new entry, dispatch tag `aa4cc365` |
| Entry tags `register` / `merge` / `absorbed` | `8667af5e` / `63d25bc2` / `dab76355` | unchanged |

**A registry with no predecessor** sets root 0 and deadline 0. Nothing can be imported, and
`register` works as in v4.

## 2. `import`

```
import(byte[] name, byte[32] owner, int periodStart, int expiresAt, int index, byte[] proof,
       bool bySponsor, sig authSig, byte[] namePrefix, byte[] nameSuffix)
[gap(lo, hi).import, funding..] -> [gap(lo, key), gap(key, hi), name, change]
```

**Same checks as register:**
- the gap is input 0, the only registry input;
- 3 registry outputs at 0..2, all authorized by the gap;
- name charset and length;
- `lo < blake3(name) < hi`;
- gap values and the bond.

**What import adds:**
- **The name output** is `(key, padded name, owner, price 0, periodStart, expiresAt)`: the snapshot
  owner and paid period, **unlisted**.
- **In the snapshot.** It hashes `blake3("kachat-snapshot-leaf:v1" ‖ key ‖ owner ‖
  periodStart as byte[8] ‖ expiresAt as byte[8])` up a 20-level path (`proof`: 640 bytes, the
  sibling at each level, leaf level first; bit *i* of `index` = right child at level *i*), and
  requires the result to equal `snapshotRoot`.
  - `0 <= index < 2^20`: a negative index would alias a leaf, so it's refused.
  - Proof length exactly 640.
- **Signed (SIGHASH_ALL)** by the snapshot owner, or by `snapshotSponsor` when `bySponsor`.
  - **Why signed:** script can say "not before" but never "not after", so the snapshot stays valid
    forever. If import were permissionless, anyone could push a name its owner later *released*
    back onto them until its old expiry. Requiring the owner or the sponsor prevents that.
  - **The sponsor's power** is only to re-create snapshot names *for their snapshot owners*. It
    can't choose owners, dates or names, and with `snapshotSponsor = 0` only owners import.
- **Date sanity:** `0 <= periodStart <= expiresAt <= 1e17`.
- **No commit, no price, no time lock.** The name is already someone's, and a front-runner can
  only import it for its own owner.

**Why `register` closes until the deadline, instead of proving non-membership.** The first design
made every registration during the window prove its name isn't in the snapshot: two Merkle paths
per registration, the most complex code in the design. Instead, `register` simply stays closed
until `snapshotDeadline`. The sponsor imports every name right after the genesis, so the window
is short: hours on testnet, days on mainnet. After the deadline, `register` works as in v4.

## 3. The snapshot

`tools/kachat-names-cli/src/snapshot.rs`, over `harness/src/snapshot.rs` (the contract's exact
rules).

```bash
kachat-names scan                       # the state up to the confirmed tip
kachat-names snapshot [--at <unix ms>]  # proves the state against a node, then writes the snapshot
kachat-names snapshot --check <file>    # anyone: rebuild the tree from the entries, match root + every proof
```

**Which names are kept:**
- **Kept:** every name **active or in grace** at `--at` (`at < expiresAt + graceMs`), with its
  owner, `periodStart` and `expiresAt`.
  - A name **in grace** stays in grace in v5, with the same countdown, and its owner renews there.
- **Left behind:** **lapsed** names (past grace).
  - They are free in v5 once `register` opens.
  - Their bonds aren't lost: `reclaim` in the old registry pays the bond to the last owner and the
    freed gap value to whoever runs it.

**Not carried:**
- **Listings:** price 0 in v5; owners relist.
- **Open offers:** they stay on the old registry, bound to it. They come back through `decline`,
  `withdraw` or `refund`.

**Trust.**
- `snapshot` refuses to write a file unless the scanned state is **exactly** the registry on
  chain (the `verify --live` completeness proof, run against a node first). A stale state would
  silently drop names; this was seen on 2026-10-09, when a timed-out scan left the state behind
  the chain.
- The file holds the predecessor registry id, the checkpoint, `atMs`, every entry with its proof,
  and the lapsed names left behind.
- Anyone can rebuild it from the chain, so a deployer can't add, drop or alter a name unseen.

**Leaves:** in key order from index 0; empty leaves are 32 zero bytes; a node is
`blake3(left ‖ right)`. Capacity is 1,048,576 names.

## 4. Params and manifest

```json
"registryVersion": 5,
"migration": {
  "predecessorRegistryId": "<old registry id>",
  "snapshot": "manifests/snapshots/<file>.json",
  "root": "<snapshot root>",
  "deadlineMs": <unix ms>,
  "sponsor": "<deployer x-only key>"
}
```

- **Build:** `scripts/build.py` compiles the v5 gap with these values. `build-info.json` carries
  the `migration` block, for v5 only.
- **Manifest:** a v5 manifest records `snapshot: {file, sha256, predecessorRegistryId, atMs,
  names}` and refuses a snapshot file whose root isn't `migration.root`.
- **`verify`** also compares `registryVersion` and `migration` with params.

## 5. Cost

Measured by the harness, testnet templates, 2026-10-09.

| | Size | Network fee | Compute budget |
|---|---|---|---|
| import (by owner or sponsor) | 12.1 kB | 0.024 KAS | gap.import 23 (~233k script units), funding 10 |
| v5 register (7 chars, 1 period) | 11.6 kB | 0.023 KAS | gap.register 11, commit 10, funding 10 |
| v4 register, for comparison | 7.9 kB | 0.016 KAS | gap.register 7 |

**Locked per imported name:** 2 KAS, the bond and one gap value. That's the same as a
registration, and both come back on `release`.

**The v5 gap makes every registration ~4 kB bigger** (every gap spend reveals the whole gap).
Trimming it is possible: the name check inlined twice, and the unrolled loop. That's an
optimisation for later, not a blocker.

## 6. The testnet drill

From the live day-clock v4 registry (`e6b72448…7f0d`) to a v5 testnet registry.

1. **Freeze the snapshot.**
   1. `kachat-names scan`.
   2. `kachat-names snapshot`. This is proven against the chain first.
   3. Commit `manifests/snapshots/<file>.json`.
2. **Prepare v5.**
   1. Archive the v4 manifest and state (`manifests/v4-day/`, `state/v4-day/`).
   2. Set params `registryVersion: 5`, the `migration` block (root from the file, deadline about
     6 h after the genesis on testnet, sponsor = the deployer's x-only key), and
     `registryCovenantId: null`.
   3. `./scripts/build.sh`.
3. **Genesis.**
   1. `kachat-names genesis` (dry run).
   2. **The owner says "send it"**, then `genesis --submit`.
   3. `./scripts/build.sh` (the offer), then commit.
4. **Import every name.**
   1. `kachat-names import-all` (dry run: the first import).
   2. `import-all --submit` imports each name, one transaction each, chained.
5. **Check.**
   - `kachat-names status`: every snapshot name, owner, `periodStart` and `expiresAt` equal to the
     snapshot, price 0.
   - `verify --live` passes on the v5 state.
   - `register` is refused before the deadline, and works after it.
   - A lapsed v4 name (if any) is registrable after the deadline.
6. **Clean up the old registry** (optional). `reclaim` lapsed v4 names, so their bonds go back to
   their owners. Owners can `release` their old copies for 2 KAS each.

**Funding.** About 2.03 TKAS per name (bond + gap + fee), plus about 1.002 TKAS for the genesis.
The deployer holds about 7.99 TKAS today, which covers roughly 3 names. Fund more if the snapshot
has more.

## 7. For the app (KaChat) and the indexer

Handoffs only; this repository changes neither.

**App:**
- **Pins:** new gap template hash per deployment (v5 testnet gap; name and offer as v4).
- **Import:** decode `import` (tag `aa4cc365`) in the chain walker: the same outputs as
  `register`, with the owner and dates from the arguments, price 0.
- **Register:** don't offer it, or show "opens at <deadline>", while `now < migration.deadlineMs`
  (the contract refuses it anyway).
- **Moving users over:** the bundled/served manifest switches to v5. Users' names appear with the
  same owner and expiry, unlisted.
- **Offers:** offers on the old registry should be returned (`decline` by the seller, or
  `withdraw` / `refund`), and old-registry offers hidden.
- **Optional:** a "release my old copies" action (2 KAS back per name).

**Indexer:**
- the follower must decode `import`;
- it must accept `registryVersion: 5` manifests with a `migration` block;
- it should serve `/names/all`, so `verify --live --indexer` can prove it.

## 8. Mainnet emergency runbook (outline)

1. **Decide the snapshot time.** Normally "now". If a bug was exploited, the last block before
   the exploit.
2. **Snapshot.** `scan`, then `snapshot --at <ms>`, publish the file, and let others run
   `snapshot --check` and rebuild it from the chain.
3. **Prepare the release.** v5 params (or a fixed v6 with the same import code), with a deadline
   a few days out.
4. **Audit, then deploy.** Audit the change, then a dry run and the owner's explicit go-ahead,
   then the genesis.
5. **Import.** `import-all`, sponsored. Users don't need to act.
6. **Switch the clients.** App and indexer releases pin the new registry.
