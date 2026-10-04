# Registry v3: adjustable prices (design, 2026-10-04)

**Status: design, waiting on the owner's answers in §7.** No contract code has been written yet.

**Owner's decision (2026-10-04):** prices can be changed, at most once every 30 days, with **no cap**
on how much a change moves them. Fees still go to miners, so nobody holds or receives funds.

## 1. Why v2 can't do this

In v2 the yearly prices are constructor constants:
- `price1..price5` in `KachatGap`, for registration;
- `renewPrice` tiers in `KachatName`, for extend and renew.

They are part of the template hash, and the registry covenant id commits to the templates. A live
registry's prices are therefore permanent, and that includes renewals of names already
registered.

A second registry is not a way out on mainnet either. Names are unique only within one registry,
so a second one could hand out `alice` again.

## 2. The price record

A new covenant template, **`KachatPrice`**, created at genesis inside the registry covenant, so it
shares the registry covenant id.

```
state:  shard     num8     0..K-1
        authority byte[32] x-only key allowed to change prices
        changedAt num8     unix ms of the last change (0 at genesis)
        reg1..reg5   num8  registration price per year, by name length 1/2/3/4/5+ (sompi)
        ren1..ren5   num8  extend/renew price per year, same tiers (sompi)
value:  exactly priceValue (a small constant, like gapValue)
```

**Shards.** A record has to be *spent* to be read: Kaspa has no read-only inputs. With one record,
every registration, extension and renewal in the world would queue behind the previous one. Genesis
therefore creates **K = 8 identical shards**. A transaction uses any one of them, and a price change
updates all of them in one transaction, so they can never disagree.

## 3. Entries

| Entry | Who | Rules |
|---|---|---|
| `use()` | anyone | Pass-through: exactly one authorized output, carrying the identical state and value. Spent alongside a register, extend or renew so those can read the prices. Harmless on its own: someone spending it in a loop only pays fees and slows that one shard |
| `setPrices(reg[5], ren[5], now, sig)` | `authority` | All K shards are inputs, and K outputs carry the same new prices. Also: `changedAt = now`; `tx.time >= now` (timestamp lock time, like renew); every price >= 0; plus the 30-day rule below |
| `setAuthority(newKey, sig)` | `authority` | All K shards, same prices, new `authority`. Allowed any time, so a key can be rotated |

**The 30-day rule** (`tx.time >= changedAt + 30 d`) applies to every price change (§7.2 asks
whether a decrease should be allowed any time).

## 4. What changes in the registry

- **`KachatGap.register`.** One more input: a `KachatPrice` shard.
  - The gap checks the shard's covenant id and template with `readInputStateWithTemplate`.
  - It takes `reg[len]` from that state in place of the baked `price1..5`.
  - The miner-fee rule stays the same: `Σin − Σout >= reg[len] · years`.
- **`KachatName.extend` and `.renew`.** Same, using `ren[len]`.
- **Unchanged:**
  - buy, list, transfer, offers, release and reclaim (they never charged the registry price);
  - the 2-year cap, the renewal window and grace;
  - state layouts, apart from the new record.
- **Transaction budgets** grow by one input and one output for register, extend and renew. The
  8-input / 8-output fee loop still covers them; to be re-measured.

## 5. Changing prices in practice

- **Only the CLI** (`kachat-names-cli set-prices`) changes prices. The app never holds the
  authority key.
- **The key** should be a dedicated key held cold, ideally on KasSigner. It shouldn't be the
  deployer's hot key, and never a wallet key.
- **Before applying,** the CLI shows the old and new tables, the dates and the cost, then a dry
  run, and only then sends.
- **The app** reads the current prices from a shard: from the indexer, or from its own chain
  walker. It always shows the price that will actually be charged.
- **The indexer** follows the shards and serves `GET /names/prices`, with the next allowed change
  date.

## 6. Risks and how they're handled

| Risk | Effect | Handling |
|---|---|---|
| **Authority key stolen** | The attacker could set prices so high that nobody can renew for up to 30 days. Names whose renewal deadline (expiry + 10-day grace) falls in that window would lapse | Keep the key cold (KasSigner). §7.2's option lets a bad *increase* be undone at once. `setAuthority` lets you move to a new key, but only while you still hold the old one |
| **Authority key lost** | Prices are frozen forever at the last setting | Back up the key the way you back up a seed. The registry keeps working at the last prices; nothing breaks |
| **A mistake (typo)** | Wrong prices for up to 30 days | The CLI's double confirmation, and §7.2 for increases |
| **Price set to 0** | Free names; squatting | Your call; the contract allows it, since there's no cap |
| **Shard contention** | Two users picking the same shard at the same moment: one has to retry | K = 8 shards; the app picks one at random and retries on conflict |

## 7. Questions for the owner

1. **Shards:** K = 8? More shards mean less queueing but a bigger price-change transaction.
2. **Decreases:** should a price *decrease* be allowed any time, with only *increases* limited to
   once per 30 days? There's still no cap. It means a mistaken or malicious increase can be
   reversed at once instead of standing for 30 days, and lowering prices never hurts anyone.
   *Recommended: yes.*
3. **Key:** a new dedicated price key held on KasSigner? *Recommended: yes.*
4. **Tables:** keep separate registration and renewal tables (more flexible), or one table used
   for both?

## 8. Work, in order

1. **Contracts:** `KachatPrice.sil`, plus the changes to gap and name. Then the harness tests
   (price input, shards, 30-day rule, authority, every entry against wrong shards, forged records
   and stale prices) and a fresh mutation check.
2. **CLI:**
   - genesis v3, which creates the gap and K shards;
   - `set-prices` and `set-authority`;
   - shard selection for register, extend and renew;
   - the test vectors.
3. **A new testnet registry (v3):** dry run, then the owner's "send it". v2 is then retired. Its
   test names are left behind, as v1's gap was.
4. **App:**
   - v3 transactions;
   - showing prices from the record;
   - shard retry on conflict.
5. **Indexer handoff:** follow the shards; `/names/prices`; the app contract update.
6. **Optional:** the short-clock rehearsal registry, to test expiry, renewal and price changes in
   days instead of years.
7. **Audit,** then the mainnet genesis on the owner's go-ahead.
