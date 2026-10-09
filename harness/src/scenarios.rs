//! Valid transactions for every entry, built the way the app will build them.
//! Attack tests start from one of these and change one thing.

use crate::*;
use secp256k1::Keypair;

/// DAA score at which test commit UTXOs were accepted.
pub const COMMIT_DAA: u64 = 500_000_000;
/// Wall-clock "now" used by registrations (2026-10-14, after the testnet v5
/// registry's import deadline of 2026-10-09 10:30 UTC), unix ms.
pub const NOW_MS: i64 = 1_792_000_000_000;
/// Network fee the scenarios leave on top of any price.
pub const NET_FEE: u64 = 1_000_000;
pub const COMMIT_VALUE: u64 = 20_000_000;
/// One paid period on the testnet-10 short clock (params/testnet10.json
/// `periodMs`, a day; the genesis tests check they agree).
pub const PERIOD: i64 = 86_400_000;
/// The testnet-10 renewal window: 2 hours before the expiry (`renewWindowMs`).
pub const RENEW_WINDOW: i64 = 7_200_000;
/// The testnet-10 grace after the expiry: 6 hours (`graceMs`).
pub const GRACE: i64 = 21_600_000;

pub fn kas(n: u64) -> u64 {
    n * SOMPI_PER_KAS
}

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

pub struct Reg {
    pub name: Vec<u8>,
    pub owner: Keypair,
    pub salt: [u8; 32],
    pub years: i64,
    pub now: i64,
    pub lo: [u8; 32],
    pub hi: [u8; 32],
    pub key: [u8; 32],
    pub spec: TxSpec,
    /// a block in which the registration is valid
    pub block: Block,
}

impl Reg {
    pub fn name_fields(&self, period_ms: i64) -> NameFields {
        NameFields::new(&self.name, &xonly(&self.owner), 0, self.now, self.now + self.years * period_ms)
    }

    /// Value left as miner fee by the scenario (the registration cost + NET_FEE).
    pub fn fee(&self) -> i64 {
        self.spec.fee()
    }

    /// Lower the change output so the fee grows by `delta` (or shrinks if negative).
    pub fn adjust_fee(&mut self, delta: i64) {
        let o = self.spec.outputs.last_mut().unwrap();
        o.value = (o.value as i64 - delta) as u64;
    }
}

pub fn register(kit: &Kit, name: &[u8], years: i64) -> Reg {
    register_in(kit, name, years, &ZERO32, &FF32)
}

pub fn register_in(kit: &Kit, name: &[u8], years: i64, lo: &[u8; 32], hi: &[u8; 32]) -> Reg {
    let p = &kit.params;
    let owner = keypair(1);
    let owner_x = xonly(&owner);
    let salt = [0x5au8; 32];
    let now = NOW_MS;
    let key = name_key(name);
    // registry v4: the first period at the registration price, the rest at the renewal price
    let price = p.register_cost(name.len(), years.max(1));

    let gap_in = Input::contract(
        kit.gap_utxo(lo, hi, 10),
        &kit.gap,
        gap_state(lo, hi),
        "register",
        vec![
            bytes(name),
            bytes(&owner_x),
            bytes(&salt),
            int(now),
            int(years),
            bytes(&kit.name.prefix),
            bytes(&kit.name.suffix),
        ],
    );
    let redeem = commit_redeem(&commitment(name, &owner_x, &salt), &owner_x);
    let commit_utxo = Utxo::new(
        TransactionOutpoint::new(TransactionId::from_bytes([11; 32]), 0),
        UtxoEntry::new(COMMIT_VALUE, pay_to_script_hash_script(&redeem), COMMIT_DAA, false, None),
    );
    let mut commit_in = Input::new(commit_utxo, Unlock::Commit { redeem, key: owner });
    commit_in.sequence = p.t_commit;
    let funding = kit.p2pk_utxo(&owner, price + p.bond + p.gap_value + kas(1), 12);

    let mut spec = TxSpec {
        inputs: vec![gap_in, commit_in, Input::new(funding, Unlock::P2pk(owner))],
        outputs: vec![
            kit.gap_output(lo, &key, 0),
            kit.gap_output(&key, hi, 0),
            kit.name_output(&NameFields::new(name, &owner_x, 0, now, now + years * p.period_ms), 0),
        ],
        lock_time: now as u64,
    };
    let change = spec.total_in() - spec.total_out() - price - NET_FEE;
    spec.outputs.push(TransactionOutput::new(change, p2pk_spk(&owner_x)));
    Reg {
        name: name.to_vec(),
        owner,
        salt,
        years,
        now,
        lo: *lo,
        hi: *hi,
        key,
        spec,
        block: Block { daa: COMMIT_DAA + p.t_commit, time_ms: now as u64 + 1 },
    }
}

// ---------------------------------------------------------------------------
// name entries
// ---------------------------------------------------------------------------

pub struct NameCase {
    pub fields: NameFields,
    pub owner: Keypair,
    pub utxo: Utxo,
}

/// A name registered at NOW_MS for one period (periodStart = NOW_MS,
/// expiresAt = NOW_MS + periodMs).
pub fn name_case(kit: &Kit, name: &[u8], price: i64) -> NameCase {
    let owner = keypair(1);
    let fields = NameFields::new(name, &xonly(&owner), price, NOW_MS, NOW_MS + kit.params.period_ms);
    let utxo = kit.name_utxo(&fields, 20);
    NameCase { fields, owner, utxo }
}

impl NameCase {
    /// The same name with another state (a fresh UTXO for it).
    pub fn with_fields(&self, kit: &Kit, fields: NameFields) -> NameCase {
        let utxo = kit.name_utxo(&fields, 20);
        NameCase { fields, owner: self.owner, utxo }
    }

    /// When renew opens: expiresAt - renewWindowMs (unix ms).
    pub fn window_opens(&self, kit: &Kit) -> i64 {
        self.fields.expires_at - kit.params.renew_window_ms
    }
}

/// A block well inside the name's paid period (10 s after NOW_MS: inside even
/// the testnet's 24-hour period).
pub fn active_block() -> Block {
    Block { daa: COMMIT_DAA + 10_000, time_ms: NOW_MS as u64 + 10_000 }
}

fn name_input(kit: &Kit, n: &NameCase, entry: &str, args: Vec<Arg>) -> Input {
    Input::contract(n.utxo.clone(), &kit.name, n.fields.encode(), entry, args)
}

pub fn transfer(kit: &Kit, n: &NameCase, new_owner: &[u8; 32]) -> TxSpec {
    let funding = kit.p2pk_utxo(&n.owner, kas(1), 21);
    let mut spec = TxSpec {
        inputs: vec![
            name_input(kit, n, "transfer", vec![bytes(new_owner), Arg::Sig(n.owner)]),
            Input::new(funding, Unlock::P2pk(n.owner)),
        ],
        outputs: vec![kit.name_output(&n.fields.with_owner(new_owner), 0)],
        lock_time: 0,
    };
    let change = spec.total_in() - spec.total_out() - NET_FEE;
    spec.outputs.push(TransactionOutput::new(change, p2pk_spk(&xonly(&n.owner))));
    spec
}

pub fn list(kit: &Kit, n: &NameCase, price: i64) -> TxSpec {
    let funding = kit.p2pk_utxo(&n.owner, kas(1), 21);
    let mut spec = TxSpec {
        inputs: vec![
            name_input(kit, n, "list", vec![int(price), Arg::Sig(n.owner)]),
            Input::new(funding, Unlock::P2pk(n.owner)),
        ],
        outputs: vec![kit.name_output(&n.fields.with_price(price), 0)],
        lock_time: 0,
    };
    let change = spec.total_in() - spec.total_out() - NET_FEE;
    spec.outputs.push(TransactionOutput::new(change, p2pk_spk(&xonly(&n.owner))));
    spec
}

/// The buyer (keypair 2) buys a listed name: [name.buy, buyer funding] ->
/// [continuation, payout to seller, buyer change].
pub fn buy(kit: &Kit, n: &NameCase) -> TxSpec {
    let buyer = keypair(2);
    let buyer_x = xonly(&buyer);
    let price = n.fields.price as u64;
    let funding = kit.p2pk_utxo(&buyer, price + kas(2), 22);
    let mut spec = TxSpec {
        inputs: vec![name_input(kit, n, "buy", vec![bytes(&buyer_x)]), Input::new(funding, Unlock::P2pk(buyer))],
        outputs: vec![
            kit.name_output(&n.fields.with_owner(&buyer_x), 0),
            TransactionOutput::new(price, p2pk_spk(&n.fields.owner)),
        ],
        lock_time: 0,
    };
    let change = spec.total_in() - spec.total_out() - NET_FEE;
    spec.outputs.push(TransactionOutput::new(change, p2pk_spk(&buyer_x)));
    spec
}

/// Anyone (keypair 3) pays `years` for a name with `entry` (extend or renew),
/// continuation `next`, lock time `lock_time`:
/// [name @0, funding @1] -> [continuation, change].
fn paid_entry(kit: &Kit, n: &NameCase, entry: &str, years: i64, next: NameFields, lock_time: u64) -> TxSpec {
    let payer = keypair(3);
    let price = kit.params.renew_price_for(name_len(&n.fields.name)) * years.max(0) as u64;
    let funding = kit.p2pk_utxo(&payer, price + kas(2), 23);
    let mut spec = TxSpec {
        inputs: vec![name_input(kit, n, entry, vec![int(years)]), Input::new(funding, Unlock::P2pk(payer))],
        outputs: vec![kit.name_output(&next, 0)],
        lock_time,
    };
    let change = spec.total_in() - spec.total_out() - price - NET_FEE;
    spec.outputs.push(TransactionOutput::new(change, p2pk_spk(&xonly(&payer))));
    spec
}

/// Anyone (keypair 3) extends the current period by `years`: no lock time;
/// the continuation keeps periodStart, expiresAt += years.
pub fn extend(kit: &Kit, n: &NameCase, years: i64) -> TxSpec {
    paid_entry(kit, n, "extend", years, n.fields.extended(years, kit.params.period_ms), 0)
}

/// Anyone (keypair 3) renews a name for `years`, with the lock time at the
/// opening of the renewal window (expiresAt - renewWindowMs, timestamp
/// domain; every input sequence 0, so not final until the median time
/// passes it): periodStart = the old expiry, expiresAt += years.
pub fn renew(kit: &Kit, n: &NameCase, years: i64) -> TxSpec {
    renew_at(kit, n, years, n.window_opens(kit) as u64)
}

/// [`renew`] with an explicit lock time.
pub fn renew_at(kit: &Kit, n: &NameCase, years: i64, lock_time: u64) -> TxSpec {
    paid_entry(kit, n, "renew", years, n.fields.renewed(years, kit.params.period_ms), lock_time)
}

/// A block whose past median time is `ms` + 1 (so a lock time of `ms` is final).
pub fn block_after(ms: i64) -> Block {
    Block { daa: COMMIT_DAA + 1_000_000, time_ms: ms as u64 + 1 }
}

/// The first block in which `renew(n)` (lock time = window opening) is final.
pub fn window_block(kit: &Kit, n: &NameCase) -> Block {
    block_after(n.window_opens(kit))
}

pub fn name_len(padded: &[u8; 32]) -> usize {
    padded.iter().position(|b| *b == 0).unwrap_or(32)
}

// ---------------------------------------------------------------------------
// the exit: merge @0, release | reclaim @1, absorbed @2
// ---------------------------------------------------------------------------

pub struct Exit {
    pub n: NameCase,
    pub lo: [u8; 32],
    pub hi: [u8; 32],
    pub spec: TxSpec,
    pub block: Block,
}

/// Name `name` sits between gaps (lo, key) and (key, hi).
fn exit_inputs(kit: &Kit, n: &NameCase, lo: &[u8; 32], hi: &[u8; 32], entry: &str, args: Vec<Arg>) -> Vec<Input> {
    let key = n.fields.key;
    vec![
        Input::contract(kit.gap_utxo(lo, &key, 30), &kit.gap, gap_state(lo, &key), "merge", vec![]),
        name_input(kit, n, entry, args),
        Input::contract(kit.gap_utxo(&key, hi, 31), &kit.gap, gap_state(&key, hi), "absorbed", vec![]),
    ]
}

pub fn neighbours(key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut lo = *key;
    let mut hi = *key;
    // strictly below / above the key (the test names never hash to 00.. or ff..)
    for i in (0..32).rev() {
        if lo[i] > 0 {
            lo[i] -= 1;
            break;
        }
        lo[i] = 0xff;
    }
    for i in (0..32).rev() {
        if hi[i] < 0xff {
            hi[i] += 1;
            break;
        }
        hi[i] = 0;
    }
    (lo, hi)
}

/// The owner releases: [merge, release(sig), absorbed] -> [merged gap, owner change].
pub fn release(kit: &Kit, name: &[u8]) -> Exit {
    let n = name_case(kit, name, 0);
    let (lo, hi) = neighbours(&n.fields.key);
    let mut spec = TxSpec {
        inputs: exit_inputs(kit, &n, &lo, &hi, "release", vec![Arg::Sig(n.owner)]),
        outputs: vec![kit.gap_output(&lo, &hi, 0)],
        lock_time: 0,
    };
    let change = spec.total_in() - spec.total_out() - NET_FEE;
    spec.outputs.push(TransactionOutput::new(change, p2pk_spk(&n.fields.owner)));
    Exit { n, lo, hi, spec, block: active_block() }
}

/// Anyone (keypair 4) reclaims a lapsed name: [merge, reclaim(), absorbed] ->
/// [merged gap, bond to the last owner, caller's bounty]; lock time =
/// expiresAt + grace (timestamp domain).
pub fn reclaim(kit: &Kit, name: &[u8]) -> Exit {
    let n = name_case(kit, name, 0);
    let (lo, hi) = neighbours(&n.fields.key);
    let caller = keypair(4);
    let unlock_at = (n.fields.expires_at + kit.params.grace_ms) as u64;
    let mut spec = TxSpec {
        inputs: exit_inputs(kit, &n, &lo, &hi, "reclaim", vec![]),
        outputs: vec![kit.gap_output(&lo, &hi, 0), TransactionOutput::new(kit.params.bond, p2pk_spk(&n.fields.owner))],
        lock_time: unlock_at,
    };
    let bounty = spec.total_in() - spec.total_out() - NET_FEE;
    spec.outputs.push(TransactionOutput::new(bounty, p2pk_spk(&xonly(&caller))));
    Exit { n, lo, hi, spec, block: Block { daa: COMMIT_DAA + 1_000_000, time_ms: unlock_at + 1 } }
}

// ---------------------------------------------------------------------------
// offers
// ---------------------------------------------------------------------------

pub struct OfferCase {
    pub n: NameCase,
    pub buyer: Keypair,
    pub fields: OfferFields,
    pub value: u64,
    pub utxo: Utxo,
}

pub const OFFER_REFUND_AFTER: i64 = COMMIT_DAA as i64 + 100_000;

/// An offer by keypair 2 for `name`, made to its current owner (keypair 1).
pub fn offer_case(kit: &Kit, name: &[u8], value: u64) -> OfferCase {
    let n = name_case(kit, name, 0);
    let buyer = keypair(2);
    let fields = OfferFields { key: n.fields.key, buyer: xonly(&buyer), seller: n.fields.owner, refund_after: OFFER_REFUND_AFTER };
    let utxo = kit.offer_utxo(&fields, value, 40);
    OfferCase { n, buyer, fields, value, utxo }
}

pub fn offer_input(kit: &Kit, o: &OfferCase, entry: &str, args: Vec<Arg>) -> Input {
    Input::contract(o.utxo.clone(), &kit.offer, o.fields.encode(), entry, args)
}

/// The owner (the seller) accepts: [name.transfer(buyer, ownerSig) @0,
/// offer.accept(0, sellerSig) @1] -> [continuation to the buyer, payout to the owner].
pub fn accept(kit: &Kit, o: &OfferCase) -> TxSpec {
    TxSpec {
        inputs: vec![
            name_input(kit, &o.n, "transfer", vec![bytes(&o.fields.buyer), Arg::Sig(o.n.owner)]),
            offer_input(kit, o, "accept", vec![int(0), Arg::Sig(o.n.owner)]),
        ],
        outputs: vec![
            kit.name_output(&o.n.fields.with_owner(&o.fields.buyer), 0),
            TransactionOutput::new(o.value - NET_FEE, p2pk_spk(&o.n.fields.owner)),
        ],
        lock_time: 0,
    }
}

pub fn withdraw(kit: &Kit, o: &OfferCase) -> TxSpec {
    TxSpec {
        inputs: vec![offer_input(kit, o, "withdraw", vec![Arg::Sig(o.buyer)])],
        outputs: vec![TransactionOutput::new(o.value - NET_FEE, p2pk_spk(&o.fields.buyer))],
        lock_time: 0,
    }
}

/// The seller declines (registry v3): [offer.decline(sellerSig)] -> [back to the buyer].
pub fn decline(kit: &Kit, o: &OfferCase) -> TxSpec {
    TxSpec {
        inputs: vec![offer_input(kit, o, "decline", vec![Arg::Sig(o.n.owner)])],
        outputs: vec![TransactionOutput::new(o.value - NET_FEE, p2pk_spk(&o.fields.buyer))],
        lock_time: 0,
    }
}

/// Anyone refunds: lock time = refundAfter (DAA domain).
pub fn refund(kit: &Kit, o: &OfferCase) -> TxSpec {
    TxSpec {
        inputs: vec![offer_input(kit, o, "refund", vec![])],
        outputs: vec![TransactionOutput::new(o.value - NET_FEE, p2pk_spk(&o.fields.buyer))],
        lock_time: o.fields.refund_after as u64,
    }
}

pub fn refund_block(o: &OfferCase) -> Block {
    Block { daa: o.fields.refund_after as u64 + 1, time_ms: NOW_MS as u64 }
}

// ---------------------------------------------------------------------------
// assertions
// ---------------------------------------------------------------------------

/// Build, validate, and require success. Also checks that every input runs
/// under its committed compute budget.
pub fn ok(kit: &Kit, spec: &TxSpec, block: Block) -> Built {
    let built = kit.build(spec);
    for (i, r) in built.run_inputs().into_iter().enumerate() {
        if let Err(e) = r {
            panic!("input {i} failed: {e:?}");
        }
    }
    if let Err(e) = kit.validate(&built, block) {
        panic!("expected a valid transaction, got {e}");
    }
    built
}

/// Build and require that full consensus validation rejects it.
pub fn rejected(kit: &Kit, spec: &TxSpec, block: Block) -> String {
    let built = kit.build(spec);
    match kit.validate(&built, block) {
        Ok(_) => panic!("expected a rejection, but the transaction is valid"),
        Err(e) => e,
    }
}

/// Build and require that input `idx` fails its script, and that the whole
/// transaction is rejected. Returns the script error.
pub fn input_fails(kit: &Kit, spec: &TxSpec, block: Block, idx: usize) -> TxScriptError {
    let built = kit.build(spec);
    let res = built.run_inputs();
    let err = match &res[idx] {
        Ok(_) => panic!("expected input {idx} to fail, but it succeeded (all: {res:?})"),
        Err(e) => e.clone(),
    };
    assert!(
        !matches!(err, TxScriptError::ExceededCommittedScriptUnits { .. }),
        "input {idx} failed only on its compute budget: {err:?}"
    );
    assert!(kit.validate(&built, block).is_err(), "input {idx} fails but consensus accepted the transaction");
    err
}

// ---------------------------------------------------------------------------
// registry v5: import from a migration snapshot
// ---------------------------------------------------------------------------

/// A snapshot name for the tests: its name, owner and paid period.
pub struct SnapName {
    pub name: Vec<u8>,
    pub owner: Keypair,
    pub period_start: i64,
    pub expires_at: i64,
}

impl SnapName {
    pub fn new(name: &[u8], owner_seed: u8, period_start: i64, expires_at: i64) -> SnapName {
        SnapName { name: name.to_vec(), owner: keypair(owner_seed), period_start, expires_at }
    }

    pub fn entry(&self) -> crate::snapshot::Entry {
        crate::snapshot::Entry { key: name_key(&self.name), owner: xonly(&self.owner), period_start: self.period_start, expires_at: self.expires_at }
    }

    pub fn fields(&self) -> NameFields {
        NameFields::new(&self.name, &xonly(&self.owner), 0, self.period_start, self.expires_at)
    }
}

/// The sponsor of the test migrations (`Migration::sponsor`).
pub fn sponsor() -> Keypair {
    keypair(90)
}

/// A v5 kit whose snapshot holds `names`, with the test sponsor and `deadline_ms`.
pub fn v5_kit(names: &[SnapName], deadline_ms: i64) -> (Kit, crate::snapshot::Snapshot) {
    let snap = crate::snapshot::Snapshot::new(names.iter().map(SnapName::entry).collect());
    let kit = Kit::v5(Migration { root: snap.root(), deadline_ms, sponsor: xonly(&sponsor()) });
    (kit, snap)
}

/// What an import claims (defaults: the snapshot's own values).
#[derive(Clone)]
pub struct ImportArgs {
    pub name: Vec<u8>,
    pub owner: [u8; 32],
    pub period_start: i64,
    pub expires_at: i64,
    pub index: i64,
    pub proof: Vec<u8>,
    pub by_sponsor: bool,
    pub signer: Keypair,
}

impl ImportArgs {
    /// `n` imported by its owner (`by_sponsor` false) or by the sponsor.
    pub fn of(snap: &crate::snapshot::Snapshot, n: &SnapName, by_sponsor: bool) -> ImportArgs {
        let index = snap.index_of(&name_key(&n.name)).expect("in the snapshot");
        ImportArgs {
            name: n.name.clone(),
            owner: xonly(&n.owner),
            period_start: n.period_start,
            expires_at: n.expires_at,
            index: index as i64,
            proof: snap.proof(index),
            by_sponsor,
            signer: if by_sponsor { sponsor() } else { n.owner },
        }
    }
}

/// [gap.import, funding] -> [gap (lo, key), gap (key, hi), name, change], in
/// the gap (lo, hi). The name output carries `out` (default: the claimed
/// owner and period, price 0).
pub fn import_in(kit: &Kit, a: &ImportArgs, lo: &[u8; 32], hi: &[u8; 32], out: Option<NameFields>) -> TxSpec {
    let key = name_key(&a.name);
    let gap_in = Input::contract(
        kit.gap_utxo(lo, hi, 10),
        &kit.gap,
        gap_state(lo, hi),
        "import",
        vec![
            bytes(&a.name),
            bytes(&a.owner),
            int(a.period_start),
            int(a.expires_at),
            int(a.index),
            bytes(&a.proof),
            Arg::V(ArtifactValue::Bool(a.by_sponsor)),
            Arg::Sig(a.signer),
            bytes(&kit.name.prefix),
            bytes(&kit.name.suffix),
        ],
    );
    let payer = a.signer;
    let funding = kit.p2pk_utxo(&payer, kit.params.bond + kit.params.gap_value + kas(1), 12);
    let fields = out.unwrap_or_else(|| NameFields::new(&a.name, &a.owner, 0, a.period_start, a.expires_at));
    let mut spec = TxSpec {
        inputs: vec![gap_in, Input::new(funding, Unlock::P2pk(payer))],
        outputs: vec![kit.gap_output(lo, &key, 0), kit.gap_output(&key, hi, 0), kit.name_output(&fields, 0)],
        lock_time: 0,
    };
    let change = spec.total_in() - spec.total_out() - NET_FEE;
    spec.outputs.push(TransactionOutput::new(change, p2pk_spk(&xonly(&payer))));
    spec
}

/// Import `a` in the genesis gap.
pub fn import(kit: &Kit, a: &ImportArgs) -> TxSpec {
    import_in(kit, a, &ZERO32, &FF32, None)
}
