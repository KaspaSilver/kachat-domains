//! The CLI's transaction builders against synthetic UTXOs: every command's
//! dry-run transaction must pass rusty-kaspa's consensus validator (the same
//! harness kit the contract tests use), have exactly the README shape, and
//! move the decoded registry state the way the contracts do.

use kachat_names_cli::{
    commits::CommitRec,
    net::parse_owner_address,
    ops::{self, Env, ExitParts, Templates},
    paths::Paths,
    plan::{self, PLANNED_FUNDING, Sim, Step},
    registry::{GapRec, NameRec, OfferRec, Registry, TxView},
    util::SOMPI,
};
use kachat_names_harness::{
    Block, FF32, Kit, NameFields, OfferFields, TransactionId, TransactionOutpoint, TransactionOutput, Utxo, UtxoEntry, YEAR_MS, ZERO32,
    commit_redeem, commitment, gap_state, keypair, name_key, p2pk_spk,
    scenarios::{self, COMMIT_DAA, NOW_MS, active_block, neighbours},
    xonly,
};
use kaspa_txscript::pay_to_script_hash_script;

fn templates() -> Templates {
    Templates::load(&Paths::find(None).unwrap().root)
}

/// An Env on the harness's own test registry (Kit::new()), deployer = the
/// harness scenarios' owner (keypair 1), so CLI transactions can be compared
/// with the harness scenarios field by field.
fn harness_env(block: Block) -> Env {
    Env { kit: Kit::new(), deployer: keypair(1), block, wall_ms: NOW_MS + 180_000, feerate: ops::MIN_FEERATE }
}

fn wallet(env: &Env, kas: u64, n: u8) -> Vec<Utxo> {
    (0..n)
        .map(|i| {
            Utxo::new(
                TransactionOutpoint::new(TransactionId::from_bytes([0xc0 + i; 32]), i as u32),
                UtxoEntry::new(kas * SOMPI, p2pk_spk(&env.me()), COMMIT_DAA - 1000, false, None),
            )
        })
        .collect()
}

fn reg_utxo(env: &Env, spk: kaspa_consensus_core::tx::ScriptPublicKey, value: u64, tag: u8) -> Utxo {
    Utxo::new(
        TransactionOutpoint::new(TransactionId::from_bytes([tag; 32]), 0),
        UtxoEntry::new(value, spk, COMMIT_DAA - 500, false, Some(env.kit.registry_id)),
    )
}

fn assert_valid(p: &ops::Plan) {
    if let Err(e) = &p.validation {
        panic!("{}: rejected: {e}", p.op);
    }
    p.standard.as_ref().unwrap();
    // every input runs under its committed compute budget
    for (i, r) in p.built.run_inputs().into_iter().enumerate() {
        r.unwrap_or_else(|e| panic!("{}: input {i}: {e:?}", p.op));
    }
    // the fee the validator computes is exactly price + network fee, and pays the relay floor
    let fee = *p.validation.as_ref().unwrap();
    assert_eq!(fee, p.price_fee + p.network_fee, "{}", p.op);
    assert!(p.network_fee >= p.costs.min_fee, "{}: network fee {} below the floor {}", p.op, p.network_fee, p.costs.min_fee);
}

fn name_rec(env: &Env, name: &str, owner: &[u8; 32], price: i64, tag: u8) -> (NameRec, Utxo) {
    let fields = NameFields::new(name.as_bytes(), owner, price, NOW_MS, NOW_MS + YEAR_MS);
    let u = reg_utxo(env, env.kit.name.spk(&fields.encode()), env.kit.params.bond, tag);
    (NameRec { outpoint: u.outpoint, fields, value: env.kit.params.bond }, u)
}

// ---------------------------------------------------------------------------
// shapes vs the harness scenarios
// ---------------------------------------------------------------------------

#[test]
fn register_matches_the_harness_scenario_shape() {
    let r = scenarios::register(&Kit::new(), b"alice", 1);
    let env = harness_env(r.block);
    let me = env.me();
    let gap = GapRec { outpoint: r.spec.inputs[0].utxo.outpoint, lo: ZERO32, hi: FF32, value: env.kit.params.gap_value };
    let gap_utxo = r.spec.inputs[0].utxo.clone();
    let commit_utxo = r.spec.inputs[1].utxo.clone();
    let c = CommitRec {
        name: "alice".into(),
        owner: me,
        salt: r.salt,
        value: commit_utxo.entry.amount,
        outpoint: Some(commit_utxo.outpoint),
        used_by: None,
        created_ms: 0,
    };
    let p = ops::register(&env, &wallet(&env, 100, 1), &gap, &gap_utxo, &c, &commit_utxo, 1, r.now).unwrap();
    assert_valid(&p);
    let tx = &p.built.tx;
    // the registry part is byte-identical to the harness scenario: outputs
    // 0..2, input 0's whole signature script (no signature in it), lock
    // time, sequences
    let h = Kit::new().build(&r.spec).tx;
    assert_eq!(tx.outputs[..3], h.outputs[..3]);
    assert_eq!(tx.inputs[0].signature_script, h.inputs[0].signature_script);
    assert_eq!(tx.lock_time, r.now as u64);
    assert_eq!((tx.inputs[0].sequence, tx.inputs[1].sequence, tx.inputs[2].sequence), (0, 600, 0));
    assert_eq!(tx.version, 1);
    assert_eq!(p.price_fee, 35 * SOMPI);
    assert_eq!(tx.payload, b"kchat:1:name:register:alice");
    // change back to the owner at output 3
    assert_eq!(tx.outputs.len(), 4);
    assert_eq!(tx.outputs[3].script_public_key, p2pk_spk(&me));
}

#[test]
fn register_waits_for_commit_maturity() {
    let r = scenarios::register(&Kit::new(), b"alice", 1);
    let early = Block { daa: r.block.daa - 1, ..r.block };
    let env = harness_env(early);
    let gap = GapRec { outpoint: r.spec.inputs[0].utxo.outpoint, lo: ZERO32, hi: FF32, value: SOMPI };
    let cu = r.spec.inputs[1].utxo.clone();
    let c = CommitRec { name: "alice".into(), owner: env.me(), salt: r.salt, value: cu.entry.amount, outpoint: Some(cu.outpoint), used_by: None, created_ms: 0 };
    let p = ops::register(&env, &wallet(&env, 100, 1), &gap, &r.spec.inputs[0].utxo, &c, &cu, 1, r.now).unwrap();
    let e = p.validation.unwrap_err();
    assert!(e.contains("sequence") || e.to_lowercase().contains("lock"), "{e}");
    assert!(p.notes.iter().any(|n| n.contains("not mature")));
}

#[test]
fn register_refuses_a_name_outside_the_gap_and_bad_years() {
    let r = scenarios::register(&Kit::new(), b"alice", 1);
    let env = harness_env(r.block);
    let key = name_key(b"alice");
    let (lo, _) = neighbours(&key);
    let gap = GapRec { outpoint: r.spec.inputs[0].utxo.outpoint, lo: ZERO32, hi: lo, value: SOMPI };
    let cu = r.spec.inputs[1].utxo.clone();
    let c = CommitRec { name: "alice".into(), owner: env.me(), salt: r.salt, value: cu.entry.amount, outpoint: Some(cu.outpoint), used_by: None, created_ms: 0 };
    let w = wallet(&env, 100, 1);
    assert!(ops::register(&env, &w, &gap, &r.spec.inputs[0].utxo, &c, &cu, 1, r.now).is_err());
    let gap = GapRec { hi: FF32, ..gap };
    assert!(ops::register(&env, &w, &gap, &r.spec.inputs[0].utxo, &c, &cu, 0, r.now).is_err());
    assert!(ops::register(&env, &w, &gap, &r.spec.inputs[0].utxo, &c, &cu, 3, r.now).is_err());
}

#[test]
fn register_respects_the_8_input_bound() {
    // the deployer's money split over many small UTXOs: the builder may use
    // at most 6 funding inputs (gap + commit + 6 = 8)
    let r = scenarios::register(&Kit::new(), b"alice", 2);
    let env = harness_env(r.block);
    let gap = GapRec { outpoint: r.spec.inputs[0].utxo.outpoint, lo: ZERO32, hi: FF32, value: SOMPI };
    let cu = r.spec.inputs[1].utxo.clone();
    let c = CommitRec { name: "alice".into(), owner: env.me(), salt: r.salt, value: cu.entry.amount, outpoint: Some(cu.outpoint), used_by: None, created_ms: 0 };
    let w = wallet(&env, 12, 10); // 120 TKAS in 12-TKAS pieces; 70 + 2 needed
    let p = ops::register(&env, &w, &gap, &r.spec.inputs[0].utxo, &c, &cu, 2, r.now).unwrap();
    assert_valid(&p);
    assert!(p.built.tx.inputs.len() <= 8);
    let tiny = wallet(&env, 10, 10); // 6 x 10 = 60 < 72
    let err = ops::register(&env, &tiny, &gap, &r.spec.inputs[0].utxo, &c, &cu, 2, r.now).err().unwrap().to_string();
    assert!(err.contains("insufficient") && err.contains("at most 6"), "{err}");
}

#[test]
fn name_entries_pass_the_validator() {
    let env = harness_env(active_block());
    let me = env.me();
    let w = wallet(&env, 200, 2);
    let (n, u) = name_rec(&env, "alice", &me, 0, 30);

    let p = ops::extend(&env, &w, &n, &u, 1).unwrap();
    assert_valid(&p);
    assert_eq!(p.price_fee, 35 * SOMPI);
    assert_eq!(p.built.tx.payload, b"kchat:1:name:extend:alice");
    assert_eq!(p.built.tx.lock_time, 0);
    let p = ops::transfer(&env, &w, &n, &u, &xonly(&keypair(9))).unwrap();
    assert_valid(&p);
    assert_eq!(p.built.tx.payload, b"kchat:1:name:transfer:alice");
    let p = ops::list(&env, &w, &n, &u, 50 * SOMPI).unwrap();
    assert_valid(&p);
    assert_eq!(p.built.tx.payload, b"kchat:1:name:list:alice");
    // buying needs a listed name; the payout is output 1, right after the continuation
    assert!(ops::buy(&env, &w, &n, &u).is_err());
    let (listed, lu) = name_rec(&env, "alice", &xonly(&keypair(5)), 50 * SOMPI as i64, 31);
    let p = ops::buy(&env, &w, &listed, &lu).unwrap();
    assert_valid(&p);
    assert_eq!(p.built.tx.outputs[1].script_public_key, p2pk_spk(&xonly(&keypair(5))));
    assert_eq!(p.built.tx.outputs[1].value, 50 * SOMPI);
    assert_eq!(p.built.tx.payload, b"kchat:1:name:buy:alice");
}

#[test]
fn owner_entries_refuse_names_the_deployer_does_not_own() {
    let env = harness_env(active_block());
    let w = wallet(&env, 50, 1);
    let (n, u) = name_rec(&env, "alice", &xonly(&keypair(5)), 0, 30);
    assert!(ops::transfer(&env, &w, &n, &u, &env.me()).is_err());
    assert!(ops::list(&env, &w, &n, &u, SOMPI).is_err());
    // extend and renew are anyone's (gifts)
    assert_valid(&ops::extend(&env, &w, &n, &u, 1).unwrap());
    let opens = n.fields.expires_at - env.kit.params.renew_window_ms;
    let in_window = Env { block: Block { daa: env.block.daa, time_ms: opens as u64 + 60_000 }, wall_ms: opens + 300_000, ..harness_env(active_block()) };
    assert_valid(&ops::renew(&in_window, &w, &n, &u, 1).unwrap());
}

// ---------------------------------------------------------------------------
// extend and renew (registry v2)
// ---------------------------------------------------------------------------

/// An Env whose median time is `median` and wall clock `median + 132 s`.
fn env_at(median: i64) -> Env {
    Env { block: Block { daa: active_block().daa, time_ms: median as u64 }, wall_ms: median + 132_000, ..harness_env(active_block()) }
}

#[test]
fn extend_is_capped_at_max_years_past_period_start() {
    let env = harness_env(active_block());
    let w = wallet(&env, 200, 2);
    let (n, u) = name_rec(&env, "alice", &env.me(), 0, 30);
    assert_eq!(ops::extendable_years(&env.kit.params, &n.fields), 1);
    let p = ops::extend(&env, &w, &n, &u, 1).unwrap();
    assert_valid(&p);
    let next = n.fields.extended(1);
    assert_eq!(p.built.tx.outputs[0].script_public_key, env.kit.name.spk(&next.encode()));
    assert_eq!((next.period_start, next.expires_at), (NOW_MS, NOW_MS + 2 * YEAR_MS));
    assert_eq!(p.built.tx.inputs[0].sequence, 0);
    // 2 years from a 1-year registration, or anything once paid 2 years ahead: refused with the reason
    let err = ops::extend(&env, &w, &n, &u, 2).err().unwrap().to_string();
    assert!(err.contains("refused") && err.contains("1 y can be added now"), "{err}");
    let two = NameRec { fields: next.clone(), ..n.clone() };
    let u2 = reg_utxo(&env, env.kit.name.spk(&next.encode()), env.kit.params.bond, 31);
    assert_eq!(ops::extendable_years(&env.kit.params, &next), 0);
    let err = ops::extend(&env, &w, &two, &u2, 1).err().unwrap().to_string();
    assert!(err.contains("0 y can be added now") && err.contains("renew opens"), "{err}");
    assert!(ops::extend(&env, &w, &n, &u, 0).is_err());
    assert!(ops::extend(&env, &w, &n, &u, 3).is_err());
}

#[test]
fn renew_waits_for_its_window() {
    let base = harness_env(active_block());
    let w = wallet(&base, 200, 2);
    let (n, u) = name_rec(&base, "alice", &base.me(), 0, 30);
    let opens = ops::renew_opens(&base.kit.params, &n.fields);
    assert_eq!(opens, n.fields.expires_at - 10 * 86_400_000);

    // long before the window: built, but not final (lock time = the window
    // opening, above the median time), with a note saying when it opens
    let p = ops::renew(&base, &w, &n, &u, 1).unwrap();
    assert!(!ops::renew_window_open(&base, &n.fields));
    assert_eq!(p.built.tx.lock_time as i64, opens);
    let e = p.validation.as_ref().unwrap_err();
    assert!(e.contains("finalized"), "{e}");
    assert!(p.notes.iter().any(|x| x.contains("renewal window not open")), "{:?}", p.notes);
    // one millisecond before it opens (median time == opening): still not final
    let p = ops::renew(&env_at(opens), &w, &n, &u, 1).unwrap();
    assert!(p.validation.is_err());

    // right after it opens: the wall clock - 3 min is still before the
    // opening, so the lock time is the opening itself, and it is final
    let env = env_at(opens + 1);
    assert!(ops::renew_window_open(&env, &n.fields));
    let p = ops::renew(&env, &w, &n, &u, 1).unwrap();
    assert_valid(&p);
    assert_eq!(p.built.tx.lock_time as i64, opens);
    // a day into the window: lock time = wall clock - 3 min
    let env = env_at(opens + 86_400_000);
    let p = ops::renew(&env, &w, &n, &u, 2).unwrap();
    assert_valid(&p);
    assert_eq!(p.built.tx.lock_time as i64, ops::register_now(&env));
    assert_eq!(p.price_fee, 70 * SOMPI);
    assert_eq!(p.built.tx.payload, b"kchat:1:name:renew:alice");
    // every input non-final (sequence 0), as the CLTV needs
    assert!(p.built.tx.inputs.iter().all(|i| i.sequence == 0));
    let next = n.fields.renewed(2);
    assert_eq!(p.built.tx.outputs[0].script_public_key, env.kit.name.spk(&next.encode()));
    assert_eq!((next.period_start, next.expires_at), (NOW_MS + YEAR_MS, NOW_MS + 3 * YEAR_MS));
    // in grace and long after lapse
    for t in [n.fields.expires_at + 1, n.fields.expires_at + env.kit.params.grace_ms + 1, n.fields.expires_at + 5 * YEAR_MS] {
        assert_valid(&ops::renew(&env_at(t), &w, &n, &u, 1).unwrap());
    }
}

#[test]
fn the_decoder_follows_extend_and_renew() {
    let env = harness_env(active_block());
    let w = wallet(&env, 200, 2);
    let (n, u) = name_rec(&env, "alice", &env.me(), 0, 30);
    let mut reg = Registry::at_genesis(env.kit.registry_id, TransactionId::from_bytes([1; 32]), SOMPI, None);
    reg.names.push(n.clone());
    // extend: periodStart kept
    let p = ops::extend(&env, &w, &n, &u, 1).unwrap();
    let ev = reg.apply(&env.kit, &TxView::from(&p.built.tx)).unwrap();
    assert!(ev[0].starts_with("extend alice by 1 y"), "{ev:?}");
    let a = reg.name("alice").unwrap().clone();
    assert_eq!((a.fields.period_start, a.fields.expires_at), (NOW_MS, NOW_MS + 2 * YEAR_MS));
    assert_eq!(a.outpoint, TransactionOutpoint::new(p.txid(), 0));
    // renew in the window: a new period from the old expiry
    let au = Utxo::new(a.outpoint, UtxoEntry::new(SOMPI, env.kit.name.spk(&a.fields.encode()), COMMIT_DAA, false, Some(env.kit.registry_id)));
    let later = env_at(a.fields.expires_at - 86_400_000);
    let p = ops::renew(&later, &w, &a, &au, 1).unwrap();
    assert_valid(&p);
    let ev = reg.apply(&env.kit, &TxView::from(&p.built.tx)).unwrap();
    assert!(ev[0].starts_with("renew alice by 1 y"), "{ev:?}");
    let r = reg.name("alice").unwrap();
    assert_eq!((r.fields.period_start, r.fields.expires_at), (NOW_MS + 2 * YEAR_MS, NOW_MS + 3 * YEAR_MS));
    // a forged continuation that keeps the old periodStart under renew is refused
    let mut forged = TxView::from(&p.built.tx);
    let f = a.fields.extended(1);
    forged.id = TransactionId::from_bytes([9; 32]);
    forged.outputs[0] = TransactionOutput::with_covenant(SOMPI, env.kit.name.spk(&f.encode()), forged.outputs[0].covenant);
    let mut fresh = Registry::at_genesis(env.kit.registry_id, TransactionId::from_bytes([1; 32]), SOMPI, None);
    fresh.names.push(a.clone());
    assert!(fresh.apply(&env.kit, &forged).is_err());
    // the 126-byte state decodes back, periodStart included
    let back = kachat_names_cli::registry::decode_name_state(&r.fields.encode()).unwrap();
    assert_eq!(&back, &r.fields);
    assert!(kachat_names_cli::registry::decode_name_state(&r.fields.encode()[..117]).is_err());
}

#[test]
fn offers_pass_the_validator() {
    let env = harness_env(active_block());
    let me = env.me();
    let w = wallet(&env, 50, 1);
    let (n, nu) = name_rec(&env, "alice", &me, 0, 30);
    let refund_after = active_block().daa + 600;

    let p = ops::offer(&env, &w, "alice", 10 * SOMPI, refund_after, Some(&n)).unwrap();
    assert_valid(&p);
    let o: OfferRec = p.new_offer.clone().unwrap();
    assert_eq!(o.outpoint, TransactionOutpoint::new(p.txid(), 0));
    // the payload marker the indexer (and `scan`) find offers by
    let marker = format!("kchat:1:offer:{}:{}:{refund_after}", faster_hex::hex_string(&o.fields.key), faster_hex::hex_string(&me));
    assert_eq!(p.built.tx.payload, marker.as_bytes());
    let found = kachat_names_cli::registry::offer_from_marker(&env.kit, &TxView::from(&p.built.tx)).unwrap();
    assert_eq!(found, (0, o.fields.clone()));
    // a marker that matches no output is ignored
    let mut lying = TxView::from(&p.built.tx);
    lying.payload = format!("kchat:1:offer:{}:{}:{}", faster_hex::hex_string(&o.fields.key), faster_hex::hex_string(&me), refund_after + 1).into_bytes();
    assert!(kachat_names_cli::registry::offer_from_marker(&env.kit, &lying).is_none());
    let ou = Utxo::new(o.outpoint, UtxoEntry::new(o.value, env.kit.offer.spk(&o.fields.encode()), active_block().daa, false, None));

    let p = ops::accept_offer(&env, &n, &nu, &o, &ou).unwrap();
    assert_valid(&p);
    assert_eq!(p.built.tx.payload, b"kchat:1:name:accept:alice");
    assert!(p.network_fee <= env.kit.params.offer_max_fee);
    assert_eq!(p.built.tx.inputs.len(), 2);

    let p = ops::withdraw_offer(&env, &o, &ou).unwrap();
    assert_valid(&p);
    assert!(p.built.tx.payload.is_empty());

    // refund: invalid before refundAfter, valid after; DAA lock time
    let p = ops::refund_offer(&env, &o, &ou).unwrap();
    assert!(p.validation.is_err());
    let later = Env { block: Block { daa: refund_after + 1, ..env.block }, ..harness_env(active_block()) };
    let p = ops::refund_offer(&later, &o, &ou).unwrap();
    assert_valid(&p);
    assert_eq!(p.built.tx.lock_time, refund_after);
    assert_eq!((p.built.tx.inputs.len(), p.built.tx.outputs.len()), (1, 1));
}

#[test]
fn exits_pass_the_validator() {
    let env = harness_env(active_block());
    let me = env.me();
    let (n, nu) = name_rec(&env, "alice", &me, 0, 30);
    let key = n.fields.key;
    let (lo, hi) = neighbours(&key);
    let below = GapRec { outpoint: TransactionOutpoint::new(TransactionId::from_bytes([40; 32]), 0), lo, hi: key, value: SOMPI };
    let above = GapRec { outpoint: TransactionOutpoint::new(TransactionId::from_bytes([41; 32]), 0), lo: key, hi, value: SOMPI };
    let bu = reg_utxo(&env, env.kit.gap.spk(&gap_state(&lo, &key)), SOMPI, 40);
    let au = reg_utxo(&env, env.kit.gap.spk(&gap_state(&key, &hi)), SOMPI, 41);
    let x = || ExitParts { below: &below, below_utxo: &bu, name: &n, name_utxo: &nu, above: &above, above_utxo: &au };

    let p = ops::release(&env, x()).unwrap();
    assert_valid(&p);
    assert_eq!(p.built.tx.payload, b"kchat:1:name:release:alice");
    assert_eq!(p.built.tx.outputs.len(), 2);

    // reclaim: not before expiresAt + grace (median time), then valid
    let p = ops::reclaim(&env, x()).unwrap();
    assert!(p.validation.is_err());
    let unlock = (n.fields.expires_at + env.kit.params.grace_ms) as u64;
    let late = Env { block: Block { daa: env.block.daa + 1000, time_ms: unlock + 1 }, ..harness_env(active_block()) };
    let p = ops::reclaim(&late, x()).unwrap();
    assert_valid(&p);
    assert_eq!(p.built.tx.lock_time, unlock);
    assert_eq!(p.built.tx.payload, b"kchat:1:name:reclaim:alice");
    assert_eq!(p.built.tx.outputs[1].script_public_key, p2pk_spk(&me));
    assert_eq!(p.built.tx.outputs[1].value, env.kit.params.bond);
}

#[test]
fn commit_builds_the_fixed_redeem() {
    let env = harness_env(active_block());
    let p = ops::commit(&env, &wallet(&env, 5, 1), "alice", [3; 32]).unwrap();
    assert_valid(&p);
    let redeem = commit_redeem(&commitment(b"alice", &env.me(), &[3; 32]), &env.me());
    assert_eq!(p.built.tx.outputs[0].script_public_key, pay_to_script_hash_script(&redeem));
    assert_eq!(p.built.tx.outputs[0].value, ops::COMMIT_VALUE);
    // a commit carries no payload: the name stays hidden until registration
    assert!(p.built.tx.payload.is_empty());
    assert!(ops::commit(&env, &wallet(&env, 5, 1), "-bad", [3; 32]).is_err());
    assert!(ops::commit(&env, &wallet(&env, 5, 1), "Alice", [3; 32]).is_err());
}

// ---------------------------------------------------------------------------
// genesis
// ---------------------------------------------------------------------------

#[test]
fn genesis_authorizes_only_the_genesis_gap() {
    let t = templates();
    let d = keypair(200);
    let w = vec![Utxo::new(
        TransactionOutpoint::new(TransactionId::from_bytes([0x42; 32]), 0),
        UtxoEntry::new(300 * SOMPI, p2pk_spk(&xonly(&d)), 1_000, false, None),
    )];
    let (p, kit) = ops::genesis(&t, d, &w, active_block(), NOW_MS, ops::MIN_FEERATE).unwrap();
    assert_valid(&p);
    let tx = &p.built.tx;
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.iter().filter(|o| o.covenant.is_some()).count(), 1);
    assert_eq!(tx.outputs[0].script_public_key, kit.gap.spk(&gap_state(&ZERO32, &FF32)));
    // the same registry id the harness computes for the same outpoint (its
    // genesis uses exactly this funding outpoint)
    assert_eq!(p.registry_id.unwrap(), Kit::new().registry_id);
    assert_eq!(kit.registry_id, Kit::new().registry_id);
    assert_eq!(kit.offer.bytecode, Kit::new().offer.bytecode);
}

// ---------------------------------------------------------------------------
// registry decoding
// ---------------------------------------------------------------------------

#[test]
fn the_full_plan_runs_end_to_end_and_balances() {
    let (sim, b) = plan::simulate(templates(), PLANNED_FUNDING, NOW_MS + 10 * YEAR_MS).unwrap();
    // 35 + 70 + 35 (registrations) + 35 (extend alpha-tn) + 35 (renew lapse-tn)
    assert_eq!(b.prices, 210 * SOMPI);
    assert_eq!(b.txs, plan::e2e_steps().iter().filter(|(s, _)| !matches!(s, Step::Wait(..))).count());
    let reg = sim.reg.as_ref().unwrap();
    reg.check_invariants().unwrap();
    // left: alpha-tn (owned by the deployer, extended to 2 years) between two gaps
    assert_eq!(reg.names.len(), 1);
    assert_eq!(reg.gaps.len(), 2);
    let a = reg.name(plan::A).unwrap();
    assert_eq!(a.fields.owner, xonly(&sim.deployer));
    assert_eq!(a.fields.price, 0);
    assert_eq!(a.fields.expires_at - a.fields.period_start, 2 * YEAR_MS);
    // lapse-tn was renewed after lapse (a new period from its old expiry) before the reclaim
    let renew = sim.plans.iter().find(|p| p.op.starts_with("renew lapse-tn")).unwrap();
    assert!(renew.built.tx.lock_time > 0 && renew.built.tx.payload == b"kchat:1:name:renew:lapse-tn");
    assert!(reg.offers.is_empty());
    assert!(sim.commits.iter().all(|c| c.used_by.is_some()));
    // the least funding the plan needs
    assert!(b.peak_need < PLANNED_FUNDING);
    let need = b.peak_need.div_ceil(SOMPI) * SOMPI;
    plan::simulate(templates(), need, NOW_MS + 10 * YEAR_MS).unwrap();
    assert!(plan::simulate(templates(), need - 30 * SOMPI, NOW_MS + 10 * YEAR_MS).is_err());
}

#[test]
fn every_step_builds_a_valid_transaction() {
    let mut sim = Sim::new(templates(), PLANNED_FUNDING, NOW_MS + 10 * YEAR_MS);
    for (step, _) in plan::e2e_steps() {
        sim.run(&step).unwrap_or_else(|e| panic!("{step:?}: {e}"));
    }
    for p in &sim.plans {
        assert_valid(p);
    }
}

#[test]
fn the_decoder_refuses_unexplained_registry_outputs() {
    // A registry output that no tracked registry input predicts (e.g. a
    // forged state) is refused and the state does not move.
    let mut sim = Sim::new(templates(), PLANNED_FUNDING, NOW_MS + 10 * YEAR_MS);
    for (step, _) in plan::e2e_steps().into_iter().take(6) {
        sim.run(&step).unwrap();
    }
    let kit = sim.templates.kit(sim.kit.as_ref().unwrap().registry_id).unwrap();
    let reg = sim.reg.clone().unwrap();
    let last = sim.plans.last().unwrap().built.tx.clone(); // register alpha-tn
    // replay a mutated copy: the name output now says another owner
    let mut fresh = Registry::at_genesis(reg.registry_id, sim.plans[0].txid(), SOMPI, None);
    let mut forged = TxView::from(&last);
    let f = NameFields::new(plan::A.as_bytes(), &xonly(&keypair(9)), 0, 0, 1);
    forged.outputs[2] = TransactionOutput::with_covenant(SOMPI, kit.name.spk(&f.encode()), forged.outputs[2].covenant);
    let before = fresh.to_json();
    assert!(fresh.apply(&kit, &forged).is_err());
    assert_eq!(fresh.to_json(), before);
    // the genuine one applies
    let ev = fresh.apply(&kit, &TxView::from(&last)).unwrap();
    assert!(ev[0].starts_with("register alpha-tn"), "{ev:?}");
    fresh.check_invariants().unwrap();
    // and re-applying is a no-op
    assert!(fresh.apply(&kit, &TxView::from(&last)).unwrap().is_empty());
}

#[test]
fn state_round_trips_through_json() {
    let mut sim = Sim::new(templates(), PLANNED_FUNDING, NOW_MS + 10 * YEAR_MS);
    for (step, _) in plan::e2e_steps().into_iter().take(14) {
        sim.run(&step).unwrap();
    }
    let reg = sim.reg.unwrap();
    assert!(!reg.offers.is_empty());
    let back = Registry::from_json(&reg.to_json()).unwrap();
    assert_eq!(back.to_json(), reg.to_json());
    assert_eq!(back.gaps, reg.gaps);
    assert_eq!(back.names, reg.names);
    assert_eq!(back.offers, reg.offers);
}

// ---------------------------------------------------------------------------
// network guards
// ---------------------------------------------------------------------------

#[test]
fn only_kaspatest_schnorr_addresses_are_accepted() {
    let x = xonly(&keypair(9));
    let tn = kaspa_addresses::Address::new(kaspa_addresses::Prefix::Testnet, kaspa_addresses::Version::PubKey, &x);
    assert_eq!(parse_owner_address(&tn.to_string()).unwrap(), x);
    let main = kaspa_addresses::Address::new(kaspa_addresses::Prefix::Mainnet, kaspa_addresses::Version::PubKey, &x);
    assert!(parse_owner_address(&main.to_string()).unwrap_err().to_string().contains("kaspatest"));
    let p2sh = kaspa_addresses::Address::new(kaspa_addresses::Prefix::Testnet, kaspa_addresses::Version::ScriptHash, &x);
    assert!(parse_owner_address(&p2sh.to_string()).is_err());
    assert!(parse_owner_address("kaspatest:nonsense").is_err());
}

#[test]
fn consensus_params_are_testnet10() {
    assert_eq!(kachat_names_cli::net::consensus_params().net.to_string(), "testnet-10");
    let _ = OfferFields { key: ZERO32, buyer: ZERO32, refund_after: 0 };
}

// ---------------------------------------------------------------------------
// the signature-script encoding the indexer decodes (KACHAT_NAMES_INDEXER.md B3)
// ---------------------------------------------------------------------------

/// (opcode, pushed bytes) of every push.
fn raw_pushes(script: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = vec![];
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let n = match op {
            0x01..=0x4b => op as usize,
            0x4c => {
                i += 1;
                script[i - 1] as usize
            }
            0x4d => {
                i += 2;
                u16::from_le_bytes([script[i - 2], script[i - 1]]) as usize
            }
            _ => 0,
        };
        out.push((op, script[i..i + n].to_vec()));
        i += n;
    }
    out
}

#[test]
fn signature_scripts_are_args_then_tag_then_redeem() {
    let mut sim = Sim::new(templates(), PLANNED_FUNDING, NOW_MS + 10 * YEAR_MS);
    for (step, _) in plan::e2e_steps() {
        sim.run(&step).unwrap();
    }
    let kit = sim.kit.as_ref().unwrap();
    let find = |op: &str| sim.plans.iter().find(|p| p.op.starts_with(op)).unwrap();

    // register alpha-tn (1 y): name, ownerKey, salt, now, years, namePrefix, nameSuffix, tag, redeem
    let p = find("register alpha-tn");
    let s = raw_pushes(&p.built.tx.inputs[0].signature_script);
    assert_eq!(s.len(), 9);
    assert_eq!(s[0], (0x08, b"alpha-tn".to_vec()));
    assert_eq!((s[1].0, s[2].0), (0x20, 0x20)); // byte[32]: 32-byte pushes
    assert_eq!(s[3].0, 0x06); // now ~1.8e12 ms: a 6-byte minimal script number
    assert_eq!(s[4], (0x51, vec![])); // years = 1: OP_1, not a data push
    assert_eq!(s[5], (0x01, kit.name.prefix.clone())); // byte[] prefix (1 byte, 0x6b)
    assert_eq!((s[6].0, s[6].1.len()), (0x4d, 2981)); // byte[] suffix: OP_PUSHDATA2
    let mut tag = [0u8; 4];
    faster_hex::hex_decode(kit.gap.dispatch_tag("register").as_bytes(), &mut tag).unwrap();
    assert_eq!(s[7], (0x04, tag.to_vec())); // the 4-byte dispatch tag push
    assert_eq!((s[8].0, s[8].1.len()), (0x4d, 4014)); // the gap redeem, OP_PUSHDATA2

    // list alpha-tn 50: price (5e9 sompi: 5-byte script number), sig (65 bytes, ends 0x01), tag, redeem
    let p = find("list alpha-tn");
    let s = raw_pushes(&p.built.tx.inputs[0].signature_script);
    assert_eq!(s.len(), 4);
    assert_eq!(s[0].0, 0x05);
    assert_eq!((s[1].0, s[1].1.len(), *s[1].1.last().unwrap()), (0x41, 65, 0x01));
    assert_eq!(s[2].0, 0x04);
    assert_eq!((s[3].0, s[3].1.len()), (0x4d, 3108));

    // accept-offer: offer.accept(0): nameIdx 0 is OP_0 (an empty push)
    let p = find("accept offer");
    let s = raw_pushes(&p.built.tx.inputs[1].signature_script);
    assert_eq!(s[0], (0x00, vec![]));
    assert_eq!(s[1].0, 0x04);
    assert_eq!((s[2].0, s[2].1.len()), (0x4d, 948)); // offer redeem

    // extend(1) / renew(1): years = OP_1, tag, name redeem
    for (op, entry) in [("extend alpha-tn", "extend"), ("renew lapse-tn", "renew")] {
        let p = find(op);
        let s = raw_pushes(&p.built.tx.inputs[0].signature_script);
        assert_eq!(s.len(), 3, "{op}");
        assert_eq!(s[0], (0x51, vec![]));
        let mut tag = [0u8; 4];
        faster_hex::hex_decode(kit.name.dispatch_tag(entry).as_bytes(), &mut tag).unwrap();
        assert_eq!(s[1], (0x04, tag.to_vec()));
        assert_eq!((s[2].0, s[2].1.len()), (0x4d, 3108));
    }
    assert_eq!(kit.name.dispatch_tag("extend"), "2ce7cceb");
    assert_eq!(kit.name.dispatch_tag("renew"), "b706ac38");

    // reclaim(): no args, just tag + redeem; merge/absorbed likewise
    let p = find("reclaim lapse-tn");
    for i in 0..3 {
        let s = raw_pushes(&p.built.tx.inputs[i].signature_script);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].0, 0x04);
    }
}

#[test]
fn the_manifest_carries_and_verifies_the_genesis_binding() {
    let t = templates();
    let paths = Paths::find(None).unwrap();
    let d = keypair(200);
    let w = vec![Utxo::new(
        TransactionOutpoint::new(TransactionId::from_bytes([0x42; 32]), 0),
        UtxoEntry::new(300 * SOMPI, p2pk_spk(&xonly(&d)), 1_000, false, None),
    )];
    let (p, kit) = ops::genesis(&t, d, &w, active_block(), NOW_MS, ops::MIN_FEERATE).unwrap();
    let m = kachat_names_cli::manifest::build(&paths, &kit, &p, "kaspatest:x", None, true).unwrap();
    let file = std::env::temp_dir().join(format!("kachat-names-manifest-{}.json", std::process::id()));
    kachat_names_cli::manifest::write(&file, &m).unwrap();
    let back = kachat_names_cli::manifest::load(&file, Some(&kit)).unwrap();
    assert_eq!(back.registry_id, kit.registry_id);
    assert_eq!(back.genesis_txid, p.txid());
    assert!(back.dry_run);
    for c in ["KachatGap", "KachatName", "KachatOffer"] {
        let a = &m["artifacts"][c];
        let pre = a["prefixHex"].as_str().unwrap();
        let suf = a["suffixHex"].as_str().unwrap();
        let (mut pb, mut sb) = (vec![0u8; pre.len() / 2], vec![0u8; suf.len() / 2]);
        faster_hex::hex_decode(pre.as_bytes(), &mut pb).unwrap();
        faster_hex::hex_decode(suf.as_bytes(), &mut sb).unwrap();
        assert_eq!(faster_hex::hex_string(&silverscript_abi::template_hash(&pb, &sb)), a["templateHash"].as_str().unwrap(), "{c}");
    }
    // a manifest whose registry id does not follow from its genesis outpoint is refused
    let mut bad = m.clone();
    bad["genesis"]["outpoint"] = serde_json::json!(format!("{}:1", TransactionId::from_bytes([0x42; 32])));
    kachat_names_cli::manifest::write(&file, &bad).unwrap();
    assert!(kachat_names_cli::manifest::load(&file, Some(&kit)).is_err());
    std::fs::remove_file(file).unwrap();
}
