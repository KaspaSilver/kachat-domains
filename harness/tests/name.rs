//! KachatName: transfer, list, buy, renew (release/reclaim live in exit.rs).

use kachat_names_harness::{scenarios::*, *};

fn name_fails(kit: &Kit, spec: &TxSpec) {
    input_fails(kit, spec, active_block(), 0);
}

// ---------------------------------------------------------------- transfer

#[test]
fn transfer_hands_over_and_keeps_the_expiry() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let to = xonly(&keypair(7));
    let spec = transfer(&kit, &n, &to);
    ok(&kit, &spec, active_block());
    assert_eq!(n.fields.with_owner(&to).expires_at, n.fields.expires_at);
}

#[test]
fn transfer_clears_a_listing() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 5 * SOMPI_PER_KAS as i64);
    let to = xonly(&keypair(7));
    ok(&kit, &transfer(&kit, &n, &to), active_block());
    // keeping the price on the continuation is refused
    let mut spec = transfer(&kit, &n, &to);
    spec.outputs[0] = kit.name_output(&NameFields { owner: to, ..n.fields.clone() }, 0);
    name_fails(&kit, &spec);
}

#[test]
fn transfer_works_after_expiry() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let late = Block { daa: COMMIT_DAA + 1_000_000_000, time_ms: (n.fields.expires_at + 10 * YEAR_MS) as u64 };
    ok(&kit, &transfer(&kit, &n, &xonly(&keypair(7))), late);
}

#[test]
fn transfer_rejects_a_wrong_signature() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let mut spec = transfer(&kit, &n, &xonly(&keypair(7)));
    spec.inputs[0].args_mut()[1] = Arg::Sig(keypair(9));
    name_fails(&kit, &spec);
}

#[test]
fn owner_signatures_must_be_sighash_all() {
    // A valid owner signature with ALL|ANYONECANPAY or NONE is refused
    // (NONE would let anyone rewrite newOwner and the outputs).
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    for t in [0x81u8, 0x02, 0x04, 0x82, 0x84] {
        let mut spec = transfer(&kit, &n, &xonly(&keypair(7)));
        spec.inputs[0].args_mut()[1] = Arg::SigWithType(n.owner, t);
        name_fails(&kit, &spec);
    }
}

#[test]
fn transfer_rejects_a_zero_owner() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    name_fails(&kit, &transfer(&kit, &n, &ZERO32));
}

#[test]
fn transfer_rejects_a_changed_key_name_or_expiry() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let to = xonly(&keypair(7));
    let next = n.fields.with_owner(&to);
    for bad in [
        NameFields { key: name_key(b"bob"), ..next.clone() },
        NameFields { name: pad_name(b"bob"), ..next.clone() },
        next.with_expiry(next.expires_at + YEAR_MS),
        next.with_expiry(next.expires_at - 1),
    ] {
        let mut spec = transfer(&kit, &n, &to);
        spec.outputs[0] = kit.name_output(&bad, 0);
        name_fails(&kit, &spec);
    }
}

#[test]
fn continuation_value_is_pinned_to_the_bond() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    for delta in [-1i64, 1] {
        let mut spec = transfer(&kit, &n, &xonly(&keypair(7)));
        spec.outputs[0].value = (spec.outputs[0].value as i64 + delta) as u64;
        spec.outputs[1].value = (spec.outputs[1].value as i64 - delta) as u64;
        name_fails(&kit, &spec);
    }
}

#[test]
fn a_name_cannot_vanish_or_split() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let to = xonly(&keypair(7));
    // no registry output: the name would be destroyed outside the exit
    let mut spec = transfer(&kit, &n, &to);
    let cont = spec.outputs.remove(0);
    spec.outputs[0].value += cont.value;
    name_fails(&kit, &spec);
    // two registry outputs
    let mut spec = transfer(&kit, &n, &to);
    spec.inputs[1].utxo.entry.amount += kit.params.bond;
    spec.outputs.insert(1, kit.name_output(&n.fields.with_owner(&xonly(&n.owner)), 0));
    name_fails(&kit, &spec);
}

#[test]
fn the_continuation_cannot_leave_the_registry() {
    // A continuation must carry the registry id: an unbound output with the
    // right script is not counted, and a fresh covenant id authorized by the
    // name is a genesis, not a continuation.
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let to = xonly(&keypair(7));
    let mut spec = transfer(&kit, &n, &to);
    spec.outputs[0].covenant = None;
    name_fails(&kit, &spec);
}

#[test]
fn names_cannot_be_batched() {
    let kit = Kit::new();
    let a = name_case(&kit, b"alice", 0);
    let b = NameCase {
        fields: NameFields::new(b"bob", &xonly(&a.owner), 0, NOW_MS, NOW_MS + YEAR_MS),
        owner: a.owner,
        utxo: kit.name_utxo(&NameFields::new(b"bob", &xonly(&a.owner), 0, NOW_MS, NOW_MS + YEAR_MS), 24),
    };
    let to = xonly(&keypair(7));
    let mut spec = transfer(&kit, &a, &to);
    spec.inputs.push(Input::contract(b.utxo.clone(), &kit.name, b.fields.encode(), "transfer", vec![bytes(&to), Arg::Sig(b.owner)]));
    spec.outputs.insert(1, kit.name_output(&b.fields.with_owner(&to), 2));
    spec.outputs.last_mut().unwrap().value += kit.params.bond - kit.params.bond;
    let built = kit.build(&spec);
    let res = built.run_inputs();
    assert!(res[0].is_err() && res[2].is_err(), "{res:?}");
    assert!(kit.validate(&built, active_block()).is_err());
}

// ---------------------------------------------------------------- list

#[test]
fn list_and_delist() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    ok(&kit, &list(&kit, &n, 50 * SOMPI_PER_KAS as i64), active_block());
    let listed = name_case(&kit, b"alice", 50 * SOMPI_PER_KAS as i64);
    ok(&kit, &list(&kit, &listed, 0), active_block()); // delist
}

#[test]
fn list_rejects_a_wrong_signature_and_bad_prices() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let mut spec = list(&kit, &n, 10);
    spec.inputs[0].args_mut()[1] = Arg::Sig(keypair(9));
    name_fails(&kit, &spec);
    name_fails(&kit, &list(&kit, &n, -1));
    name_fails(&kit, &list(&kit, &n, 2_900_000_000_000_000_001));
    ok(&kit, &list(&kit, &n, 2_900_000_000_000_000_000), active_block());
}

#[test]
fn list_cannot_change_the_owner() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let mut spec = list(&kit, &n, 10);
    spec.outputs[0] = kit.name_output(&NameFields { owner: xonly(&keypair(9)), price: 10, ..n.fields.clone() }, 0);
    name_fails(&kit, &spec);
}

// ---------------------------------------------------------------- buy

const PRICE: i64 = 100 * SOMPI_PER_KAS as i64;

#[test]
fn buy_pays_the_seller_and_moves_the_name() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", PRICE);
    ok(&kit, &buy(&kit, &n), active_block());
}

#[test]
fn buy_may_overpay() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", PRICE);
    let mut spec = buy(&kit, &n);
    spec.outputs[1].value += 7;
    spec.outputs[2].value -= 7;
    ok(&kit, &spec, active_block());
}

#[test]
fn buy_rejects_an_unlisted_name() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let mut spec = buy(&kit, &n);
    // pay something anyway (a zero-value output is not even consensus-valid)
    spec.outputs[1].value = kas(1);
    spec.outputs[2].value -= kas(1);
    name_fails(&kit, &spec);
}

#[test]
fn buy_rejects_paying_too_little() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", PRICE);
    let mut spec = buy(&kit, &n);
    spec.outputs[1].value -= 1;
    spec.outputs[2].value += 1;
    name_fails(&kit, &spec);
}

#[test]
fn buy_rejects_paying_the_wrong_script() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", PRICE);
    let buyer = xonly(&keypair(2));
    for spk in [
        p2pk_spk(&buyer),                                                // to the buyer
        p2pk_spk(&xonly(&keypair(9))),                                   // to a stranger
        kaspa_txscript::pay_to_script_hash_script(&[0x51]),              // P2SH
        ScriptPublicKey::new(1, [&[0x20u8][..], &n.fields.owner, &[0xac]].concat().into()), // seller key, other version
    ] {
        let mut spec = buy(&kit, &n);
        spec.outputs[1].script_public_key = spk;
        name_fails(&kit, &spec);
    }
}

#[test]
fn buy_rejects_the_payout_at_another_index() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", PRICE);
    let mut spec = buy(&kit, &n);
    spec.outputs.swap(1, 2); // payout after the change
    name_fails(&kit, &spec);
    let mut spec = buy(&kit, &n);
    let payout = spec.outputs.remove(1);
    spec.outputs.insert(0, payout); // payout before the continuation
    spec.outputs[1].covenant.as_mut().unwrap().authorizing_input = 0;
    name_fails(&kit, &spec);
}

#[test]
fn two_buys_cannot_share_one_payment() {
    // Two names listed by the same seller at the same price, bought in one
    // transaction with a single payout that satisfies both "output after my
    // continuation" checks.
    let kit = Kit::new();
    let a = name_case(&kit, b"alice", PRICE);
    let bf = NameFields::new(b"bobby", &a.fields.owner, PRICE, NOW_MS, NOW_MS + YEAR_MS);
    let b_utxo = kit.name_utxo(&bf, 25);
    let buyer = keypair(2);
    let bx = xonly(&buyer);
    let funding = kit.p2pk_utxo(&buyer, PRICE as u64 + kas(3), 22);
    let mut spec = TxSpec {
        inputs: vec![
            Input::contract(a.utxo.clone(), &kit.name, a.fields.encode(), "buy", vec![bytes(&bx)]),
            Input::contract(b_utxo, &kit.name, bf.encode(), "buy", vec![bytes(&bx)]),
            Input::new(funding, Unlock::P2pk(buyer)),
        ],
        outputs: vec![
            kit.name_output(&a.fields.with_owner(&bx), 0),
            TransactionOutput::new(PRICE as u64, p2pk_spk(&a.fields.owner)), // after a's continuation
        ],
        lock_time: 0,
    };
    // b's continuation right before the same payout is impossible (indices are
    // unique), so put it after: [a', payout, b', payout?] - only one payout paid
    spec.outputs.push(kit.name_output(&bf.with_owner(&bx), 1));
    let change = spec.total_in() - spec.total_out() - NET_FEE;
    spec.outputs.push(TransactionOutput::new(change, p2pk_spk(&bx)));
    let built = kit.build(&spec);
    let res = built.run_inputs();
    assert!(res[0].is_err() && res[1].is_err(), "both buys must refuse a shared registry tx: {res:?}");
    assert!(kit.validate(&built, active_block()).is_err());
}

#[test]
fn buy_rejects_a_zero_buyer_and_a_tampered_continuation() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", PRICE);
    let mut spec = buy(&kit, &n);
    spec.inputs[0].args_mut()[0] = bytes(&ZERO32);
    spec.outputs[0] = kit.name_output(&n.fields.with_owner(&ZERO32), 0);
    name_fails(&kit, &spec);
    // continuation still listed
    let bx = xonly(&keypair(2));
    let mut spec = buy(&kit, &n);
    spec.outputs[0] = kit.name_output(&NameFields { owner: bx, ..n.fields.clone() }, 0);
    name_fails(&kit, &spec);
    // continuation to someone other than the argument
    let mut spec = buy(&kit, &n);
    spec.outputs[0] = kit.name_output(&n.fields.with_owner(&xonly(&keypair(9))), 0);
    name_fails(&kit, &spec);
}

// ---------------------------------------------------------------- the paid period
//
// name_case: periodStart = NOW_MS, expiresAt = NOW_MS + 1 year (a 1-year
// registration). maxYears = 2, renewWindowMs = 10 days.

#[test]
fn transfer_list_and_buy_keep_the_paid_period() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    // a renewed name: periodStart is no longer the registration time
    let n = n.with_fields(&kit, n.fields.renewed(1));
    assert_eq!((n.fields.period_start, n.fields.expires_at), (NOW_MS + YEAR_MS, NOW_MS + 2 * YEAR_MS));
    let to = xonly(&keypair(7));
    ok(&kit, &transfer(&kit, &n, &to), active_block());
    ok(&kit, &list(&kit, &n, 10), active_block());
    let listed = n.with_fields(&kit, n.fields.with_price(PRICE));
    ok(&kit, &buy(&kit, &listed), active_block());
    // a continuation that moves periodStart either way is refused by each
    for start in [n.fields.period_start - YEAR_MS, n.fields.period_start + 1, n.fields.expires_at] {
        let mut spec = transfer(&kit, &n, &to);
        spec.outputs[0] = kit.name_output(&NameFields { period_start: start, ..n.fields.with_owner(&to) }, 0);
        name_fails(&kit, &spec);
        let mut spec = list(&kit, &n, 10);
        spec.outputs[0] = kit.name_output(&NameFields { period_start: start, ..n.fields.with_price(10) }, 0);
        name_fails(&kit, &spec);
        let mut spec = buy(&kit, &listed);
        spec.outputs[0] = kit.name_output(&NameFields { period_start: start, ..listed.fields.with_owner(&xonly(&keypair(2))) }, 0);
        name_fails(&kit, &spec);
    }
}

// ---------------------------------------------------------------- extend

#[test]
fn extend_one_year_to_two() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let spec = extend(&kit, &n, 1);
    assert_eq!(spec.lock_time, 0);
    ok(&kit, &spec, active_block());
    let next = n.fields.extended(1);
    assert_eq!((next.period_start, next.expires_at), (NOW_MS, NOW_MS + 2 * YEAR_MS));
}

#[test]
fn extend_past_period_start_plus_max_years_fails() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    // 1-year registration: 2 more years would be 3 past periodStart
    let spec = extend(&kit, &n, 2);
    name_fails(&kit, &spec);
    // a 2-year registration cannot be extended at all
    let two = n.with_fields(&kit, NameFields { expires_at: NOW_MS + 2 * YEAR_MS, ..n.fields.clone() });
    name_fails(&kit, &extend(&kit, &two, 1));
    // one millisecond over the cap is refused; exactly at it passes
    let almost = n.with_fields(&kit, n.fields.with_expiry(NOW_MS + YEAR_MS + 1));
    name_fails(&kit, &extend(&kit, &almost, 1));
    let exact = n.with_fields(&kit, n.fields.with_expiry(NOW_MS + YEAR_MS));
    ok(&kit, &extend(&kit, &exact, 1), active_block());
    // and extending twice by a year from a 1-year registration: the second is refused
    let once = n.with_fields(&kit, n.fields.extended(1));
    name_fails(&kit, &extend(&kit, &once, 1));
}

#[test]
fn extend_works_any_time_even_after_expiry() {
    // no time lock: in the period, in grace, after lapse
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    for t in [NOW_MS + 10_000, n.fields.expires_at + 1, n.fields.expires_at + kit.params.grace_ms + 1] {
        ok(&kit, &extend(&kit, &n, 1), block_after(t));
    }
}

#[test]
fn extend_rejects_zero_and_too_many_years() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    // even from a state whose period would leave room for 3 years
    let roomy = n.with_fields(&kit, NameFields { period_start: NOW_MS + 5 * YEAR_MS, ..n.fields.clone() });
    ok(&kit, &extend(&kit, &roomy, 2), active_block());
    for years in [0, -1, kit.params.max_years + 1] {
        name_fails(&kit, &extend(&kit, &roomy, years));
        name_fails(&kit, &extend(&kit, &n, years));
    }
}

#[test]
fn extend_must_pay_the_tier_price_per_year() {
    let kit = Kit::new();
    for name in [&b"a"[..], b"ab", b"abc", b"abcd", b"alice", b"kaspa-silver-0123456789-abcdefgh"] {
        let n = name_case(&kit, name, 0);
        let mut spec = extend(&kit, &n, 1);
        let due = kit.params.renew_price_for(name.len());
        spec.outputs.last_mut().unwrap().value += NET_FEE;
        assert_eq!(spec.fee() as u64, due);
        ok(&kit, &spec, active_block());
        // underpaid by one sompi
        spec.outputs.last_mut().unwrap().value += 1;
        name_fails(&kit, &spec);
    }
    // 2 years (from a state with room for them) must pay 2 years: one sompi short fails
    let n = name_case(&kit, b"alice", 0);
    let roomy = n.with_fields(&kit, NameFields { period_start: NOW_MS + 5 * YEAR_MS, ..n.fields.clone() });
    let mut spec = extend(&kit, &roomy, 2);
    spec.outputs.last_mut().unwrap().value += NET_FEE;
    assert_eq!(spec.fee() as u64, 2 * kit.params.renew_price_for(5));
    ok(&kit, &spec, active_block());
    spec.outputs.last_mut().unwrap().value += 1;
    name_fails(&kit, &spec);
    // the tier comes from the stored name
    let n = name_case(&kit, b"x", 0);
    let mut spec = extend(&kit, &n, 1);
    spec.outputs.last_mut().unwrap().value += kit.params.renew_price_for(1) - kit.params.renew_price_for(5);
    name_fails(&kit, &spec);
}

#[test]
fn extend_changes_nothing_but_the_expiry() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 9);
    let next = n.fields.extended(1);
    for bad in [
        NameFields { owner: xonly(&keypair(9)), ..next.clone() },
        NameFields { price: 0, ..next.clone() },
        NameFields { period_start: NOW_MS + YEAR_MS, ..next.clone() }, // a fresh period
        NameFields { period_start: NOW_MS - YEAR_MS, ..next.clone() },
        next.with_expiry(next.expires_at - 1),
        n.fields.renewed(1), // renew's continuation under extend
    ] {
        let mut spec = extend(&kit, &n, 1);
        spec.outputs[0] = kit.name_output(&bad, 0);
        name_fails(&kit, &spec);
    }
}

#[test]
fn extend_stops_at_the_expiry_cap() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let cap = 100_000_000_000_000_000i64;
    // periodStart leaves room; only the expiry cap refuses
    let over = n.with_fields(&kit, n.fields.with_period(cap + 1, cap + 1));
    name_fails(&kit, &extend(&kit, &over, 1));
    let at = n.with_fields(&kit, n.fields.with_period(cap, cap));
    ok(&kit, &extend(&kit, &at, 1), active_block());
}

#[test]
fn anyone_may_extend_and_renew_a_name_as_a_gift() {
    // the scenarios' payer is keypair 3, not the owner (keypair 1); no signature
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let spec = extend(&kit, &n, 1);
    assert!(matches!(&spec.inputs[1].unlock, Unlock::P2pk(k) if xonly(k) != n.fields.owner));
    ok(&kit, &spec, active_block());
    let spec = renew(&kit, &n, 1);
    assert!(matches!(&spec.inputs[1].unlock, Unlock::P2pk(k) if xonly(k) != n.fields.owner));
    ok(&kit, &spec, window_block(&kit, &n));
    // the owner is unchanged by either
    assert_eq!(n.fields.extended(1).owner, n.fields.owner);
    assert_eq!(n.fields.renewed(1).owner, n.fields.owner);
}

// ---------------------------------------------------------------- renew

#[test]
fn renew_at_the_window_boundary_passes() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    assert_eq!(kit.params.renew_window_ms, 10 * 86_400_000);
    // lock time exactly expiresAt - window, in the first block whose median time passes it
    let spec = renew(&kit, &n, 1);
    assert_eq!(spec.lock_time as i64, n.fields.expires_at - kit.params.renew_window_ms);
    ok(&kit, &spec, window_block(&kit, &n));
    ok(&kit, &renew(&kit, &n, kit.params.max_years), window_block(&kit, &n));
}

#[test]
fn renew_before_the_window_fails() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let opens = n.window_opens(&kit);
    // lock time one millisecond before the window, or well before it: the
    // script refuses, whatever the block time
    for lock in [opens - 1, opens - 86_400_000, NOW_MS + 10_000] {
        let spec = renew_at(&kit, &n, 1, lock as u64);
        input_fails(&kit, &spec, block_after(opens + YEAR_MS), 0);
    }
    // no lock time at all
    input_fails(&kit, &renew_at(&kit, &n, 1, 0), window_block(&kit, &n), 0);
    // a valid lock time is not final before the median time passes it (consensus)
    let spec = renew(&kit, &n, 1);
    let err = rejected(&kit, &spec, block_after(opens - 1));
    assert!(err.contains("finalized"), "{err}");
}

#[test]
fn renew_lock_time_must_be_a_timestamp_with_a_non_final_input() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    // a DAA-score lock time (domain mismatch in the CLTV)
    let spec = renew_at(&kit, &n, 1, COMMIT_DAA + 1);
    input_fails(&kit, &spec, Block { daa: COMMIT_DAA + 2, time_ms: n.window_opens(&kit) as u64 + 1 }, 0);
    // a finalized name input (sequence u64::MAX) disables the CLTV: refused
    let mut spec = renew(&kit, &n, 1);
    spec.inputs[0].sequence = u64::MAX;
    input_fails(&kit, &spec, window_block(&kit, &n), 0);
}

#[test]
fn renew_in_grace_and_after_lapse_passes() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let e = n.fields.expires_at;
    for t in [e, e + 1, e + kit.params.grace_ms - 1, e + kit.params.grace_ms + 1, e + 3 * YEAR_MS] {
        // lock time = a recent time (the CLI's "now - 3 min"), past the window
        let spec = renew_at(&kit, &n, 1, (t - 180_000) as u64);
        ok(&kit, &spec, block_after(t));
    }
}

#[test]
fn renew_starts_a_new_period_at_the_old_expiry() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let next = n.fields.renewed(1);
    assert_eq!((next.period_start, next.expires_at), (NOW_MS + YEAR_MS, NOW_MS + 2 * YEAR_MS));
    ok(&kit, &renew(&kit, &n, 1), window_block(&kit, &n));
    // a lapsed name counts from its old expiry too (no free gap years)
    let lapsed = n.with_fields(&kit, n.fields.with_period(NOW_MS - 4 * YEAR_MS, NOW_MS - 3 * YEAR_MS));
    let spec = renew_at(&kit, &lapsed, 1, NOW_MS as u64);
    ok(&kit, &spec, block_after(NOW_MS));
    // keeping the old periodStart (extend's continuation), or counting from now, is refused
    for bad in [
        n.fields.extended(1),
        n.fields.with_period(NOW_MS + YEAR_MS - 10 * 86_400_000, NOW_MS + 2 * YEAR_MS),
        n.fields.with_period(NOW_MS + YEAR_MS, NOW_MS + 2 * YEAR_MS + 1),
    ] {
        let mut spec = renew(&kit, &n, 1);
        spec.outputs[0] = kit.name_output(&bad, 0);
        input_fails(&kit, &spec, window_block(&kit, &n), 0);
    }
    let mut spec = renew_at(&kit, &lapsed, 1, NOW_MS as u64);
    spec.outputs[0] = kit.name_output(&lapsed.fields.with_period(NOW_MS, NOW_MS + YEAR_MS), 0);
    input_fails(&kit, &spec, block_after(NOW_MS), 0);
}

#[test]
fn renew_then_renew_again_at_once_fails() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let blk = window_block(&kit, &n);
    ok(&kit, &renew(&kit, &n, 1), blk);
    let r = n.with_fields(&kit, n.fields.renewed(1));
    // the window moved a year on: the same lock time, or any time before
    // the new window, is refused
    let spec = renew_at(&kit, &r, 1, n.window_opens(&kit) as u64);
    input_fails(&kit, &spec, blk, 0);
    let spec = renew_at(&kit, &r, 1, (r.window_opens(&kit) - 1) as u64);
    input_fails(&kit, &spec, block_after(r.window_opens(&kit)), 0);
    // a year later it opens again
    ok(&kit, &renew(&kit, &r, 1), window_block(&kit, &r));
}

#[test]
fn renew_one_then_extend_one_passes_renew_two_then_extend_fails() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let blk = window_block(&kit, &n);
    ok(&kit, &renew(&kit, &n, 1), blk);
    let r1 = n.with_fields(&kit, n.fields.renewed(1));
    ok(&kit, &extend(&kit, &r1, 1), blk);
    assert_eq!(r1.fields.extended(1).expires_at, r1.fields.period_start + 2 * YEAR_MS);
    ok(&kit, &renew(&kit, &n, 2), blk);
    let r2 = n.with_fields(&kit, n.fields.renewed(2));
    name_fails(&kit, &extend(&kit, &r2, 1));
}

#[test]
fn renew_pays_exactly_the_tier_price_per_year() {
    let kit = Kit::new();
    for name in [&b"a"[..], b"ab", b"abc", b"abcd", b"alice", b"kaspa-silver-0123456789-abcdefgh"] {
        let n = name_case(&kit, name, 0);
        for years in [1, kit.params.max_years] {
            let mut spec = renew(&kit, &n, years);
            let due = kit.params.renew_price_for(name.len()) * years as u64;
            // exactly the price: passes
            spec.outputs.last_mut().unwrap().value += NET_FEE;
            assert_eq!(spec.fee() as u64, due);
            ok(&kit, &spec, window_block(&kit, &n));
            // one sompi short: fails
            spec.outputs.last_mut().unwrap().value += 1;
            input_fails(&kit, &spec, window_block(&kit, &n), 0);
        }
    }
}

#[test]
fn renew_rejects_zero_and_too_many_years() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    for years in [0, -1, kit.params.max_years + 1] {
        input_fails(&kit, &renew(&kit, &n, years), window_block(&kit, &n), 0);
    }
}

#[test]
fn renew_changes_nothing_but_the_period() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 9);
    let next = n.fields.renewed(1);
    for bad in [
        NameFields { owner: xonly(&keypair(9)), ..next.clone() },
        NameFields { price: 0, ..next.clone() },
        next.with_expiry(next.expires_at + YEAR_MS), // two years for the price of one
    ] {
        let mut spec = renew(&kit, &n, 1);
        spec.outputs[0] = kit.name_output(&bad, 0);
        input_fails(&kit, &spec, window_block(&kit, &n), 0);
    }
}

#[test]
fn renew_tier_comes_from_the_stored_name() {
    // a 1-character name cannot be renewed at the 5+ price
    let kit = Kit::new();
    let n = name_case(&kit, b"x", 0);
    let mut spec = renew(&kit, &n, 1);
    let cheap = kit.params.renew_price_for(5);
    let due = kit.params.renew_price_for(1);
    spec.outputs.last_mut().unwrap().value += due - cheap; // pay only the 5+ tier
    input_fails(&kit, &spec, window_block(&kit, &n), 0);
}

#[test]
fn renew_stops_at_the_expiry_cap() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let cap = 100_000_000_000_000_000i64;
    let over = n.with_fields(&kit, n.fields.with_period(cap - YEAR_MS, cap + 1));
    input_fails(&kit, &renew(&kit, &over, 1), window_block(&kit, &over), 0);
    let at = n.with_fields(&kit, n.fields.with_period(cap - YEAR_MS, cap));
    ok(&kit, &renew(&kit, &at, 1), window_block(&kit, &at));
}

#[test]
fn two_renewals_cannot_share_one_fee() {
    let kit = Kit::new();
    let a = name_case(&kit, b"alice", 0);
    let bf = NameFields::new(b"bobby", &a.fields.owner, 0, NOW_MS, NOW_MS + YEAR_MS);
    let mut spec = renew(&kit, &a, 1);
    spec.inputs.push(Input::contract(kit.name_utxo(&bf, 26), &kit.name, bf.encode(), "renew", vec![int(1)]));
    spec.outputs.insert(1, kit.name_output(&bf.renewed(1), 2));
    let built = kit.build(&spec);
    let res = built.run_inputs();
    assert!(res[0].is_err() && res[2].is_err(), "{res:?}");
    assert!(kit.validate(&built, window_block(&kit, &a)).is_err());
}

#[test]
fn an_extend_and_a_renew_cannot_share_one_fee() {
    let kit = Kit::new();
    let a = name_case(&kit, b"alice", 0);
    let bf = NameFields::new(b"bobby", &a.fields.owner, 0, NOW_MS, NOW_MS + YEAR_MS);
    let mut spec = renew(&kit, &a, 1);
    spec.inputs.push(Input::contract(kit.name_utxo(&bf, 26), &kit.name, bf.encode(), "extend", vec![int(1)]));
    spec.outputs.insert(1, kit.name_output(&bf.extended(1), 2));
    let built = kit.build(&spec);
    let res = built.run_inputs();
    assert!(res[0].is_err() && res[2].is_err(), "{res:?}");
    assert!(kit.validate(&built, window_block(&kit, &a)).is_err());
}

#[test]
fn renew_and_extend_reject_more_than_eight_inputs() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let payer = keypair(3);
    for (mut spec, blk) in [(renew(&kit, &n, 1), window_block(&kit, &n)), (extend(&kit, &n, 1), active_block())] {
        for t in 0..7u8 {
            spec.inputs.push(Input::new(kit.p2pk_utxo(&payer, kas(1), 110 + t), Unlock::P2pk(payer)));
        }
        spec.outputs.last_mut().unwrap().value += kas(7);
        assert_eq!(spec.inputs.len(), 9);
        input_fails(&kit, &spec, blk, 0);
    }
}

#[test]
fn malformed_signatures_fail_closed() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let mut garbage = vec![0xffu8; 64];
    garbage.push(0x01);
    let mut zero = vec![0u8; 64];
    zero.push(0x01);
    for sig in [garbage, zero, vec![0x01; 64], vec![0x01; 66]] {
        let mut spec = transfer(&kit, &n, &xonly(&keypair(7)));
        // raw signature script: the ABI encoder itself refuses wrong lengths
        let redeem = kit.name.redeem(&n.fields.encode());
        let tag = { let h = kit.name.dispatch_tag("transfer"); let mut b = vec![0u8; 4]; faster_hex::hex_decode(h.as_bytes(), &mut b).unwrap(); b };
        let raw = [push(&xonly(&keypair(7))), push(&sig), push(&tag), push(&redeem)].concat();
        if sig.len() == 65 {
            // the raw layout is exactly what the ABI encoder produces
            let abi = kit.name.sig_script(&redeem, "transfer", &[ArtifactValue::Bytes(xonly(&keypair(7)).to_vec()), ArtifactValue::Bytes(sig.clone())]);
            assert_eq!(raw, abi);
        }
        spec.inputs[0].unlock = Unlock::Raw(raw);
        let built = kit.build(&spec);
        assert!(built.run_inputs()[0].is_err(), "sig {sig:?}");
        assert!(kit.validate(&built, active_block()).is_err());
    }
}
