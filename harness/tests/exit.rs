//! The 3-input exit: KachatGap.merge @0 + KachatName.release|reclaim @1 +
//! KachatGap.absorbed @2.

use kachat_names_harness::{scenarios::*, *};

fn fails_at(kit: &Kit, e: &Exit, idx: usize) {
    input_fails(kit, &e.spec, e.block, idx);
}

// ---------------------------------------------------------------- release

#[test]
fn owner_release_merges_the_gaps_and_frees_the_bond() {
    let kit = Kit::new();
    let e = release(&kit, b"alice");
    let built = ok(&kit, &e.spec, e.block);
    // the merged gap is (lo, hi) at gapValue, the only registry output
    assert_eq!(built.tx.outputs[0].script_public_key, kit.gap.spk(&gap_state(&e.lo, &e.hi)));
    assert_eq!(built.tx.outputs[0].value, kit.params.gap_value);
    assert_eq!(built.tx.outputs.iter().filter(|o| o.covenant.is_some()).count(), 1);
}

#[test]
fn owner_release_works_while_listed_and_after_expiry() {
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    e.n.fields = e.n.fields.with_price(5).with_expiry(NOW_MS - 10 * YEAR_MS);
    e.n.utxo = kit.name_utxo(&e.n.fields, 20);
    e.spec.inputs[1] = Input::contract(e.n.utxo.clone(), &kit.name, e.n.fields.encode(), "release", vec![Arg::Sig(e.n.owner)]);
    ok(&kit, &e.spec, e.block);
}

#[test]
fn release_rejects_a_wrong_signature() {
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    e.spec.inputs[1].args_mut()[0] = Arg::Sig(keypair(9));
    fails_at(&kit, &e, 1);
    let mut e = release(&kit, b"alice");
    e.spec.inputs[1].args_mut()[0] = Arg::SigWithType(e.n.owner, 0x82); // NONE|ANYONECANPAY
    fails_at(&kit, &e, 1);
}

#[test]
fn merge_rejects_a_non_adjacent_predecessor() {
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    // predecessor (lo, x) with x != key
    let (x, _) = neighbours(&e.n.fields.key);
    e.spec.inputs[0] = Input::contract(kit.gap_utxo(&e.lo, &x, 30), &kit.gap, gap_state(&e.lo, &x), "merge", vec![]);
    fails_at(&kit, &e, 0);
}

#[test]
fn merge_rejects_a_non_adjacent_successor() {
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    // successor (y, hi) with y != key, claiming to extend the merged gap to FF
    let (_, y) = neighbours(&e.n.fields.key);
    e.spec.inputs[2] = Input::contract(kit.gap_utxo(&y, &FF32, 31), &kit.gap, gap_state(&y, &FF32), "absorbed", vec![]);
    e.spec.outputs[0] = kit.gap_output(&e.lo, &FF32, 0);
    fails_at(&kit, &e, 0);
}

#[test]
fn merge_rejects_a_forged_seat_2_gap() {
    // A gap-shaped UTXO the attacker made outside the registry (no covenant
    // id) with lo = key and hi = ff..ff, to swallow the key space above.
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    let key = e.n.fields.key;
    let forged = Utxo::new(
        TransactionOutpoint::new(TransactionId::from_bytes([77; 32]), 0),
        UtxoEntry::new(kit.params.gap_value, kit.gap.spk(&gap_state(&key, &FF32)), 1_000, false, None),
    );
    e.spec.inputs[2] = Input::contract(forged, &kit.gap, gap_state(&key, &FF32), "absorbed", vec![]);
    e.spec.outputs[0] = kit.gap_output(&e.lo, &FF32, 0);
    let built = kit.build(&e.spec);
    let res = built.run_inputs();
    assert!(res[0].is_err(), "merge must refuse: {res:?}");
    assert!(res[1].is_err(), "release must refuse: {res:?}");
    assert!(res[2].is_err(), "absorbed must refuse: {res:?}");
    assert!(kit.validate(&built, e.block).is_err());
}

#[test]
fn merge_rejects_a_forged_seat_2_with_another_covenant_id() {
    // Same, but the forged gap carries a covenant id of its own.
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    let key = e.n.fields.key;
    let mut forged = kit.gap_utxo(&key, &FF32, 31);
    forged.entry.covenant_id = Some(Hash::from_bytes([0x99; 32]));
    e.spec.inputs[2] = Input::contract(forged, &kit.gap, gap_state(&key, &FF32), "absorbed", vec![]);
    e.spec.outputs[0] = kit.gap_output(&e.lo, &FF32, 0);
    fails_at(&kit, &e, 0);
}

#[test]
fn merge_rejects_a_forged_name_at_seat_1() {
    // A name-shaped UTXO outside the registry.
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    let mut forged = e.n.utxo.clone();
    forged.entry.covenant_id = None;
    e.spec.inputs[1] = Input::contract(forged, &kit.name, e.n.fields.encode(), "release", vec![Arg::Sig(e.n.owner)]);
    fails_at(&kit, &e, 0);
}

#[test]
fn merge_rejects_a_gap_at_seat_1() {
    // Three adjacent gaps (lo,a) (a,b) (b,hi) merged without destroying a name.
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    let key = e.n.fields.key;
    let (_, b) = neighbours(&key);
    e.spec.inputs[1] = Input::contract(kit.gap_utxo(&key, &b, 32), &kit.gap, gap_state(&key, &b), "absorbed", vec![]);
    fails_at(&kit, &e, 0);
}

#[test]
fn merge_rejects_a_wrong_merged_gap() {
    let kit = Kit::new();
    for (lo, hi) in [(ZERO32, None), (ZERO32, Some(FF32))] {
        let mut e = release(&kit, b"alice");
        let hi = hi.unwrap_or(e.hi);
        e.spec.outputs[0] = kit.gap_output(&lo, &hi, 0);
        fails_at(&kit, &e, 0);
    }
    let mut e = release(&kit, b"alice");
    e.spec.outputs[0].value += 1;
    e.spec.outputs[1].value -= 1;
    fails_at(&kit, &e, 0);
}

#[test]
fn exit_rejects_an_extra_registry_output() {
    // keep a copy of the name alive while merging its gaps
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    e.spec.outputs.insert(1, kit.name_output(&e.n.fields, 1));
    e.spec.outputs.last_mut().unwrap().value -= kit.params.bond;
    let built = kit.build(&e.spec);
    let res = built.run_inputs();
    assert!(res.iter().all(|r| r.is_err()), "{res:?}");
    assert!(kit.validate(&built, e.block).is_err());
}

#[test]
fn exit_rejects_reordered_seats() {
    let kit = Kit::new();
    let base = release(&kit, b"alice");
    for perm in [[1usize, 0, 2], [0, 2, 1], [2, 1, 0]] {
        let mut e = release(&kit, b"alice");
        e.spec.inputs = perm.iter().map(|i| base.spec.inputs[*i].clone()).collect();
        let built = kit.build(&e.spec);
        assert!(kit.validate(&built, e.block).is_err(), "perm {perm:?} accepted");
    }
}

#[test]
fn exit_rejects_a_fourth_registry_input() {
    let kit = Kit::new();
    let mut e = release(&kit, b"alice");
    let other = NameFields::new(b"bobby", &e.n.fields.owner, 0, NOW_MS + YEAR_MS);
    e.spec.inputs.push(Input::contract(kit.name_utxo(&other, 33), &kit.name, other.encode(), "release", vec![Arg::Sig(e.n.owner)]));
    e.spec.outputs.last_mut().unwrap().value += kit.params.bond;
    fails_at(&kit, &e, 0);
}

// ---------------------------------------------------------------- reclaim

#[test]
fn reclaim_after_grace_returns_the_bond_to_the_last_owner() {
    let kit = Kit::new();
    let e = reclaim(&kit, b"alice");
    let built = ok(&kit, &e.spec, e.block);
    assert_eq!(built.tx.outputs[1].script_public_key, p2pk_spk(&e.n.fields.owner));
    assert_eq!(built.tx.outputs[1].value, kit.params.bond);
}

#[test]
fn grace_is_ten_days() {
    let kit = Kit::new();
    assert_eq!(kit.params.grace_ms, 864_000_000);
    let e = reclaim(&kit, b"alice");
    assert_eq!(e.spec.lock_time as i64, e.n.fields.expires_at + 10 * 24 * 3_600_000);
}

#[test]
fn reclaim_before_grace_ends_fails_in_the_script() {
    let kit = Kit::new();
    let mut e = reclaim(&kit, b"alice");
    // exactly expiresAt + grace works (the happy-path scenario)...
    ok(&kit, &e.spec, e.block);
    // ...one millisecond earlier does not
    e.spec.lock_time -= 1;
    fails_at(&kit, &e, 1);
    // at expiry, inside grace
    e.spec.lock_time = e.n.fields.expires_at as u64;
    fails_at(&kit, &e, 1);
}

#[test]
fn reclaim_before_grace_ends_fails_in_consensus() {
    // the lock time is right, but the block's median time has not passed it
    let kit = Kit::new();
    let e = reclaim(&kit, b"alice");
    let early = Block { time_ms: e.spec.lock_time, ..e.block };
    let err = rejected(&kit, &e.spec, early);
    assert!(err.contains("not finalized"), "{err}");
}

#[test]
fn reclaim_needs_a_timestamp_lock_and_an_unfinalized_name_input() {
    let kit = Kit::new();
    let mut e = reclaim(&kit, b"alice");
    e.spec.lock_time = COMMIT_DAA + 5; // DAA domain
    fails_at(&kit, &e, 1);
    let mut e = reclaim(&kit, b"alice");
    e.spec.inputs[1].sequence = u64::MAX;
    fails_at(&kit, &e, 1);
}

#[test]
fn reclaim_rejects_the_bond_paid_elsewhere() {
    let kit = Kit::new();
    // to the caller instead of the owner
    let mut e = reclaim(&kit, b"alice");
    e.spec.outputs[1].script_public_key = p2pk_spk(&xonly(&keypair(4)));
    fails_at(&kit, &e, 1);
    // one sompi short
    let mut e = reclaim(&kit, b"alice");
    e.spec.outputs[1].value -= 1;
    e.spec.outputs[2].value += 1;
    fails_at(&kit, &e, 1);
    // owner paid at output 2, caller at output 1
    let mut e = reclaim(&kit, b"alice");
    e.spec.outputs.swap(1, 2);
    fails_at(&kit, &e, 1);
    // no output 1 at all
    let mut e = reclaim(&kit, b"alice");
    e.spec.outputs.truncate(1);
    e.spec.outputs[0].value = kit.params.gap_value;
    fails_at(&kit, &e, 1);
}

#[test]
fn reclaim_may_pay_the_owner_more() {
    let kit = Kit::new();
    let mut e = reclaim(&kit, b"alice");
    e.spec.outputs[1].value += 5;
    e.spec.outputs[2].value -= 5;
    ok(&kit, &e.spec, e.block);
}

#[test]
fn reclaim_uses_the_stored_expiry() {
    // a renewed name (later expiresAt) cannot be reclaimed at the old time
    let kit = Kit::new();
    let mut e = reclaim(&kit, b"alice");
    e.n.fields = e.n.fields.with_expiry(e.n.fields.expires_at + YEAR_MS);
    e.n.utxo = kit.name_utxo(&e.n.fields, 20);
    e.spec.inputs[1] = Input::contract(e.n.utxo.clone(), &kit.name, e.n.fields.encode(), "reclaim", vec![]);
    fails_at(&kit, &e, 1);
}

#[test]
fn a_name_cannot_sit_at_seat_2() {
    // Seat 2 is trusted by lineage: it carries the registry id and is not a
    // name, because a name refuses every entry at seat 2 of a 3-input exit.
    let kit = Kit::new();
    for entry in ["release", "reclaim", "transfer", "renew"] {
        let mut e = release(&kit, b"alice");
        let other = NameFields::new(b"bobby", &e.n.fields.owner, 0, NOW_MS - 5 * YEAR_MS);
        let args = match entry {
            "release" => vec![Arg::Sig(e.n.owner)],
            "transfer" => vec![bytes(&other.owner), Arg::Sig(e.n.owner)],
            "renew" => vec![int(1)],
            _ => vec![],
        };
        e.spec.inputs[2] = Input::contract(kit.name_utxo(&other, 34), &kit.name, other.encode(), entry, args);
        e.spec.outputs.last_mut().unwrap().value -= kit.params.gap_value;
        e.spec.outputs.last_mut().unwrap().value += kit.params.bond;
        if entry == "reclaim" {
            e.spec.lock_time = (NOW_MS + 1) as u64;
            e.block = Block { time_ms: NOW_MS as u64 + 2, ..e.block };
        }
        input_fails(&kit, &e.spec, e.block, 2);
    }
}
