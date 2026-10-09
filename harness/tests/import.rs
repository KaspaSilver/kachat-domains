//! Registry v5: KachatGap.import (migration from a snapshot) and the register
//! deadline. Happy paths, then every way to cheat.

use kachat_names_harness::{scenarios::*, snapshot::Snapshot, *};

const DEADLINE: i64 = NOW_MS + 6 * 3_600_000;

fn names() -> Vec<SnapName> {
    vec![
        SnapName::new(b"alice", 1, NOW_MS - 86_400_000, NOW_MS + 86_400_000),
        SnapName::new(b"bob", 2, NOW_MS, NOW_MS + 2 * 86_400_000),
        // in grace at the snapshot: expired, still renewable
        SnapName::new(b"k", 3, NOW_MS - 2 * 86_400_000, NOW_MS - 3_600_000),
    ]
}

fn setup() -> (Kit, Snapshot, Vec<SnapName>) {
    let n = names();
    let (kit, snap) = v5_kit(&n, DEADLINE);
    (kit, snap, n)
}

fn import_fails(kit: &Kit, spec: &TxSpec) -> TxScriptError {
    input_fails(kit, spec, active_block(), 0)
}

// ---------------------------------------------------------------- the snapshot

#[test]
fn every_proof_rebuilds_the_root_and_proofs_are_640_bytes() {
    let (_, snap, n) = setup();
    for s in &n {
        let i = snap.index_of(&name_key(&s.name)).unwrap();
        let p = snap.proof(i);
        assert_eq!(p.len(), 640);
        assert_eq!(Snapshot::root_from(s.entry().leaf(), i, &p), snap.root());
    }
    // a larger, sparse tree: every 37th of 1,000 names
    let many: Vec<_> = (0..1000u32)
        .map(|i| snapshot::Entry { key: name_key(format!("n{i}").as_bytes()), owner: [7; 32], period_start: 1, expires_at: 2 })
        .collect();
    let big = Snapshot::new(many);
    for i in (0..1000).step_by(37) {
        assert_eq!(Snapshot::root_from(big.entries[i].leaf(), i, &big.proof(i)), big.root());
    }
    // the root moves with any field of any entry
    let mut changed = names();
    changed[1].expires_at += 1;
    assert_ne!(v5_kit(&changed, DEADLINE).1.root(), snap.root());
}

// ---------------------------------------------------------------- happy paths

#[test]
fn an_owner_imports_their_name_with_its_snapshot_owner_and_period() {
    let (kit, snap, n) = setup();
    for s in &n {
        let spec = import(&kit, &ImportArgs::of(&snap, s, false));
        let built = ok(&kit, &spec, active_block());
        assert_eq!(built.tx.outputs[2].script_public_key, kit.name.spk(&s.fields().encode()));
    }
}

#[test]
fn the_sponsor_imports_any_snapshot_name_for_its_owner() {
    let (kit, snap, n) = setup();
    for s in &n {
        ok(&kit, &import(&kit, &ImportArgs::of(&snap, s, true)), active_block());
    }
}

#[test]
fn import_needs_no_time_lock_and_works_before_and_after_the_deadline() {
    let (kit, snap, n) = setup();
    let spec = import(&kit, &ImportArgs::of(&snap, &n[0], true));
    assert_eq!(spec.lock_time, 0);
    ok(&kit, &spec, active_block());
    ok(&kit, &spec, block_after(DEADLINE + 86_400_000));
}

#[test]
fn imported_names_are_ordinary_names_afterwards() {
    // The name template is v4's, unchanged: an imported name transfers, lists and
    // extends as usual (here one paid a single period, so extend has room).
    let carol = vec![SnapName::new(b"carol", 4, NOW_MS, NOW_MS + 86_400_000)];
    let (kit, snap) = v5_kit(&carol, DEADLINE);
    let s = &carol[0];
    ok(&kit, &import(&kit, &ImportArgs::of(&snap, s, true)), active_block());
    let case = NameCase { fields: s.fields(), owner: s.owner, utxo: kit.name_utxo(&s.fields(), 20) };
    ok(&kit, &transfer(&kit, &case, &xonly(&keypair(5))), active_block());
    ok(&kit, &list(&kit, &case, 1_000), active_block());
    ok(&kit, &extend(&kit, &case, 1), active_block());
}

#[test]
fn a_name_in_grace_at_the_snapshot_is_imported_still_in_grace() {
    let (kit, snap, n) = setup();
    let k = &n[2];
    assert!(k.expires_at < NOW_MS && NOW_MS < k.expires_at + kit.params.grace_ms);
    ok(&kit, &import(&kit, &ImportArgs::of(&snap, k, false)), active_block());
}

// ---------------------------------------------------------------- authorization

#[test]
fn a_stranger_cannot_import() {
    let (kit, snap, n) = setup();
    let mut a = ImportArgs::of(&snap, &n[0], false);
    a.signer = keypair(66);
    import_fails(&kit, &import(&kit, &a));
    // ...nor the owner of another snapshot name
    a.signer = n[1].owner;
    import_fails(&kit, &import(&kit, &a));
}

#[test]
fn the_flag_must_match_the_signer() {
    let (kit, snap, n) = setup();
    let mut a = ImportArgs::of(&snap, &n[0], true);
    a.signer = n[0].owner; // owner signs but claims the sponsor did
    import_fails(&kit, &import(&kit, &a));
    let mut b = ImportArgs::of(&snap, &n[0], false);
    b.signer = sponsor(); // sponsor signs but claims the owner did
    import_fails(&kit, &import(&kit, &b));
}

#[test]
fn without_a_sponsor_only_owners_import() {
    let n = names();
    let snap = Snapshot::new(n.iter().map(SnapName::entry).collect());
    let kit = Kit::v5(Migration { root: snap.root(), deadline_ms: DEADLINE, sponsor: ZERO32 });
    ok(&kit, &import(&kit, &ImportArgs::of(&snap, &n[0], false)), active_block());
    import_fails(&kit, &import(&kit, &ImportArgs::of(&snap, &n[0], true)));
}

#[test]
fn import_signatures_must_be_sighash_all() {
    let (kit, snap, n) = setup();
    for t in [0x81u8, 0x02, 0x04] {
        let a = ImportArgs::of(&snap, &n[0], false);
        let mut spec = import(&kit, &a);
        if let Unlock::Contract { args, .. } = &mut spec.inputs[0].unlock {
            args[7] = Arg::SigWithType(a.signer, t);
        }
        import_fails(&kit, &spec);
    }
}

// ---------------------------------------------------------------- the proof

#[test]
fn the_claim_must_be_exactly_the_snapshot_entry() {
    let (kit, snap, n) = setup();
    let base = ImportArgs::of(&snap, &n[0], true);
    let mut wrong_owner = base.clone();
    wrong_owner.owner = xonly(&n[1].owner);
    let mut early = base.clone();
    early.period_start -= 1;
    let mut later = base.clone();
    later.expires_at += 1;
    let mut longer = base.clone();
    longer.expires_at += kit.params.period_ms;
    for a in [wrong_owner, early, later, longer] {
        import_fails(&kit, &import(&kit, &a));
    }
}

#[test]
fn a_name_outside_the_snapshot_cannot_be_imported() {
    let (kit, snap, n) = setup();
    // alice's proof, but for "mallory" (and mallory's own dates)
    let mut a = ImportArgs::of(&snap, &n[0], true);
    a.name = b"mallory".to_vec();
    import_fails(&kit, &import(&kit, &a));
}

#[test]
fn a_tampered_proof_or_index_fails() {
    let (kit, snap, n) = setup();
    let base = ImportArgs::of(&snap, &n[1], true);
    let mut flipped = base.clone();
    flipped.proof[5] ^= 1;
    let mut deep = base.clone();
    deep.proof[600] ^= 1;
    let mut other_index = base.clone();
    other_index.index ^= 1;
    let mut wrapped = base.clone();
    wrapped.index += 1 << 20; // same low bits, one level too many
    let mut negative = base.clone();
    negative.index = -1;
    let mut short = base.clone();
    short.proof.truncate(608);
    let mut long = base.clone();
    long.proof.extend([0u8; 32]);
    for a in [flipped, deep, other_index, wrapped, negative, short, long] {
        import_fails(&kit, &import(&kit, &a));
    }
}

#[test]
fn a_registry_without_a_predecessor_imports_nothing() {
    let kit = Kit::v5(Migration::NONE);
    let n = names();
    let snap = Snapshot::new(n.iter().map(SnapName::entry).collect());
    import_fails(&kit, &import(&kit, &ImportArgs::of(&snap, &n[0], false)));
}

#[test]
fn snapshot_dates_out_of_range_are_refused() {
    // Entries with absurd dates (a snapshot can only hold what the old registry did,
    // but the contract does not rely on that).
    let bad = vec![
        SnapName::new(b"neg", 1, -1, 5),
        SnapName::new(b"backwards", 2, 10, 9),
        SnapName::new(b"far", 3, 0, 100_000_000_000_000_001),
    ];
    let (kit, snap) = v5_kit(&bad, DEADLINE);
    for s in &bad {
        import_fails(&kit, &import(&kit, &ImportArgs::of(&snap, s, true)));
    }
}

// ---------------------------------------------------------------- outputs

#[test]
fn the_name_must_carry_the_snapshot_state_unlisted() {
    let (kit, snap, n) = setup();
    let a = ImportArgs::of(&snap, &n[0], true);
    let f = n[0].fields();
    let mut listed = f.clone();
    listed.price = 5;
    let mut moved = f.clone();
    moved.period_start += 1;
    let mut later = f.clone();
    later.expires_at += 1;
    let mut stolen = f.clone();
    stolen.owner = xonly(&sponsor());
    for out in [listed, moved, later, stolen] {
        import_fails(&kit, &import_in(&kit, &a, &ZERO32, &FF32, Some(out)));
    }
}

#[test]
fn the_gaps_and_values_are_checked_like_register() {
    let (kit, snap, n) = setup();
    let a = ImportArgs::of(&snap, &n[0], true);
    let key = name_key(&n[0].name);
    // wrong split
    let mut spec = import(&kit, &a);
    spec.outputs[0] = kit.gap_output(&ZERO32, &FF32, 0);
    import_fails(&kit, &spec);
    // wrong bond
    let mut spec = import(&kit, &a);
    spec.outputs[2].value -= 1;
    import_fails(&kit, &spec);
    // wrong gap value
    let mut spec = import(&kit, &a);
    spec.outputs[1].value += 1;
    import_fails(&kit, &spec);
    // a gap that does not hold the key (already imported: the key is a bound)
    import_fails(&kit, &import_in(&kit, &a, &key, &FF32, None));
    import_fails(&kit, &import_in(&kit, &a, &ZERO32, &key, None));
}

// ---------------------------------------------------------------- register

#[test]
fn register_is_closed_until_the_deadline() {
    let n = names();
    let (closed, _) = v5_kit(&n, NOW_MS + 1);
    let r = register(&closed, b"newname", 1);
    input_fails(&closed, &r.spec, r.block, 0);
    let (open, _) = v5_kit(&n, NOW_MS);
    let r = register(&open, b"newname", 1);
    ok(&open, &r.spec, r.block);
    // and with no predecessor at all
    let fresh = Kit::v5(Migration::NONE);
    let r = register(&fresh, b"newname", 1);
    ok(&fresh, &r.spec, r.block);
}

// ---------------------------------------------------------------- cost

#[test]
fn import_cost() {
    let (kit, snap, n) = setup();
    for (who, by_sponsor) in [("owner", false), ("sponsor", true)] {
        let built = ok(&kit, &import(&kit, &ImportArgs::of(&snap, &n[0], by_sponsor)), active_block());
        let c = kit.costs(&built);
        println!(
            "import by {who}: size {} B, compute {} g, transient {} g, storage {} g, min fee {:.5} KAS, budgets {:?} (units {:?})",
            c.size,
            c.compute_mass,
            c.transient_mass,
            c.storage_mass,
            c.min_fee as f64 / SOMPI_PER_KAS as f64,
            c.budgets,
            c.used_units
        );
        assert!(c.compute_mass < 100_000 && c.transient_mass < 250_000);
    }
    let r = register(&kit, b"alice", 1);
    let _ = r; // register is closed before the deadline: measured with an open kit
    let (open, _) = v5_kit(&names(), NOW_MS);
    let r = register(&open, b"newname", 1);
    let c = open.costs(&ok(&open, &r.spec, r.block));
    println!("v5 register 7 chars, 1 period: size {} B, compute {} g, min fee {:.5} KAS, budgets {:?}", c.size, c.compute_mass, c.min_fee as f64 / SOMPI_PER_KAS as f64, c.budgets);
}

// ---------------------------------------------------------------- found by the v5 mutation check

#[test]
fn a_negative_index_cannot_alias_a_leaf() {
    // -1 walks the same path as 1 (-1 % 2 = -1: right child; -1 / 2 = 0), so without the
    // sign check the entry at index 1 could be imported with index -1.
    let (kit, snap, n) = setup();
    let s = n.iter().find(|s| snap.index_of(&name_key(&s.name)) == Some(1)).unwrap();
    let mut a = ImportArgs::of(&snap, s, true);
    ok(&kit, &import(&kit, &a), active_block());
    a.index = -1;
    import_fails(&kit, &import(&kit, &a));
}

#[test]
fn the_lower_gap_value_is_checked() {
    let (kit, snap, n) = setup();
    let mut spec = import(&kit, &ImportArgs::of(&snap, &n[0], true));
    spec.outputs[0].value += 1;
    let last = spec.outputs.len() - 1;
    spec.outputs[last].value -= 1;
    import_fails(&kit, &spec);
}

#[test]
fn the_gap_must_be_input_0() {
    let (kit, snap, n) = setup();
    let mut spec = import(&kit, &ImportArgs::of(&snap, &n[0], true));
    spec.inputs.swap(0, 1);
    for o in spec.outputs.iter_mut().take(3) {
        o.covenant.as_mut().unwrap().authorizing_input = 1;
    }
    input_fails(&kit, &spec, active_block(), 1);
}

#[test]
fn an_unbound_name_at_output_2_with_a_forged_registry_output_after_it_fails() {
    // Only `OpCovOutputIdx(covId, 2) == 2` refuses this shape.
    let (kit, snap, n) = setup();
    let mut spec = import(&kit, &ImportArgs::of(&snap, &n[0], true));
    spec.outputs[2].covenant = None;
    spec.outputs.insert(3, kit.gap_output(&ZERO32, &FF32, 0));
    spec.inputs[1].utxo.entry.amount += kit.params.gap_value;
    import_fails(&kit, &spec);
}
