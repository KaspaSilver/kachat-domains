//! KachatGap.register: happy paths and attacks.

use kachat_names_harness::{scenarios::*, *};

fn gap_fails(kit: &Kit, r: &Reg) {
    input_fails(kit, &r.spec, r.block, 0);
}

// ---------------------------------------------------------------- happy paths

#[test]
fn registers_every_price_tier_paying_exactly_the_price() {
    let kit = Kit::new();
    for name in [&b"a"[..], b"ab", b"abc", b"abcd", b"alice", b"kaspa-silver-0123456789-abcdefgh"] {
        let mut r = register(&kit, name, 1);
        // pay exactly price(len) as miner fee: no extra network fee on top
        r.adjust_fee(-(NET_FEE as i64));
        assert_eq!(r.fee() as u64, kit.params.price_for(name.len()));
        ok(&kit, &r.spec, r.block);
    }
}

#[test]
fn every_price_tier_rejects_one_sompi_less() {
    let kit = Kit::new();
    for name in [&b"a"[..], b"ab", b"abc", b"abcd", b"alice", b"kaspa-silver-0123456789-abcdefgh"] {
        let mut r = register(&kit, name, 1);
        r.adjust_fee(-(NET_FEE as i64) - 1);
        assert_eq!(r.fee() as u64, kit.params.price_for(name.len()) - 1);
        gap_fails(&kit, &r);
    }
}

#[test]
fn registers_with_digits_and_inner_hyphens() {
    let kit = Kit::new();
    for name in [&b"0"[..], b"a-b", b"x--y", b"007", b"k-a-s-p-a", b"z9"] {
        let r = register(&kit, name, 1);
        ok(&kit, &r.spec, r.block);
    }
}

#[test]
fn registers_several_years_up_front() {
    let kit = Kit::new();
    for years in [2, kit.params.max_years] {
        let r = register(&kit, b"alice", years);
        assert_eq!(r.name_fields(PERIOD).expires_at, NOW_MS + years * PERIOD);
        assert_eq!(r.fee() as u64, kit.params.register_cost(5, years) + NET_FEE);
        ok(&kit, &r.spec, r.block);
    }
}

#[test]
fn multi_year_registration_must_pay_every_year() {
    // max years (2), paying one sompi short of the first period plus a renewal (far more
    // than 1 period)
    let kit = Kit::new();
    let mut r = register(&kit, b"bob", kit.params.max_years);
    r.adjust_fee(-(NET_FEE as i64));
    assert_eq!(r.fee() as u64, kit.params.price_for(3) + kit.params.renew_price_for(3) * (kit.params.max_years as u64 - 1));
    ok(&kit, &r.spec, r.block);
    r.adjust_fee(-1);
    gap_fails(&kit, &r);
}

#[test]
fn register_charges_the_registration_price_once_then_the_renewal_price() {
    // registry v4: for every length tier, 1 period costs exactly the registration price and 2
    // periods the registration price plus one renewal; a sompi less is refused
    let kit = Kit::new();
    let p = &kit.params;
    for name in [&b"a"[..], b"ab", b"abc", b"abcd", b"abcde", b"kaspa-silver-0123456789-abcdefgh"] {
        for years in [1, p.max_years] {
            let mut r = register(&kit, name, years);
            r.adjust_fee(-(NET_FEE as i64));
            let due = p.price_for(name.len()) + p.renew_price_for(name.len()) * (years as u64 - 1);
            assert_eq!(r.fee() as u64, due, "{} x{years}", String::from_utf8_lossy(name));
            ok(&kit, &r.spec, r.block);
            r.adjust_fee(-1);
            gap_fails(&kit, &r);
        }
    }
    // the tables differ: a renewal is cheaper than a registration in every tier
    for len in 1..=5 {
        assert!(p.renew_price_for(len) < p.price_for(len));
    }
}

#[test]
fn registers_inside_a_narrow_gap() {
    let kit = Kit::new();
    let key = name_key(b"alice");
    let (lo, hi) = neighbours(&key);
    let r = register_in(&kit, b"alice", 1, &lo, &hi);
    ok(&kit, &r.spec, r.block);
}

// ---------------------------------------------------------------- years

#[test]
fn rejects_zero_years_and_more_than_max_years() {
    let kit = Kit::new();
    for years in [0, kit.params.max_years + 1, -1] {
        let mut r = register(&kit, b"alice", 1);
        r.spec.inputs[0].args_mut()[4] = int(years);
        // make the name output and the fee consistent with the claimed years, so only the
        // years bounds can refuse it (for 0 and -1 the expiry is now / a period ago, and the
        // fee already covers more than priceFor(len, years))
        let fields = NameFields::new(b"alice", &xonly(&r.owner), 0, NOW_MS, NOW_MS + years * PERIOD);
        r.spec.outputs[2] = kit.name_output(&fields, 0);
        if years > 0 {
            r.spec.inputs[2].utxo.entry.amount += kit.params.register_cost(5, years); // the funding
            assert!(r.fee() as u64 >= kit.params.register_cost(5, years));
        }
        gap_fails(&kit, &r);
    }
}

#[test]
fn register_sets_period_start_to_now() {
    let kit = Kit::new();
    for years in [1, 2] {
        let r = register(&kit, b"alice", years);
        let f = r.name_fields(PERIOD);
        assert_eq!((f.period_start, f.expires_at), (NOW_MS, NOW_MS + years * PERIOD));
        let built = ok(&kit, &r.spec, r.block);
        assert_eq!(built.tx.outputs[2].script_public_key, kit.name.spk(&f.encode()));
    }
    // any other periodStart is refused: an earlier one would let extend add
    // years, a later one would shorten nothing but is still not the rule
    for start in [NOW_MS - PERIOD, NOW_MS - 1, NOW_MS + 1, 0] {
        let mut r = register(&kit, b"alice", 1);
        r.spec.outputs[2] = kit.name_output(&NameFields { period_start: start, ..r.name_fields(PERIOD) }, 0);
        gap_fails(&kit, &r);
    }
}

#[test]
fn rejects_an_expiry_that_does_not_match_the_years_paid() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    let fields = NameFields::new(b"alice", &xonly(&r.owner), 0, NOW_MS, NOW_MS + 2 * PERIOD);
    r.spec.outputs[2] = kit.name_output(&fields, 0);
    gap_fails(&kit, &r);
}

// ---------------------------------------------------------------- commit

#[test]
fn rejects_a_registration_without_a_commit() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    let plain = kit.p2pk_utxo(&r.owner, COMMIT_VALUE, 13);
    r.spec.inputs[1] = Input::new(plain, Unlock::P2pk(r.owner));
    r.spec.inputs[1].sequence = kit.params.t_commit;
    gap_fails(&kit, &r);
}

fn with_commit(kit: &Kit, r: &mut Reg, name: &[u8], owner: &secp256k1::Keypair, salt: &[u8; 32]) {
    let ox = xonly(owner);
    let redeem = commit_redeem(&commitment(name, &ox, salt), &ox);
    let utxo = Utxo::new(
        TransactionOutpoint::new(TransactionId::from_bytes([14; 32]), 0),
        UtxoEntry::new(COMMIT_VALUE, kaspa_txscript::pay_to_script_hash_script(&redeem), COMMIT_DAA, false, None),
    );
    r.spec.inputs[1] = Input::new(utxo, Unlock::Commit { redeem, key: *owner });
    r.spec.inputs[1].sequence = kit.params.t_commit;
}

#[test]
fn rejects_a_commit_for_another_owner() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    let other = keypair(9);
    // someone else's (valid, signed) commit for the same name and salt
    let salt = r.salt;
    with_commit(&kit, &mut r, b"alice", &other, &salt);
    gap_fails(&kit, &r);
}

#[test]
fn rejects_a_front_runner_claiming_someone_elses_commit() {
    // The attacker sees the victim's register tx and replays it with their own
    // owner key: the victim's commit no longer matches (and the attacker could
    // not sign it anyway).
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    let attacker = xonly(&keypair(9));
    r.spec.inputs[0].args_mut()[1] = bytes(&attacker);
    let fields = NameFields::new(b"alice", &attacker, 0, NOW_MS, NOW_MS + PERIOD);
    r.spec.outputs[2] = kit.name_output(&fields, 0);
    gap_fails(&kit, &r);
}

#[test]
fn rejects_a_commit_for_another_name() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    let owner = r.owner;
    let salt = r.salt;
    with_commit(&kit, &mut r, b"alicf", &owner, &salt);
    gap_fails(&kit, &r);
}

#[test]
fn rejects_a_commit_with_another_salt() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    let owner = r.owner;
    with_commit(&kit, &mut r, b"alice", &owner, &[0x5b; 32]);
    gap_fails(&kit, &r);
}

#[test]
fn immature_commit_is_refused_by_consensus_sequence_lock() {
    let kit = Kit::new();
    let r = register(&kit, b"alice", 1);
    // scripts all pass in a block at exactly commitDaa + tCommit ...
    ok(&kit, &r.spec, r.block);
    // ... and one DAA earlier the same transaction is invalid (check_sequence_lock)
    let early = Block { daa: COMMIT_DAA + kit.params.t_commit - 1, ..r.block };
    let err = rejected(&kit, &r.spec, early);
    assert!(err.contains("sequence lock"), "{err}");
}

#[test]
fn rejects_a_commit_spent_with_a_short_relative_lock() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    r.spec.inputs[1].sequence = kit.params.t_commit - 1;
    gap_fails(&kit, &r);
    r.spec.inputs[1].sequence = 0;
    gap_fails(&kit, &r);
}

#[test]
fn rejects_a_commit_with_the_sequence_lock_disabled() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    // bit 63 makes consensus skip the relative lock entirely
    r.spec.inputs[1].sequence = (1u64 << 63) | kit.params.t_commit;
    gap_fails(&kit, &r);
    r.spec.inputs[1].sequence = u64::MAX;
    gap_fails(&kit, &r);
}

#[test]
fn high_sequence_bits_cannot_fake_maturity() {
    // consensus masks the relative lock to the low 32 bits; so does the gap
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    r.spec.inputs[1].sequence = (1u64 << 40) | (kit.params.t_commit - 1);
    gap_fails(&kit, &r);
    // a lock above 2^31 still reads as positive
    r.spec.inputs[1].sequence = 0x8000_0000;
    let early = Block { daa: COMMIT_DAA + 0x8000_0000 - 1, ..r.block };
    let built = kit.build(&r.spec);
    assert!(built.run_inputs().iter().all(|x| x.is_ok()));
    assert!(kit.validate(&built, early).is_err());
}

// ---------------------------------------------------------------- time lock

#[test]
fn now_cannot_be_in_the_future() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    r.spec.lock_time = (NOW_MS - 1) as u64; // tx lock time below `now`
    gap_fails(&kit, &r);
}

#[test]
fn now_must_be_in_the_past_of_the_block() {
    let kit = Kit::new();
    let r = register(&kit, b"alice", 1);
    let block = Block { time_ms: NOW_MS as u64, ..r.block }; // median time == lock time
    let err = rejected(&kit, &r.spec, block);
    assert!(err.contains("not finalized"), "{err}");
}

#[test]
fn now_needs_a_timestamp_lock_time_and_an_unfinalized_gap_input() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    r.spec.lock_time = COMMIT_DAA + 10_000; // DAA-domain lock time
    gap_fails(&kit, &r);
    let mut r = register(&kit, b"alice", 1);
    r.spec.inputs[0].sequence = u64::MAX; // a finalized input would skip finality
    gap_fails(&kit, &r);
}

#[test]
fn rejects_an_absurd_now() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    let now = 1_000_000_000_000_001i64; // above MAX_NOW
    r.spec.inputs[0].args_mut()[3] = int(now);
    r.spec.lock_time = now as u64;
    let fields = NameFields::new(b"alice", &xonly(&r.owner), 0, now, now + PERIOD);
    r.spec.outputs[2] = kit.name_output(&fields, 0);
    gap_fails(&kit, &r);
}

// ---------------------------------------------------------------- key range

#[test]
fn rejects_a_key_outside_the_gap() {
    let kit = Kit::new();
    let key = name_key(b"alice");
    let (lo, hi) = neighbours(&key);
    // gap entirely above the key
    let r = register_in(&kit, b"alice", 1, &hi, &FF32);
    gap_fails(&kit, &r);
    // gap entirely below the key
    let r = register_in(&kit, b"alice", 1, &ZERO32, &lo);
    gap_fails(&kit, &r);
}

#[test]
fn rejects_a_key_on_the_gap_boundary() {
    let kit = Kit::new();
    let key = name_key(b"alice");
    let r = register_in(&kit, b"alice", 1, &key, &FF32); // lo == key
    gap_fails(&kit, &r);
    let r = register_in(&kit, b"alice", 1, &ZERO32, &key); // hi == key
    gap_fails(&kit, &r);
}

#[test]
fn key_order_matches_unsigned_big_endian_reference() {
    // Differential test of the 5-step binary-search compare against Rust's
    // lexicographic order on [u8; 32]: gaps whose bounds differ from the key
    // in one byte at every position, by +-1 and by flipping the high bit.
    let kit = Kit::new();
    let key = name_key(b"alice");
    let mut cases = 0;
    for pos in 0..32 {
        for tweak in [1u8, 0x80, 0xff] {
            let mut b = key;
            b[pos] = b[pos].wrapping_add(tweak);
            let (lo, hi) = if b < key { (b, FF32) } else { (ZERO32, b) };
            let expected = lo < key && key < hi;
            let r = register_in(&kit, b"alice", 1, &lo, &hi);
            let built = kit.build(&r.spec);
            let script_ok = built.run_inputs()[0].is_ok();
            assert_eq!(script_ok, expected, "pos {pos} tweak {tweak:#x} lo {lo:?} hi {hi:?}");
            cases += 1;
        }
    }
    // and the key itself as either bound
    assert!(kit.build(&register_in(&kit, b"alice", 1, &key, &FF32).spec).run_inputs()[0].is_err());
    assert!(kit.build(&register_in(&kit, b"alice", 1, &ZERO32, &key).spec).run_inputs()[0].is_err());
    assert_eq!(cases, 96);
}

// ---------------------------------------------------------------- name rules

#[test]
fn rejects_bad_characters_and_lengths() {
    let kit = Kit::new();
    let long = [b'a'; 33];
    for name in [
        &b"Alice"[..],
        b"al_ice",
        b"al.ice",
        b"al ice",
        b"al\x00ce",
        b"\xc3\xa9t\xc3\xa9",
        b"al\xffce",
        b"-alice",
        b"alice-",
        b"-",
        b"",
        &long[..],
    ] {
        let r = register(&kit, name, 1);
        gap_fails(&kit, &r);
    }
}

// ---------------------------------------------------------------- outputs

#[test]
fn rejects_an_extra_registry_output() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    // a second copy of the name, also bound to the registry by input 0
    let fields = r.name_fields(PERIOD);
    r.spec.outputs.insert(3, kit.name_output(&fields, 0));
    r.spec.inputs[2].utxo.entry.amount += kit.params.bond; // the funding
    gap_fails(&kit, &r);
}

#[test]
fn rejects_moved_output_positions() {
    let kit = Kit::new();
    let r0 = register(&kit, b"alice", 1);
    // swap the two gaps
    let mut r = register(&kit, b"alice", 1);
    r.spec.outputs.swap(0, 1);
    gap_fails(&kit, &r);
    // name after the change
    let mut r = register(&kit, b"alice", 1);
    r.spec.outputs.swap(2, 3);
    gap_fails(&kit, &r);
    // change first
    let mut r = register(&kit, b"alice", 1);
    let change = r.spec.outputs.pop().unwrap();
    r.spec.outputs.insert(0, change);
    gap_fails(&kit, &r);
    drop(r0);
}

#[test]
fn rejects_an_unbound_name_at_output_2_with_a_forged_registry_output_after_it() {
    // Three registry outputs, the first two in place, but output 2 is the right name
    // *unbound* and the third registry output is a forged gap (00.., ff..) at 3: only
    // `OpCovOutputIdx(covId, 2) == 2` refuses it.
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    r.spec.outputs[2].covenant = None;
    r.spec.outputs.insert(3, kit.gap_output(&ZERO32, &FF32, 0));
    r.spec.inputs[2].utxo.entry.amount += kit.params.gap_value; // the funding
    gap_fails(&kit, &r);
}

#[test]
fn rejects_funding_from_another_covenant() {
    // C2: an input of another covenant (here a P2PK-locked UTXO carrying a foreign
    // covenant id) could have its value counted by both covenants' fee checks.
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    r.spec.inputs[2].utxo.entry.covenant_id = Some(Hash::from_bytes([0x99; 32]));
    gap_fails(&kit, &r);
}

#[test]
fn rejects_wrong_output_values() {
    let kit = Kit::new();
    for (idx, delta) in [(0usize, 1i64), (0, -1), (1, 1), (2, -1), (2, 1)] {
        let mut r = register(&kit, b"alice", 1);
        r.spec.outputs[idx].value = (r.spec.outputs[idx].value as i64 + delta) as u64;
        r.adjust_fee(delta); // keep the fee unchanged
        gap_fails(&kit, &r);
    }
}

#[test]
fn rejects_wrong_name_state() {
    let kit = Kit::new();
    let base = register(&kit, b"alice", 1).name_fields(PERIOD);
    let other = xonly(&keypair(9));
    for fields in [
        base.with_owner(&other),
        base.with_price(1),
        NameFields { name: pad_name(b"alicf"), ..base.clone() },
        NameFields { key: name_key(b"alicf"), ..base.clone() },
    ] {
        let mut r = register(&kit, b"alice", 1);
        r.spec.outputs[2] = kit.name_output(&fields, 0);
        gap_fails(&kit, &r);
    }
}

#[test]
fn rejects_a_forged_name_template() {
    // The registrant passes their own template bytes: the gap checks them
    // against the baked KachatName template hash.
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    let mut evil_suffix = kit.name.suffix.clone();
    evil_suffix.push(0x51); // OP_TRUE appended
    r.spec.inputs[0].args_mut()[6] = bytes(&evil_suffix);
    let state = r.name_fields(PERIOD).encode();
    let redeem = [kit.name.prefix.as_slice(), &state, &evil_suffix].concat();
    r.spec.outputs[2] = kit.registry_output(kit.params.bond, kaspa_txscript::pay_to_script_hash_script(&redeem), 0);
    gap_fails(&kit, &r);
}

#[test]
fn rejects_a_zero_owner_key() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    r.spec.inputs[0].args_mut()[1] = bytes(&ZERO32);
    gap_fails(&kit, &r);
}

// ---------------------------------------------------------------- shape

#[test]
fn rejects_the_gap_at_another_input_index() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    r.spec.inputs.swap(0, 2);
    for o in r.spec.outputs.iter_mut().take(3) {
        o.covenant.as_mut().unwrap().authorizing_input = 2;
    }
    input_fails(&kit, &r.spec, r.block, 2);
}

#[test]
fn rejects_two_registry_inputs() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    // a second gap as extra funding
    let (lo, _) = neighbours(&ZERO32.map(|_| 0x01));
    let extra = Input::contract(kit.gap_utxo(&lo, &[0x01; 32], 15), &kit.gap, gap_state(&lo, &[0x01; 32]), "absorbed", vec![]);
    r.spec.inputs.push(extra);
    gap_fails(&kit, &r);
}

#[test]
fn rejects_more_than_eight_inputs_or_outputs() {
    let kit = Kit::new();
    // 9 inputs
    // [gap, commit, funding] + 6 = 9
    let mut r = register(&kit, b"alice", 1);
    for t in 0..6u8 {
        r.spec.inputs.push(Input::new(kit.p2pk_utxo(&r.owner, kas(1), 100 + t), Unlock::P2pk(r.owner)));
    }
    r.spec.outputs.last_mut().unwrap().value += kas(6);
    assert_eq!(r.spec.inputs.len(), 9);
    gap_fails(&kit, &r);
    // exactly 8 is fine
    r.spec.inputs.pop();
    r.spec.outputs.last_mut().unwrap().value -= kas(1);
    ok(&kit, &r.spec, r.block);
    // 9 outputs
    let mut r = register(&kit, b"alice", 1);
    let ox = xonly(&r.owner);
    // [gap, gap, name, change] + 5 = 9
    r.spec.inputs[2].utxo.entry.amount += kas(5);
    for _ in 0..5 {
        r.spec.outputs.push(TransactionOutput::new(kas(1), p2pk_spk(&ox)));
    }
    assert_eq!(r.spec.outputs.len(), 9);
    gap_fails(&kit, &r);
    // exactly 8 is fine
    let extra = r.spec.outputs.pop().unwrap().value;
    r.spec.outputs.last_mut().unwrap().value += extra;
    ok(&kit, &r.spec, r.block);
}
