//! One chained history through every entry, each transaction spending the
//! real outputs of the previous ones: genesis -> register alice, bob ->
//! list, buy, renew, transfer alice -> offer on bob, accept -> release bob ->
//! reclaim alice -> the registry is the single genesis gap again.

use kachat_names_harness::{scenarios::*, *};

fn out(built: &Built, idx: u32, daa: u64) -> Utxo {
    let o = &built.tx.outputs[idx as usize];
    Utxo::new(
        TransactionOutpoint::new(built.tx.id(), idx),
        UtxoEntry::new(o.value, o.script_public_key.clone(), daa, false, o.covenant.map(|c| c.covenant_id)),
    )
}

struct Gap {
    lo: [u8; 32],
    hi: [u8; 32],
    utxo: Utxo,
}

fn register_name(kit: &Kit, gap: &Gap, name: &[u8], owner: &secp256k1::Keypair, years: i64, tag: u8) -> (Built, Block) {
    let p = &kit.params;
    let ox = xonly(owner);
    let salt = [tag; 32];
    let key = name_key(name);
    let price = p.price_for(name.len()) * years as u64;
    let redeem = commit_redeem(&commitment(name, &ox, &salt), &ox);
    let commit = Utxo::new(
        TransactionOutpoint::new(TransactionId::from_bytes([tag; 32]), 0),
        UtxoEntry::new(COMMIT_VALUE, kaspa_txscript::pay_to_script_hash_script(&redeem), COMMIT_DAA, false, None),
    );
    let mut commit_in = Input::new(commit, Unlock::Commit { redeem, key: *owner });
    commit_in.sequence = p.t_commit;
    let funding = kit.p2pk_utxo(owner, price + kas(5), tag.wrapping_add(1));
    let mut spec = TxSpec {
        inputs: vec![
            Input::contract(
                gap.utxo.clone(),
                &kit.gap,
                gap_state(&gap.lo, &gap.hi),
                "register",
                vec![bytes(name), bytes(&ox), bytes(&salt), int(NOW_MS), int(years), bytes(&kit.name.prefix), bytes(&kit.name.suffix)],
            ),
            commit_in,
            Input::new(funding, Unlock::P2pk(*owner)),
        ],
        outputs: vec![
            kit.gap_output(&gap.lo, &key, 0),
            kit.gap_output(&key, &gap.hi, 0),
            kit.name_output(&NameFields::new(name, &ox, 0, NOW_MS + years * YEAR_MS), 0),
        ],
        lock_time: NOW_MS as u64,
    };
    let change = spec.total_in() - spec.total_out() - price - NET_FEE;
    spec.outputs.push(TransactionOutput::new(change, p2pk_spk(&ox)));
    let block = Block { daa: (COMMIT_DAA + p.t_commit).max(gap.utxo.entry.block_daa_score + 1), time_ms: NOW_MS as u64 + 1 };
    (ok(kit, &spec, block), block)
}

#[test]
fn full_lifecycle_returns_the_registry_to_its_genesis_gap() {
    let kit = Kit::new();
    let alice_owner = keypair(1);
    let bob_owner = keypair(2);
    let buyer = keypair(3);
    let gifter = keypair(4);
    let carol = keypair(5);
    let reclaimer = keypair(6);

    let genesis = Gap { lo: ZERO32, hi: FF32, utxo: out(&kit.genesis_tx, 0, 1_000) };

    // register alice (2 years) in the genesis gap
    let (reg_a, b0) = register_name(&kit, &genesis, b"alice", &alice_owner, 2, 50);
    let ka = name_key(b"alice");
    let below_a = Gap { lo: ZERO32, hi: ka, utxo: out(&reg_a, 0, b0.daa) };
    let above_a = Gap { lo: ka, hi: FF32, utxo: out(&reg_a, 1, b0.daa) };
    let mut alice = NameFields::new(b"alice", &xonly(&alice_owner), 0, NOW_MS + 2 * YEAR_MS);
    let mut alice_utxo = out(&reg_a, 2, b0.daa);

    // register bob in whichever gap holds its key
    let kb = name_key(b"bob");
    let host = if kb < ka { below_a } else { above_a };
    let (other_side, host) = if kb < ka {
        (Gap { lo: ka, hi: FF32, utxo: out(&reg_a, 1, b0.daa) }, host)
    } else {
        (Gap { lo: ZERO32, hi: ka, utxo: out(&reg_a, 0, b0.daa) }, host)
    };
    let (reg_b, b1) = register_name(&kit, &host, b"bob", &bob_owner, 1, 60);
    let gap_lo_b = Gap { lo: host.lo, hi: kb, utxo: out(&reg_b, 0, b1.daa) };
    let gap_b_hi = Gap { lo: kb, hi: host.hi, utxo: out(&reg_b, 1, b1.daa) };
    let mut bob = NameFields::new(b"bob", &xonly(&bob_owner), 0, NOW_MS + YEAR_MS);
    let mut bob_utxo = out(&reg_b, 2, b1.daa);

    let blk = active_block();

    // list alice at 500 KAS
    let price = 500 * SOMPI_PER_KAS as i64;
    let f = kit.p2pk_utxo(&alice_owner, kas(1), 70);
    let mut spec = TxSpec {
        inputs: vec![
            Input::contract(alice_utxo.clone(), &kit.name, alice.encode(), "list", vec![int(price), Arg::Sig(alice_owner)]),
            Input::new(f, Unlock::P2pk(alice_owner)),
        ],
        outputs: vec![kit.name_output(&alice.with_price(price), 0)],
        lock_time: 0,
    };
    spec.outputs.push(TransactionOutput::new(spec.total_in() - spec.total_out() - NET_FEE, p2pk_spk(&alice.owner)));
    let t = ok(&kit, &spec, blk);
    alice = alice.with_price(price);
    alice_utxo = out(&t, 0, blk.daa);

    // buyer buys alice
    let bx = xonly(&buyer);
    let f = kit.p2pk_utxo(&buyer, price as u64 + kas(2), 71);
    let mut spec = TxSpec {
        inputs: vec![
            Input::contract(alice_utxo.clone(), &kit.name, alice.encode(), "buy", vec![bytes(&bx)]),
            Input::new(f, Unlock::P2pk(buyer)),
        ],
        outputs: vec![kit.name_output(&alice.with_owner(&bx), 0), TransactionOutput::new(price as u64, p2pk_spk(&alice.owner))],
        lock_time: 0,
    };
    spec.outputs.push(TransactionOutput::new(spec.total_in() - spec.total_out() - NET_FEE, p2pk_spk(&bx)));
    let t = ok(&kit, &spec, blk);
    alice = alice.with_owner(&bx);
    alice_utxo = out(&t, 0, blk.daa);

    // a gifter renews alice for 3 years
    let due = kit.params.renew_price_for(5) * 3;
    let f = kit.p2pk_utxo(&gifter, due + kas(2), 72);
    let mut spec = TxSpec {
        inputs: vec![
            Input::contract(alice_utxo.clone(), &kit.name, alice.encode(), "renew", vec![int(3)]),
            Input::new(f, Unlock::P2pk(gifter)),
        ],
        outputs: vec![kit.name_output(&alice.with_expiry(alice.expires_at + 3 * YEAR_MS), 0)],
        lock_time: 0,
    };
    spec.outputs.push(TransactionOutput::new(spec.total_in() - spec.total_out() - due - NET_FEE, p2pk_spk(&xonly(&gifter))));
    let t = ok(&kit, &spec, blk);
    alice = alice.with_expiry(alice.expires_at + 3 * YEAR_MS);
    alice_utxo = out(&t, 0, blk.daa);
    assert_eq!(alice.expires_at, NOW_MS + 5 * YEAR_MS);

    // carol offers 40 KAS for bob; bob's owner accepts
    let offer = OfferFields { key: kb, buyer: xonly(&carol), refund_after: OFFER_REFUND_AFTER };
    let ov = kas(40);
    let offer_utxo = kit.offer_utxo(&offer, ov, 73);
    let spec = TxSpec {
        inputs: vec![
            Input::contract(bob_utxo.clone(), &kit.name, bob.encode(), "transfer", vec![bytes(&offer.buyer), Arg::Sig(bob_owner)]),
            Input::contract(offer_utxo, &kit.offer, offer.encode(), "accept", vec![int(0)]),
        ],
        outputs: vec![kit.name_output(&bob.with_owner(&offer.buyer), 0), TransactionOutput::new(ov - NET_FEE, p2pk_spk(&bob.owner))],
        lock_time: 0,
    };
    let t = ok(&kit, &spec, blk);
    bob = bob.with_owner(&offer.buyer);
    bob_utxo = out(&t, 0, blk.daa);

    // carol releases bob: its two gaps merge back into the host gap
    let mut spec = TxSpec {
        inputs: vec![
            Input::contract(gap_lo_b.utxo.clone(), &kit.gap, gap_state(&gap_lo_b.lo, &gap_lo_b.hi), "merge", vec![]),
            Input::contract(bob_utxo.clone(), &kit.name, bob.encode(), "release", vec![Arg::Sig(carol)]),
            Input::contract(gap_b_hi.utxo.clone(), &kit.gap, gap_state(&gap_b_hi.lo, &gap_b_hi.hi), "absorbed", vec![]),
        ],
        outputs: vec![kit.gap_output(&host.lo, &host.hi, 0)],
        lock_time: 0,
    };
    spec.outputs.push(TransactionOutput::new(spec.total_in() - spec.total_out() - NET_FEE, p2pk_spk(&xonly(&carol))));
    let t = ok(&kit, &spec, blk);
    let host_again = Gap { lo: host.lo, hi: host.hi, utxo: out(&t, 0, blk.daa) };

    // alice lapses; after expiresAt + grace anyone reclaims it
    let (below, above) = if kb < ka { (host_again, other_side) } else { (other_side, host_again) };
    assert_eq!((below.lo, below.hi, above.lo, above.hi), (ZERO32, ka, ka, FF32));
    let unlock = (alice.expires_at + kit.params.grace_ms) as u64;
    let mut spec = TxSpec {
        inputs: vec![
            Input::contract(below.utxo.clone(), &kit.gap, gap_state(&below.lo, &below.hi), "merge", vec![]),
            Input::contract(alice_utxo.clone(), &kit.name, alice.encode(), "reclaim", vec![]),
            Input::contract(above.utxo.clone(), &kit.gap, gap_state(&above.lo, &above.hi), "absorbed", vec![]),
        ],
        outputs: vec![kit.gap_output(&ZERO32, &FF32, 0), TransactionOutput::new(kit.params.bond, p2pk_spk(&alice.owner))],
        lock_time: unlock,
    };
    spec.outputs.push(TransactionOutput::new(spec.total_in() - spec.total_out() - NET_FEE, p2pk_spk(&xonly(&reclaimer))));
    let late = Block { daa: blk.daa + 100_000_000, time_ms: unlock + 1 };
    let t = ok(&kit, &spec, late);

    // the registry is the single genesis gap again
    assert_eq!(t.tx.outputs[0].script_public_key, kit.genesis_tx.tx.outputs[0].script_public_key);
    assert_eq!(t.tx.outputs[0].value, kit.params.gap_value);
    assert_eq!(t.tx.outputs[0].covenant.unwrap().covenant_id, kit.registry_id);

    // and "alice" can be registered again from it
    let fresh = Gap { lo: ZERO32, hi: FF32, utxo: out(&t, 0, late.daa) };
    let (_again, _) = register_name(&kit, &fresh, b"alice", &carol, 1, 80);
}
