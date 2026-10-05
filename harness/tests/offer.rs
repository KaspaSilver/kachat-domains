//! KachatOffer: accept, withdraw, refund.

use kachat_names_harness::{scenarios::*, *};

const V: u64 = 300 * SOMPI_PER_KAS;

fn offer_fails(kit: &Kit, spec: &TxSpec, block: Block, idx: usize) {
    input_fails(kit, spec, block, idx);
}

// ---------------------------------------------------------------- accept

#[test]
fn owner_accepts_an_offer() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    ok(&kit, &accept(&kit, &o), active_block());
}

#[test]
fn accept_works_on_an_expired_name_and_keeps_its_expiry() {
    let kit = Kit::new();
    let mut o = offer_case(&kit, b"alice", V);
    o.n.fields = o.n.fields.with_expiry(NOW_MS - 2 * PERIOD);
    o.n.utxo = kit.name_utxo(&o.n.fields, 20);
    let spec = accept(&kit, &o);
    ok(&kit, &spec, active_block());
    // and refuses a continuation that changes the expiry
    let mut spec = accept(&kit, &o);
    spec.outputs[0] = kit.name_output(&o.n.fields.with_owner(&o.fields.buyer).with_expiry(NOW_MS + PERIOD), 0);
    let built = kit.build(&spec);
    let res = built.run_inputs();
    assert!(res[0].is_err() && res[1].is_err(), "{res:?}");
}

#[test]
fn accept_keeps_the_paid_period() {
    // a renewed name (periodStart = its old expiry) changes hands with its
    // period intact; a forged continuation that moves periodStart is refused
    // by the offer (and by the name's transfer)
    let kit = Kit::new();
    let mut o = offer_case(&kit, b"alice", V);
    o.n.fields = o.n.fields.renewed(1, PERIOD);
    o.n.utxo = kit.name_utxo(&o.n.fields, 20);
    let spec = accept(&kit, &o);
    let built = ok(&kit, &spec, active_block());
    let cont = o.n.fields.with_owner(&o.fields.buyer);
    assert_eq!((cont.period_start, cont.expires_at), (NOW_MS + PERIOD, NOW_MS + 2 * PERIOD));
    assert_eq!(built.tx.outputs[0].script_public_key, kit.name.spk(&cont.encode()));
    for start in [NOW_MS, NOW_MS + PERIOD - 1, NOW_MS + PERIOD + 1, cont.expires_at] {
        let mut spec = accept(&kit, &o);
        spec.outputs[0] = kit.name_output(&NameFields { period_start: start, ..cont.clone() }, 0);
        let built = kit.build(&spec);
        let res = built.run_inputs();
        assert!(res[0].is_err() && res[1].is_err(), "{res:?}");
        assert!(kit.validate(&built, active_block()).is_err());
    }
}

#[test]
fn accept_with_a_matched_listing_refuses_a_moved_period() {
    // the seller settles their listed name against an offer (name.buy +
    // offer.accept, the seller signing the offer): the offer itself refuses a
    // continuation whose periodStart moved
    let kit = Kit::new();
    let mut o = offer_case(&kit, b"alice", V);
    o.n.fields = o.n.fields.with_price(V as i64 - kit.params.offer_max_fee as i64);
    o.n.utxo = kit.name_utxo(&o.n.fields, 20);
    let price = o.n.fields.price as u64;
    let spec = TxSpec {
        inputs: vec![
            Input::contract(o.n.utxo.clone(), &kit.name, o.n.fields.encode(), "buy", vec![bytes(&o.fields.buyer)]),
            offer_input(&kit, &o, "accept", vec![int(0), Arg::Sig(o.n.owner)]),
        ],
        outputs: vec![
            kit.name_output(&o.n.fields.with_owner(&o.fields.buyer), 0),
            TransactionOutput::new(price, p2pk_spk(&o.n.fields.owner)),
        ],
        lock_time: 0,
    };
    ok(&kit, &spec, active_block());
    let mut forged = spec.clone();
    forged.outputs[0] = kit.name_output(&NameFields { period_start: NOW_MS + PERIOD, ..o.n.fields.with_owner(&o.fields.buyer) }, 0);
    let built = kit.build(&forged);
    let res = built.run_inputs();
    assert!(res[1].is_err(), "the offer must refuse a moved periodStart: {res:?}");
    assert!(kit.validate(&built, active_block()).is_err());
}

#[test]
fn accept_can_take_the_network_fee_up_to_max_fee() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    let mut spec = accept(&kit, &o);
    spec.outputs[1].value = V - kit.params.offer_max_fee;
    ok(&kit, &spec, active_block());
    spec.outputs[1].value -= 1;
    offer_fails(&kit, &spec, active_block(), 1);
}

#[test]
fn accept_rejects_paying_less_or_elsewhere() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    let mut spec = accept(&kit, &o);
    spec.outputs[1].value = V / 2;
    offer_fails(&kit, &spec, active_block(), 1);
    let mut spec = accept(&kit, &o);
    spec.outputs[1].script_public_key = p2pk_spk(&xonly(&keypair(9)));
    offer_fails(&kit, &spec, active_block(), 1);
    let mut spec = accept(&kit, &o);
    spec.outputs[1].script_public_key = p2pk_spk(&o.fields.buyer);
    offer_fails(&kit, &spec, active_block(), 1);
}

#[test]
fn accept_rejects_the_payout_at_another_index() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    let mut spec = accept(&kit, &o);
    let owner = o.n.fields.owner;
    spec.outputs[1].value = 1_000_000;
    spec.outputs.push(TransactionOutput::new(V - 2 * NET_FEE - 1_000_000 + NET_FEE, p2pk_spk(&owner)));
    offer_fails(&kit, &spec, active_block(), 1);
}

#[test]
fn accept_rejects_a_different_name() {
    let kit = Kit::new();
    let mut o = offer_case(&kit, b"alice", V);
    // the offer wants "alice", the owner settles it with "bobby"
    o.n.fields = NameFields::new(b"bobby", &o.n.fields.owner, 0, NOW_MS, NOW_MS + PERIOD);
    o.n.utxo = kit.name_utxo(&o.n.fields, 20);
    offer_fails(&kit, &accept(&kit, &o), active_block(), 1);
}

#[test]
fn accept_rejects_a_name_not_going_to_the_buyer() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    let mut spec = accept(&kit, &o);
    let me = o.n.fields.owner;
    spec.inputs[0].args_mut()[0] = bytes(&me); // owner transfers to themself
    spec.outputs[0] = kit.name_output(&o.n.fields.with_owner(&me), 0);
    offer_fails(&kit, &spec, active_block(), 1);
}

#[test]
fn accept_rejects_a_name_outside_the_registry() {
    // a perfect copy of the name (template + state) with no covenant id, or
    // with another covenant id
    let kit = Kit::new();
    for cov in [None, Some(Hash::from_bytes([0x99; 32]))] {
        let mut o = offer_case(&kit, b"alice", V);
        o.n.utxo.entry.covenant_id = cov;
        let mut spec = accept(&kit, &o);
        spec.outputs[0].covenant = cov.map(|id| CovenantBinding { authorizing_input: 0, covenant_id: id });
        let built = kit.build(&spec);
        assert!(built.run_inputs()[1].is_err());
        assert!(kit.validate(&built, active_block()).is_err());
    }
}

#[test]
fn one_name_cannot_settle_two_offers() {
    // Two offers from the same buyer for the same name, one payout: the owner
    // would pocket the second offer. The second offer is not right after the
    // name, so it refuses.
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    let o2 = OfferCase { utxo: kit.offer_utxo(&o.fields, V, 41), ..offer_case(&kit, b"alice", V) };
    let mut spec = accept(&kit, &o);
    spec.inputs.push(offer_input(&kit, &o2, "accept", vec![int(0), Arg::Sig(o.n.owner)]));
    spec.outputs.push(TransactionOutput::new(V - NET_FEE, p2pk_spk(&o.n.fields.owner)));
    let built = kit.build(&spec);
    let res = built.run_inputs();
    assert!(res[1].is_ok(), "{res:?}");
    assert!(res[2].is_err(), "{res:?}");
    assert!(kit.validate(&built, active_block()).is_err());
}

#[test]
fn accept_rejects_the_offer_away_from_its_name() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    let mut spec = accept(&kit, &o);
    // [offer, name] with nameIdx = 1
    spec.inputs.swap(0, 1);
    spec.inputs[1].utxo = o.n.utxo.clone();
    spec.inputs[0].args_mut()[0] = int(1);
    spec.outputs[0].covenant.as_mut().unwrap().authorizing_input = 1;
    offer_fails(&kit, &spec, active_block(), 0);
    // name index out of range / negative
    for idx in [-1i64, 5] {
        let mut spec = accept(&kit, &o);
        spec.inputs[1].args_mut()[0] = int(idx);
        offer_fails(&kit, &spec, active_block(), 1);
    }
}

#[test]
fn a_third_party_cannot_match_a_listing_with_an_offer() {
    // v2 let anyone run buy(newOwner = buyer) next to the buyer's offer and keep up to
    // maxFee. v3: accept needs the seller's signature, so a matcher can't settle it...
    let kit = Kit::new();
    let mut o = offer_case(&kit, b"alice", V);
    o.n.fields = o.n.fields.with_price((V / 2) as i64);
    o.n.utxo = kit.name_utxo(&o.n.fields, 20);
    let matcher = keypair(5);
    let matched = |signer: secp256k1::Keypair| TxSpec {
        inputs: vec![
            Input::contract(o.n.utxo.clone(), &kit.name, o.n.fields.encode(), "buy", vec![bytes(&o.fields.buyer)]),
            offer_input(&kit, &o, "accept", vec![int(0), Arg::Sig(signer)]),
        ],
        outputs: vec![
            kit.name_output(&o.n.fields.with_owner(&o.fields.buyer), 0),
            TransactionOutput::new(V - kit.params.offer_max_fee, p2pk_spk(&o.n.fields.owner)),
            TransactionOutput::new(kit.params.offer_max_fee - NET_FEE, p2pk_spk(&xonly(&matcher))),
        ],
        lock_time: 0,
    };
    offer_fails(&kit, &matched(matcher), active_block(), 1);
    // ...while the seller still may (it is their listing and their offer to take)
    ok(&kit, &matched(o.n.owner), active_block());
}

#[test]
fn accept_needs_the_sellers_signature() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    ok(&kit, &accept(&kit, &o), active_block());
    // someone else's key, the buyer's key, a non-ALL sighash
    for arg in [Arg::Sig(keypair(9)), Arg::Sig(o.buyer), Arg::SigWithType(o.n.owner, 0x81), Arg::SigWithType(o.n.owner, 0x02)] {
        let mut spec = accept(&kit, &o);
        spec.inputs[1].args_mut()[1] = arg;
        offer_fails(&kit, &spec, active_block(), 1);
    }
}

#[test]
fn an_offer_made_to_an_earlier_owner_cannot_be_accepted() {
    // the name changed hands after the offer: neither the new owner nor the old
    // seller can take it - every earlier offer ends with the change of owner
    let kit = Kit::new();
    let mut o = offer_case(&kit, b"alice", V);
    let new_owner = keypair(6);
    o.n.fields = o.n.fields.with_owner(&xonly(&new_owner));
    o.n.utxo = kit.name_utxo(&o.n.fields, 20);
    o.n.owner = new_owner;
    // the new owner transfers and signs the offer
    let spec = accept(&kit, &o);
    offer_fails(&kit, &spec, active_block(), 1);
    // the new owner transfers, the old seller signs the offer
    let mut spec = accept(&kit, &o);
    spec.inputs[1].args_mut()[1] = Arg::Sig(keypair(1));
    offer_fails(&kit, &spec, active_block(), 1);
}

// ---------------------------------------------------------------- decline

#[test]
fn the_seller_declines_any_time() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    ok(&kit, &decline(&kit, &o), active_block());
    // the fee may come out of the offer, up to maxFee
    let mut spec = decline(&kit, &o);
    spec.outputs[0].value = V - kit.params.offer_max_fee;
    ok(&kit, &spec, active_block());
}

#[test]
fn decline_rejects_anyone_but_the_seller() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    for arg in [Arg::Sig(keypair(9)), Arg::Sig(o.buyer), Arg::SigWithType(o.n.owner, 0x81)] {
        let mut spec = decline(&kit, &o);
        spec.inputs[0].args_mut()[0] = arg;
        offer_fails(&kit, &spec, active_block(), 0);
    }
}

#[test]
fn decline_pays_the_buyer_alone_and_in_full() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    // to someone else (the seller)
    let mut spec = decline(&kit, &o);
    spec.outputs[0] = TransactionOutput::new(V - NET_FEE, p2pk_spk(&o.n.fields.owner));
    offer_fails(&kit, &spec, active_block(), 0);
    // more than maxFee kept back
    let mut spec = decline(&kit, &o);
    spec.outputs[0].value = V - kit.params.offer_max_fee - 1;
    offer_fails(&kit, &spec, active_block(), 0);
    // a second output (the seller skims part of it)
    let mut spec = decline(&kit, &o);
    spec.outputs[0].value = V - kit.params.offer_max_fee;
    spec.outputs.push(TransactionOutput::new(1_000, p2pk_spk(&o.n.fields.owner)));
    spec.outputs[0].value -= 1_000;
    offer_fails(&kit, &spec, active_block(), 0);
    // not alone: another input pays the buyer's output
    let mut spec = decline(&kit, &o);
    let seller = o.n.owner;
    spec.inputs.push(Input::new(kit.p2pk_utxo(&seller, kas(1), 44), Unlock::P2pk(seller)));
    spec.outputs.push(TransactionOutput::new(kas(1) - NET_FEE, p2pk_spk(&xonly(&seller))));
    offer_fails(&kit, &spec, active_block(), 0);
}

// ---------------------------------------------------------------- withdraw

#[test]
fn buyer_withdraws_any_time() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    ok(&kit, &withdraw(&kit, &o), active_block());
}

#[test]
fn withdraw_rejects_anyone_but_the_buyer() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    for kp in [o.n.owner, keypair(9)] {
        let mut spec = withdraw(&kit, &o);
        spec.inputs[0].args_mut()[0] = Arg::Sig(kp);
        offer_fails(&kit, &spec, active_block(), 0);
    }
    let mut spec = withdraw(&kit, &o);
    spec.inputs[0].args_mut()[0] = Arg::SigWithType(o.buyer, 0x82);
    offer_fails(&kit, &spec, active_block(), 0);
}

// ---------------------------------------------------------------- refund

#[test]
fn anyone_refunds_after_refund_after() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    ok(&kit, &refund(&kit, &o), refund_block(&o));
}

#[test]
fn refund_before_refund_after_fails() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    // script: lock time below refundAfter
    let mut spec = refund(&kit, &o);
    spec.lock_time -= 1;
    offer_fails(&kit, &spec, refund_block(&o), 0);
    // consensus: lock time right, block not there yet
    let spec = refund(&kit, &o);
    let err = rejected(&kit, &spec, Block { daa: o.fields.refund_after as u64, ..refund_block(&o) });
    assert!(err.contains("not finalized"), "{err}");
    // a finalized input would dodge finality: refused by CLTV
    let mut spec = refund(&kit, &o);
    spec.inputs[0].sequence = u64::MAX;
    offer_fails(&kit, &spec, refund_block(&o), 0);
}

#[test]
fn refund_pays_only_the_buyer_and_only_alone() {
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    let mut spec = refund(&kit, &o);
    spec.outputs[0].script_public_key = p2pk_spk(&xonly(&keypair(9)));
    offer_fails(&kit, &spec, refund_block(&o), 0);
    let mut spec = refund(&kit, &o);
    spec.outputs[0].value = V - kit.params.offer_max_fee - 1;
    offer_fails(&kit, &spec, refund_block(&o), 0);
    // a second output (e.g. skimming to the caller)
    let mut spec = refund(&kit, &o);
    spec.outputs[0].value -= 1_000_000;
    spec.outputs.push(TransactionOutput::new(1_000_000, p2pk_spk(&xonly(&keypair(9)))));
    offer_fails(&kit, &spec, refund_block(&o), 0);
}

#[test]
fn two_refunds_cannot_share_one_output() {
    // Two offers from the same buyer refunded in one tx with one payout:
    // the caller would keep the other. Refunds must be alone.
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    let o2 = OfferCase { utxo: kit.offer_utxo(&o.fields, V, 42), ..offer_case(&kit, b"alice", V) };
    let mut spec = refund(&kit, &o);
    spec.inputs.push(offer_input(&kit, &o2, "refund", vec![]));
    spec.outputs.push(TransactionOutput::new(V - NET_FEE, p2pk_spk(&xonly(&keypair(9)))));
    let built = kit.build(&spec);
    let res = built.run_inputs();
    assert!(res[0].is_err() && res[1].is_err(), "{res:?}");
}

#[test]
fn a_refund_cannot_pay_a_listed_names_seller() {
    // The seller (Y) of a listed name also has an expired offer out. A buy()
    // whose payout output is also that refund's output would hand the name
    // over for Y's own money. Refunds must be 1-in/1-out, so this is refused.
    let kit = Kit::new();
    let mut n = name_case(&kit, b"alice", (V / 2) as i64);
    n.utxo = kit.name_utxo(&n.fields, 20);
    let seller_offer = OfferFields { key: name_key(b"zzzzz"), buyer: n.fields.owner, seller: xonly(&keypair(8)), refund_after: OFFER_REFUND_AFTER };
    let attacker = keypair(9);
    let spec = TxSpec {
        inputs: vec![
            Input::contract(n.utxo.clone(), &kit.name, n.fields.encode(), "buy", vec![bytes(&xonly(&attacker))]),
            Input::contract(kit.offer_utxo(&seller_offer, V, 43), &kit.offer, seller_offer.encode(), "refund", vec![]),
        ],
        outputs: vec![
            kit.name_output(&n.fields.with_owner(&xonly(&attacker)), 0),
            TransactionOutput::new(V - NET_FEE, p2pk_spk(&n.fields.owner)), // payout == refund output 1
        ],
        lock_time: OFFER_REFUND_AFTER as u64,
    };
    let built = kit.build(&spec);
    let res = built.run_inputs();
    assert!(res[0].is_ok(), "the buy alone would pass: {res:?}");
    assert!(res[1].is_err(), "the refund must refuse: {res:?}");
    assert!(kit.validate(&built, Block { daa: OFFER_REFUND_AFTER as u64 + 1, time_ms: NOW_MS as u64 }).is_err());
}

#[test]
fn two_refunds_cannot_burn_one_offer() {
    // Two offers of the same buyer, one output that covers only one of them:
    // the other offer's value would go to the miner. Refunds must be alone.
    let kit = Kit::new();
    let o = offer_case(&kit, b"alice", V);
    let o2 = OfferCase { utxo: kit.offer_utxo(&o.fields, V, 44), ..offer_case(&kit, b"alice", V) };
    let mut spec = refund(&kit, &o);
    spec.inputs.push(offer_input(&kit, &o2, "refund", vec![]));
    let built = kit.build(&spec);
    let res = built.run_inputs();
    assert!(res[0].is_err() && res[1].is_err(), "{res:?}");
    assert!(kit.validate(&built, refund_block(&o)).is_err());
}
