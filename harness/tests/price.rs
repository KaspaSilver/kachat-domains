//! The price record (registry v3): KachatPrice shards, read by register / extend /
//! renew, changed (prices, authority) only by the authority, all shards at once.

use kachat_names_harness::{scenarios::*, *};
use secp256k1::Keypair;

fn doubled(kit: &Kit) -> [u64; 5] {
    kit.params.prices.map(|p| p * 2)
}

/// A shard held by `authority` with `prices` (a UTXO under the real price covenant).
fn shard_utxo(kit: &Kit, shard: i64, authority: &[u8; 32], prices: &[u64; 5], tag: u8) -> Utxo {
    Utxo::new(
        TransactionOutpoint::new(TransactionId::from_bytes([tag; 32]), tag as u32),
        UtxoEntry::new(kit.params.price_value, kit.price.spk(&price_state(shard, authority, prices)), 1_000, false, Some(kit.price_id)),
    )
}

/// [`price_update`] for shards currently held by `holder` (rotated) and signed by `signer`.
fn update_by(kit: &Kit, holder: &[u8; 32], signer: Keypair, new_authority: &[u8; 32], prices: &[u64; 5]) -> TxSpec {
    let mut spec = price_update(kit, new_authority, prices);
    for i in 0..kit.params.price_shards as usize {
        let state = price_state(i as i64, holder, &kit.params.prices);
        let utxo = shard_utxo(kit, i as i64, holder, &kit.params.prices, 50 + i as u8);
        let entry = if i == 0 { "update" } else { "follow" };
        let mut args = vec![];
        if i == 0 {
            args.push(bytes(new_authority));
            args.extend(prices.iter().map(|p| int(*p as i64)));
            args.push(Arg::Sig(signer));
        }
        spec.inputs[i] = Input::contract(utxo, &kit.price, state, entry, args);
    }
    spec
}

// ---------------------------------------------------------------- use

#[test]
fn a_shard_is_read_and_comes_back_unchanged() {
    let kit = Kit::new();
    ok(&kit, &price_use_alone(&kit), active_block());
}

#[test]
fn use_refuses_a_changed_continuation() {
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    let base = price_use_alone(&kit);
    // cheaper prices, another authority, another shard number, a different value
    let mut cheaper = base.clone();
    cheaper.outputs[0] = kit.price_output(2, &ax, &[1; 5], 0);
    input_fails(&kit, &cheaper, active_block(), 0);
    let mut stolen = base.clone();
    stolen.outputs[0] = kit.price_output(2, &xonly(&keypair(9)), &kit.params.prices, 0);
    input_fails(&kit, &stolen, active_block(), 0);
    let mut renumbered = base.clone();
    renumbered.outputs[0] = kit.price_output(0, &ax, &kit.params.prices, 0);
    input_fails(&kit, &renumbered, active_block(), 0);
    let mut drained = base.clone();
    drained.outputs[0].value -= 1;
    drained.outputs[1].value += 1;
    input_fails(&kit, &drained, active_block(), 0);
}

#[test]
fn use_refuses_two_shards_or_an_extra_price_output() {
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    // a second shard read in the same transaction
    let mut two = price_use_alone(&kit);
    let (in2, out2) = kit.price_use(4, &kit.params.prices, 2, 62);
    two.inputs.push(in2);
    two.outputs.insert(1, out2);
    input_fails(&kit, &two, active_block(), 0);
    // a second price output minted by the one shard (a ninth shard)
    let mut extra = price_use_alone(&kit);
    extra.outputs.insert(1, kit.price_output(8, &ax, &[0; 5], 0));
    extra.outputs.last_mut().unwrap().value -= kit.params.price_value;
    input_fails(&kit, &extra, active_block(), 0);
}

// ---------------------------------------------------------------- reading prices

#[test]
fn register_pays_the_shards_price() {
    let kit = Kit::new();
    // a shard at double prices: the scenario's fee (genesis price) is too low...
    let mut r = register(&kit, b"alice", 1);
    let d = doubled(&kit);
    let (price_in, price_out) = kit.price_use(3, &d, REG_PRICE_IDX as u16, 13);
    r.spec.inputs[REG_PRICE_IDX] = price_in;
    r.spec.outputs[3] = price_out;
    input_fails(&kit, &r.spec, r.block, 0);
    // ...and paying the doubled price works
    r.spec.inputs[3].utxo.entry.amount += kit.params.price_for(5);
    r.adjust_fee(kit.params.price_for(5) as i64);
    ok(&kit, &r.spec, r.block);
}

#[test]
fn register_pays_less_once_prices_drop() {
    let kit = Kit::new();
    let mut r = register(&kit, b"alice", 1);
    let half = kit.params.prices.map(|p| p / 2);
    let (price_in, price_out) = kit.price_use(3, &half, REG_PRICE_IDX as u16, 13);
    r.spec.inputs[REG_PRICE_IDX] = price_in;
    r.spec.outputs[3] = price_out;
    r.adjust_fee(-((kit.params.price_for(5) / 2) as i64));
    ok(&kit, &r.spec, r.block);
}

#[test]
fn a_look_alike_shard_does_not_set_the_price() {
    // a plain P2SH output with the price template, free prices, but no price covenant id:
    // anyone could make one. The gap, the name refuse to read it.
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    let free = [0u64; 5];
    // the fake's address and its revealed redeem script agree (only the covenant id is missing)
    let fake_in = |state: Vec<u8>| {
        let utxo = Utxo::new(
            TransactionOutpoint::new(TransactionId::from_bytes([77; 32]), 0),
            UtxoEntry::new(kit.params.price_value, kit.price.spk(&state), 1_000, false, None),
        );
        Input::new(utxo, Unlock::Contract { tpl: kit.price.clone(), redeem: kit.price.redeem(&state), entry: "use".into(), args: vec![] })
    };
    let mut r = register(&kit, b"alice", 1);
    r.spec.inputs[REG_PRICE_IDX] = fake_in(price_state(3, &ax, &free));
    r.spec.outputs[3] = TransactionOutput::new(kit.params.price_value, kit.price.spk(&price_state(3, &ax, &free)));
    r.adjust_fee(-(kit.params.price_for(5) as i64)); // pays nothing
    input_fails(&kit, &r.spec, r.block, 0);

    // same for extend and renew
    let n = name_case(&kit, b"alice", 0);
    for (mut spec, blk) in [(extend(&kit, &n, 1), active_block()), (renew(&kit, &n, 1), window_block(&kit, &n))] {
        spec.inputs[PAID_PRICE_IDX] = fake_in(price_state(5, &ax, &free));
        spec.outputs[1] = TransactionOutput::new(kit.params.price_value, kit.price.spk(&price_state(5, &ax, &free)));
        let last = spec.outputs.len() - 1;
        spec.outputs[last].value += kit.params.price_for(5);
        input_fails(&kit, &spec, blk, 0);
    }
}

#[test]
fn the_price_index_must_point_at_a_shard() {
    let kit = Kit::new();
    // register: the gap, the commit, the funding, out of range, negative
    for idx in [0i64, 1, 3, 9, -1] {
        let mut r = register(&kit, b"alice", 1);
        r.spec.inputs[0].args_mut()[7] = int(idx);
        input_fails(&kit, &r.spec, r.block, 0);
    }
    // extend / renew: the name itself, the funding, out of range, negative
    let n = name_case(&kit, b"alice", 0);
    for idx in [0i64, 2, 9, -1] {
        let mut spec = extend(&kit, &n, 1);
        spec.inputs[0].args_mut()[1] = int(idx);
        input_fails(&kit, &spec, active_block(), 0);
        let mut spec = renew(&kit, &n, 1);
        spec.inputs[0].args_mut()[1] = int(idx);
        input_fails(&kit, &spec, window_block(&kit, &n), 0);
    }
}

#[test]
fn extend_and_renew_pay_the_shards_price() {
    let kit = Kit::new();
    let n = name_case(&kit, b"alice", 0);
    let d = doubled(&kit);
    for (mut spec, blk) in [(extend(&kit, &n, 1), active_block()), (renew(&kit, &n, 1), window_block(&kit, &n))] {
        let (price_in, price_out) = kit.price_use(5, &d, PAID_PRICE_IDX as u16, 24);
        spec.inputs[PAID_PRICE_IDX] = price_in;
        spec.outputs[1] = price_out;
        input_fails(&kit, &spec, blk, 0);
        spec.inputs[2].utxo.entry.amount += kit.params.price_for(5);
        ok(&kit, &spec, blk);
    }
}

// ---------------------------------------------------------------- update

#[test]
fn the_authority_changes_every_price_at_once() {
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    ok(&kit, &price_update(&kit, &ax, &doubled(&kit)), active_block());
    // instantly, in either direction, to zero and to the cap
    ok(&kit, &price_update(&kit, &ax, &kit.params.prices.map(|p| p / 10)), active_block());
    ok(&kit, &price_update(&kit, &ax, &[0; 5]), active_block());
    ok(&kit, &price_update(&kit, &ax, &[100_000_000_000_000_000; 5]), active_block());
}

/// Price state with signed prices (to write a negative one).
fn price_state_signed(shard: i64, authority: &[u8; 32], prices: &[i64; 5]) -> Vec<u8> {
    let mut v = [&[0x08u8][..], &num8(shard), &[0x20], authority].concat();
    for p in prices {
        v.push(0x08);
        v.extend(num8(*p));
    }
    v
}

#[test]
fn prices_are_refused_out_of_range() {
    // every shard's continuation carries the out-of-range price too, so only the range
    // check can refuse it
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    for bad in [-1i64, 100_000_000_000_000_001] {
        for tier in 0..5 {
            let mut prices = kit.params.prices.map(|p| p as i64);
            prices[tier] = bad;
            let mut spec = price_update(&kit, &ax, &kit.params.prices);
            spec.inputs[0].args_mut()[1 + tier] = int(bad);
            for j in 0..kit.params.price_shards as usize {
                let o = &mut spec.outputs[j];
                o.script_public_key = kit.price.spk(&price_state_signed(j as i64, &ax, &prices));
            }
            input_fails(&kit, &spec, active_block(), 0);
        }
    }
}

#[test]
fn a_change_mints_no_extra_shard() {
    // a follower authorizes a second price output - a ninth shard at free prices that
    // shard 0's per-position checks would never look at
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    let mut spec = price_update(&kit, &ax, &doubled(&kit));
    let k = kit.params.price_shards as usize;
    spec.outputs.insert(k, kit.price_output(8, &ax, &[0; 5], 3));
    spec.outputs.last_mut().unwrap().value -= kit.params.price_value;
    let built = kit.build(&spec);
    assert!(built.run_inputs().iter().take(k).any(|r| r.is_err()));
    assert!(kit.validate(&built, active_block()).is_err());
}

#[test]
fn a_change_cannot_hide_behind_a_use() {
    // shard 0 runs use() (unchanged, unsigned) while every other shard follows with free
    // prices: the followers never check their own state, so use() must refuse to share
    // the transaction with other shards
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    let mut spec = price_update(&kit, &ax, &[0; 5]);
    spec.inputs[0].set_entry("use", vec![]);
    spec.outputs[0] = kit.price_output(0, &ax, &kit.params.prices, 0);
    input_fails(&kit, &spec, active_block(), 0);
}

#[test]
fn only_the_authority_signs_a_change() {
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    for arg in [Arg::Sig(keypair(9)), Arg::Sig(keypair(1)), Arg::SigWithType(kit.authority, 0x81), Arg::SigWithType(kit.authority, 0x02)] {
        let mut spec = price_update(&kit, &ax, &doubled(&kit));
        let last = spec.inputs[0].args_mut().len() - 1;
        spec.inputs[0].args_mut()[last] = arg;
        input_fails(&kit, &spec, active_block(), 0);
    }
}

#[test]
fn a_change_needs_every_shard_in_order() {
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    let k = kit.params.price_shards as usize;
    // one shard left out (its continuation too)
    let mut missing = price_update(&kit, &ax, &doubled(&kit));
    missing.inputs.remove(k - 1);
    missing.outputs.remove(k - 1);
    for (i, o) in missing.outputs.iter_mut().enumerate().take(k - 1) {
        o.covenant.as_mut().unwrap().authorizing_input = i as u16;
    }
    missing.outputs.last_mut().unwrap().value += kit.params.price_value;
    input_fails(&kit, &missing, active_block(), 0);
    // two followers swapped (inputs out of shard order)
    let mut swapped = price_update(&kit, &ax, &doubled(&kit));
    swapped.inputs.swap(2, 3);
    swapped.outputs[2].covenant.as_mut().unwrap().authorizing_input = 3;
    swapped.outputs[3].covenant.as_mut().unwrap().authorizing_input = 2;
    input_fails(&kit, &swapped, active_block(), 2);
    // continuations out of order
    let mut crossed = price_update(&kit, &ax, &doubled(&kit));
    crossed.outputs.swap(4, 5);
    input_fails(&kit, &crossed, active_block(), 0);
}

#[test]
fn shard_zero_leads_and_followers_cannot_go_alone() {
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    // shard 1 tries to lead
    let mut spec = price_update(&kit, &ax, &doubled(&kit));
    let lead_args = spec.inputs[0].args_mut().clone();
    spec.inputs[0].set_entry("follow", vec![]);
    spec.inputs[1].set_entry("update", lead_args);
    input_fails(&kit, &spec, active_block(), 1);
    // nobody leads: every shard follows (and so the prices change unsigned)
    let mut spec = price_update(&kit, &ax, &doubled(&kit));
    spec.inputs[0].set_entry("follow", vec![]);
    input_fails(&kit, &spec, active_block(), 0);
    // a follower alone, moving its own state
    let utxo = kit.price_utxo(3, &kit.params.prices, 63);
    let lone = TxSpec {
        inputs: vec![Input::contract(utxo, &kit.price, price_state(3, &ax, &kit.params.prices), "follow", vec![])],
        outputs: vec![kit.price_output(3, &ax, &[0; 5], 0)],
        lock_time: 0,
    };
    input_fails(&kit, &lone, active_block(), 0);
}

#[test]
fn every_shard_gets_the_same_new_state() {
    // shard 0 checks every continuation: one shard cannot end up with other prices,
    // another authority, another number or another value
    let kit = Kit::new();
    let ax = xonly(&kit.authority);
    let d = doubled(&kit);
    let mut odd_prices = price_update(&kit, &ax, &d);
    odd_prices.outputs[5] = kit.price_output(5, &ax, &[0; 5], 5);
    input_fails(&kit, &odd_prices, active_block(), 0);
    let mut odd_key = price_update(&kit, &ax, &d);
    odd_key.outputs[5] = kit.price_output(5, &xonly(&keypair(9)), &d, 5);
    input_fails(&kit, &odd_key, active_block(), 0);
    let mut renumbered = price_update(&kit, &ax, &d);
    renumbered.outputs[5] = kit.price_output(6, &ax, &d, 5);
    input_fails(&kit, &renumbered, active_block(), 0);
    let mut drained = price_update(&kit, &ax, &d);
    drained.outputs[5].value -= 1;
    drained.outputs.last_mut().unwrap().value += 1;
    input_fails(&kit, &drained, active_block(), 0);
}

#[test]
fn the_authority_key_rotates() {
    let kit = Kit::new();
    let fresh = keypair(202);
    let fx = xonly(&fresh);
    // the current authority moves every shard to the new key (prices unchanged)
    ok(&kit, &price_update(&kit, &fx, &kit.params.prices), active_block());
    // the new key can then change prices; the old one no longer can
    ok(&kit, &update_by(&kit, &fx, fresh, &fx, &doubled(&kit)), active_block());
    input_fails(&kit, &update_by(&kit, &fx, kit.authority, &fx, &doubled(&kit)), active_block(), 0);
    // and the key can't be set to zero
    let spec = price_update(&kit, &[0; 32], &kit.params.prices);
    input_fails(&kit, &spec, active_block(), 0);
}
