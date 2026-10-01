//! Prints template sizes and the cost of every operation (run with
//! `cargo test --test report -- --nocapture`). Also asserts each operation
//! stays far inside consensus and standardness limits.

use kachat_names_harness::{scenarios::*, *};

fn row(kit: &Kit, label: &str, spec: &TxSpec, block: Block, roles: &[&str]) -> String {
    let built = ok(kit, spec, block);
    let c = kit.costs(&built);
    // mempool standardness: P2SH sig-op scan <= 15 per input, standard outputs
    for (i, input) in built.tx.inputs.iter().enumerate() {
        let n = kaspa_txscript::post_toccata_p2sh_sig_scanner(&input.signature_script, &built.entries[i].script_public_key);
        assert!(n <= 15, "{label}: input {i} scans {n} sig ops");
    }
    for o in &built.tx.outputs {
        assert_ne!(kaspa_txscript::script_class::ScriptClass::from_script(&o.script_public_key), kaspa_txscript::script_class::ScriptClass::NonStandard);
    }
    // limits: compute/transient/storage each <= the 500_000-gram block limit
    // (transient 1_000_000 after Toccata), with lots of headroom
    assert!(c.compute_mass < 100_000 && c.storage_mass < 250_000 && c.transient_mass < 250_000, "{label}: {c:?}");
    let budgets: Vec<String> = roles
        .iter()
        .zip(c.budgets.iter().zip(c.used_units.iter()))
        .filter(|(r, _)| !r.is_empty())
        .map(|(r, (b, u))| format!("{r} {b} ({})", u.unwrap()))
        .collect();
    format!(
        "| {label} | {} | {} | {} | {} | {:.5} | {} |",
        c.size,
        c.compute_mass,
        c.normalized_transient,
        c.storage_mass,
        c.min_fee as f64 / SOMPI_PER_KAS as f64,
        budgets.join(", ")
    )
}

fn set_change(spec: &mut TxSpec, idx: usize, fee: u64) {
    spec.outputs[idx].value = 0;
    spec.outputs[idx].value = spec.total_in() - spec.total_out() - fee;
}

#[test]
fn print_costs() {
    let kit = Kit::new();
    println!("\n## Template sizes (bytes)\n");
    for t in [&kit.gap, &kit.name, &kit.offer] {
        println!(
            "- {}: {} (prefix {}, state {}, suffix {}), template hash {}",
            t.contract,
            t.bytecode.len(),
            t.prefix.len(),
            t.bytecode.len() - t.prefix.len() - t.suffix.len(),
            t.suffix.len(),
            faster_hex::hex_string(&t.template_hash)
        );
    }
    println!("\n## Operations\n");
    println!("| operation | size B | compute g | transient g (norm.) | storage g | min fee KAS | compute budget per contract input (script units used) |");
    println!("|---|---|---|---|---|---|---|");
    let r = register(&kit, b"alice", 1);
    println!("{}", row(&kit, "register 5-char, 1 year", &r.spec, r.block, &["gap.register", "commit", ""]));
    let r = register(&kit, b"kaspa-silver-0123456789-abcdefgh", 5);
    println!("{}", row(&kit, "register 32-char, 5 years", &r.spec, r.block, &["gap.register", "commit", ""]));
    // worst cases: longest name, most years, 8 inputs and 8 outputs
    let mut r = register(&kit, b"kaspa-silver-0123456789-abcdefgh", 5);
    let ox = xonly(&r.owner);
    for t in 0..5u8 {
        r.spec.inputs.push(Input::new(kit.p2pk_utxo(&r.owner, kas(1), 120 + t), Unlock::P2pk(r.owner)));
    }
    for _ in 0..4 {
        r.spec.outputs.push(TransactionOutput::new(kas(1), p2pk_spk(&ox)));
    }
    set_change(&mut r.spec, 3, kit.params.price_for(32) * 5 + NET_FEE);
    assert_eq!((r.spec.inputs.len(), r.spec.outputs.len()), (8, 8));
    println!("{}", row(&kit, "register worst case (32 chars, 5 y, 8 in, 8 out)", &r.spec, r.block, &["gap.register", "commit", "", "", "", "", "", ""]));
    let n = name_case(&kit, b"alice", 0);
    let mut s8 = renew(&kit, &n, 5);
    let payer = keypair(3);
    for t in 0..6u8 {
        s8.inputs.push(Input::new(kit.p2pk_utxo(&payer, kas(1), 130 + t), Unlock::P2pk(payer)));
    }
    for _ in 0..6 {
        s8.outputs.push(TransactionOutput::new(kas(1), p2pk_spk(&xonly(&payer))));
    }
    set_change(&mut s8, 1, kit.params.renew_price_for(5) * 5 + NET_FEE);
    assert_eq!((s8.inputs.len(), s8.outputs.len()), (8, 8));
    println!("{}", row(&kit, "renew worst case (5 y, 8 in, 8 out)", &s8, active_block(), &["name.renew", "", "", "", "", "", "", ""]));
    println!("{}", row(&kit, "transfer", &transfer(&kit, &n, &xonly(&keypair(7))), active_block(), &["name.transfer", ""]));
    println!("{}", row(&kit, "list", &list(&kit, &n, 10 * SOMPI_PER_KAS as i64), active_block(), &["name.list", ""]));
    let listed = name_case(&kit, b"alice", 10 * SOMPI_PER_KAS as i64);
    println!("{}", row(&kit, "buy", &buy(&kit, &listed), active_block(), &["name.buy", ""]));
    println!("{}", row(&kit, "renew 1 year", &renew(&kit, &n, 1), active_block(), &["name.renew", ""]));
    let e = release(&kit, b"alice");
    println!("{}", row(&kit, "release (exit)", &e.spec, e.block, &["gap.merge", "name.release", "gap.absorbed"]));
    let e = reclaim(&kit, b"alice");
    println!("{}", row(&kit, "reclaim (exit)", &e.spec, e.block, &["gap.merge", "name.reclaim", "gap.absorbed"]));
    let o = offer_case(&kit, b"alice", 300 * SOMPI_PER_KAS);
    println!("{}", row(&kit, "offer accept", &accept(&kit, &o), active_block(), &["name.transfer", "offer.accept"]));
    println!("{}", row(&kit, "offer withdraw", &withdraw(&kit, &o), active_block(), &["offer.withdraw"]));
    println!("{}", row(&kit, "offer refund", &refund(&kit, &o), refund_block(&o), &["offer.refund"]));
    // the refund's own fee comes out of the offer: it must fit maxFee
    let built = kit.build(&refund(&kit, &o));
    assert!(kit.costs(&built).min_fee <= kit.params.offer_max_fee);
}
