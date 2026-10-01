//! Prints template sizes and the cost of every operation (run with
//! `cargo test --test report -- --nocapture`). Also asserts each operation
//! stays far inside consensus and standardness limits.

use kachat_names_harness::{scenarios::*, *};

fn row(kit: &Kit, label: &str, spec: &TxSpec, block: Block, roles: &[&str]) -> String {
    let built = ok(kit, spec, block);
    let c = kit.costs(&built);
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
    let n = name_case(&kit, b"alice", 0);
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
