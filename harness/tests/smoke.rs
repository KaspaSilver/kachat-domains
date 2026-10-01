use kachat_names_harness::{scenarios::*, *};

#[test]
fn genesis_and_one_registration() {
    let kit = Kit::new();
    kit.validate(&kit.genesis_tx, Block { daa: 2_000, time_ms: NOW_MS as u64 }).expect("genesis");
    let r = register(&kit, b"alice", 1);
    let built = ok(&kit, &r.spec, r.block);
    println!("{:?}", kit.costs(&built));
}
