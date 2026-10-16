//! The offer refund keeper (`refund-expired`, audit DOM-002): which offers are due, the
//! indexer's offer rows, and a refund built for an expired offer on a simulated registry.

use std::path::{Path, PathBuf};

use kachat_names_cli::{
    keeper,
    ops::{self, Templates},
    plan::{A, B, Sim, Step, e2e_steps},
    util::SOMPI,
};
use kachat_names_harness::{name_key, p2pk_spk};
use serde_json::json;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// The e2e plan up to (and including) the first offer, on bravo-tn, refundable 100,000
/// DAA after it was made.
fn with_an_offer() -> Sim {
    let mut sim = Sim::new(Templates::load(&repo()), 100 * SOMPI, 1_800_000_000_000);
    for (step, _) in e2e_steps() {
        let stop = matches!(step, Step::Offer(..));
        sim.run(&step).unwrap_or_else(|e| panic!("{step:?}: {e}"));
        if stop {
            break;
        }
    }
    sim
}

#[test]
fn an_offer_is_due_only_once_the_daa_passed_its_refund_after() {
    let mut sim = with_an_offer();
    let offers = sim.reg.as_ref().unwrap().offers.clone();
    assert_eq!(offers.len(), 1);
    let ra = offers[0].fields.refund_after as u64;
    assert!(keeper::due(&offers, sim.block.daa).is_empty());
    assert!(keeper::due(&offers, ra).is_empty(), "at refundAfter itself the lock time is not final yet");
    assert_eq!(keeper::due(&offers, ra + 1).len(), 1);

    // past refundAfter: the keeper's refund is valid and pays the buyer, less a capped fee
    sim.run(&Step::Wait(ra + 1 - sim.block.daa, "past refundAfter")).unwrap();
    let due = keeper::due(&offers, sim.block.daa);
    let o = &due[0];
    let env = sim.env().unwrap();
    let plan = ops::refund_offer(&env, o, &sim.live(&o.outpoint).unwrap()).unwrap();
    assert!(plan.is_valid(), "{:?}", plan.validation);
    let out = &plan.built.tx.outputs;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].script_public_key, p2pk_spk(&o.fields.buyer));
    assert!(out[0].value >= o.value - env.kit.params.offer_max_fee);
    assert_eq!(plan.built.tx.inputs.len(), 1, "no funding: the fee comes out of the offer");
}

#[test]
fn indexer_offer_rows_parse_into_the_offer_state() {
    let sim = with_an_offer();
    let o = sim.reg.as_ref().unwrap().offers[0].clone();
    let addr = |k: &[u8; 32]| kachat_names_cli::net::p2pk_address(k).to_string();
    let row = json!({
        "outpoint": { "txId": o.outpoint.transaction_id.to_string(), "index": o.outpoint.index },
        "buyer": addr(&o.fields.buyer),
        "seller": addr(&o.fields.seller),
        "amount": o.value.to_string(),
        "refundAfter": o.fields.refund_after,
        "refundable": false,
    });
    let parsed = keeper::offer_from_indexer(&row, B).unwrap();
    assert_eq!(parsed.outpoint, o.outpoint);
    assert_eq!(parsed.fields, o.fields, "rebuilt from the name, the addresses and refundAfter");
    assert_eq!(parsed.value, o.value);
    // another name gives another key, so the node lookup (by the state's address) misses
    let other = keeper::offer_from_indexer(&row, A).unwrap();
    assert_eq!(other.fields.key, name_key(A.as_bytes()));
    assert_ne!(other.fields, o.fields);
    // a row without a seller (a pre-v3 offer) is refused
    let mut old = row.clone();
    old.as_object_mut().unwrap().remove("seller");
    assert!(keeper::offer_from_indexer(&old, B).is_err());
}
