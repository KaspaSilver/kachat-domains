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
use serde_json::{Value, json};
use std::time::{Duration, Instant};

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
    let parsed = keeper::offer_from_indexer(&row, Some(B)).unwrap();
    assert_eq!(parsed.outpoint, o.outpoint);
    assert_eq!(parsed.fields, o.fields, "rebuilt from the name, the addresses and refundAfter");
    assert_eq!(parsed.value, o.value);
    // another name gives another key, so the node lookup (by the state's address) misses
    let other = keeper::offer_from_indexer(&row, Some(A)).unwrap();
    assert_eq!(other.fields.key, name_key(A.as_bytes()));
    assert_ne!(other.fields, o.fields);
    // a row without a seller (a pre-v3 offer) is refused
    let mut old = row.clone();
    old.as_object_mut().unwrap().remove("seller");
    assert!(keeper::offer_from_indexer(&old, Some(B)).is_err());
    // /offers/refundable lists by key: no name needed, and a name that doesn't match is refused
    let mut by_key = row.clone();
    by_key["key"] = faster_hex::hex_string(&o.fields.key).into();
    assert_eq!(keeper::offer_from_indexer(&by_key, None).unwrap().fields, o.fields);
    assert!(keeper::offer_from_indexer(&by_key, Some(A)).is_err());
}

/// An indexer row for an offer on `name` (by name, as /names/<name>/offers lists it).
fn row(sim: &Sim, name: &str, index: u32) -> Value {
    let o = &sim.reg.as_ref().unwrap().offers[0];
    let addr = |k: &[u8; 32]| kachat_names_cli::net::p2pk_address(k).to_string();
    json!({
        "outpoint": { "txId": o.outpoint.transaction_id.to_string(), "index": index },
        "buyer": addr(&o.fields.buyer),
        "seller": addr(&o.fields.seller),
        "amount": "100000000",
        "refundAfter": 10,
        "name": name,
    })
}

fn names_page(names: &[&str]) -> Value {
    json!({ "names": names.iter().map(|n| json!({
        "name": n,
        "key": faster_hex::hex_string(&name_key(n.as_bytes())),
        "ownerKey": faster_hex::hex_string(&[3u8; 32]),
        "price": "0", "periodStart": 1, "expiresAt": 2,
    })).collect::<Vec<_>>() })
}

fn later() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

#[test]
fn one_failed_name_skips_only_that_name() {
    // DOM-036: no /offers/refundable (404); bravo's request fails (a 429), alpha's offers still come back
    let sim = with_an_offer();
    let c = keeper::collect_offers(
        |path, _| match path {
            "/offers/refundable" => Ok(None),
            "/names/all" => Ok(Some(names_page(&["alpha", "bravo", "charlie"]))),
            "/names/alpha/offers" => Ok(Some(json!({ "offers": [row(&sim, "alpha", 0)] }))),
            "/names/bravo/offers" => anyhow::bail!("HTTP 429 rate limited"),
            "/names/charlie/offers" => Ok(Some(json!({ "offers": [] }))),
            p => panic!("unexpected {p}"),
        },
        later(),
    )
    .unwrap();
    assert_eq!(c.offers.len(), 1);
    assert_eq!(c.offers[0].fields.key, name_key(b"alpha"));
    assert_eq!(c.skipped.len(), 1);
    assert_eq!(c.skipped[0].0, "bravo");
    assert!(c.source.contains("registered names only"));
}

#[test]
fn the_refundable_listing_is_used_when_the_indexer_has_it() {
    // DOM-037: /offers/refundable lists every open offer by key, also on names not registered now
    let sim = with_an_offer();
    let gone = name_key(b"released-name");
    let mut r = row(&sim, "x", 1);
    r.as_object_mut().unwrap().remove("name");
    r["key"] = faster_hex::hex_string(&gone).into();
    let pages = [json!({ "offers": [row(&sim, "alpha", 0)], "next": "p2" }), json!({ "offers": [r] })];
    let mut asked = vec![];
    let c = keeper::collect_offers(
        |path, cursor| {
            assert_eq!(path, "/offers/refundable", "no per-name requests when the listing exists");
            asked.push(cursor.map(str::to_string));
            Ok(Some(pages[asked.len() - 1].clone()))
        },
        later(),
    )
    .unwrap();
    assert_eq!(asked, [None, Some("p2".into())]);
    assert_eq!(c.offers.len(), 2);
    assert_eq!(c.offers[1].fields.key, gone);
    assert!(c.skipped.is_empty());
}

#[test]
fn a_spent_offer_is_a_race_not_a_failure() {
    for e in ["transaction 12ab is a double spend", "outpoint 12ab:0 is not in the UTXO set (spent by someone else)", "rejected: already spent"] {
        assert!(keeper::already_spent(e), "{e}");
    }
    for e in ["HTTP 500 internal", "fee too low", "timed out"] {
        assert!(!keeper::already_spent(e), "{e}");
    }
}

#[test]
fn a_planted_offer_with_an_invalid_key_is_skipped_not_fatal() {
    // DOM-039: anyone can plant an offer row with a zero (or off-curve) buyer; refundAfter 0
    // puts it first on every run. It must be skipped and reported, and the real offers behind
    // it still collected.
    let sim = with_an_offer();
    let mut planted = row(&sim, "x", 7);
    planted.as_object_mut().unwrap().remove("name");
    planted["key"] = faster_hex::hex_string(&name_key(b"bait")).into();
    planted["buyer"] = kachat_names_cli::net::p2pk_address(&[0u8; 32]).to_string().into();
    planted["refundAfter"] = 0.into();
    let pages = [json!({ "offers": [planted, row(&sim, "alpha", 0)], "next": "p2" }), json!({ "offers": [row(&sim, "bravo", 1)] })];
    let mut n = 0;
    let c = keeper::collect_offers(
        |_, _| {
            n += 1;
            Ok(Some(pages[n - 1].clone()))
        },
        later(),
    )
    .unwrap();
    assert_eq!(c.offers.iter().map(|o| o.outpoint.index).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(c.skipped.len(), 1);
    assert!(c.skipped[0].0.ends_with(":7"), "{:?}", c.skipped);
    assert!(c.skipped[0].1.contains("zero key"), "{:?}", c.skipped);
}

#[test]
fn an_offer_too_small_to_refund_is_skipped_not_a_failure() {
    // DOM-040: a planted offer with two real keys and 0.15 KAS: the refund would fall under the
    // CLI's floor, so the keeper skips it (and still refunds the normal offer next to it)
    let mut sim = with_an_offer();
    let normal = sim.reg.as_ref().unwrap().offers[0].clone();
    let max_fee = sim.templates.params.offer_max_fee;
    let mut tiny = normal.clone();
    tiny.value = 15_000_000;
    assert!(keeper::too_small(&tiny, max_fee));
    assert!(!keeper::too_small(&normal, max_fee));
    // the bound is the one the builder itself enforces
    let mut edge = normal.clone();
    edge.value = max_fee + ops::MIN_CHANGE;
    assert!(keeper::too_small(&edge, max_fee));
    sim.run(&Step::Wait(normal.fields.refund_after as u64 + 1 - sim.block.daa, "past refundAfter")).unwrap();
    let env = sim.env().unwrap();
    let ok = ops::refund_offer(&env, &normal, &sim.live(&normal.outpoint).unwrap()).unwrap();
    assert!(ok.is_valid());
}
