//! `verify --live --indexer`: the `/names/all` paging is bounded (DOM-035). A broken
//! or hostile indexer gets an error, never a hang.

use std::time::{Duration, Instant};

use kachat_names_cli::prove::collect_pages;
use kachat_names_harness::{keypair, name_key, xonly};
use serde_json::{Value, json};

fn name(n: &str) -> Value {
    json!({
        "name": n,
        "key": faster_hex::hex_string(&name_key(n.as_bytes())),
        "ownerKey": faster_hex::hex_string(&xonly(&keypair(5))),
        "price": "0",
        "periodStart": 1_800_000_000_000i64,
        "expiresAt": 1_800_086_400_000i64,
    })
}

fn later() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

#[test]
fn pages_are_followed_to_the_end() {
    let pages = [json!({ "names": [name("alpha")], "next": "c1" }), json!({ "names": [name("bravo")], "next": "c2" }), json!({ "names": [name("charlie")] })];
    let mut asked = vec![];
    let claims = collect_pages(
        |c| {
            asked.push(c.map(str::to_string));
            Ok(pages[asked.len() - 1].clone())
        },
        later(),
    )
    .unwrap();
    assert_eq!(claims.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["alpha", "bravo", "charlie"]);
    assert_eq!(asked, [None, Some("c1".into()), Some("c2".into())]);
}

#[test]
fn a_repeated_cursor_is_an_error_not_a_loop() {
    let mut calls = 0;
    let err = collect_pages(
        |_| {
            calls += 1;
            assert!(calls < 10, "still looping");
            Ok(json!({ "names": [], "next": "same" }))
        },
        later(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("second time"), "{err}");
    assert_eq!(calls, 2);
}

#[test]
fn the_deadline_stops_a_listing_that_never_ends() {
    let mut i = 0u64;
    let err = collect_pages(
        |_| {
            i += 1;
            std::thread::sleep(Duration::from_millis(20));
            Ok(json!({ "names": [], "next": format!("c{i}") }))
        },
        Instant::now() + Duration::from_millis(100),
    )
    .unwrap_err();
    assert!(err.to_string().contains("deadline"), "{err}");
}

#[test]
fn more_names_than_a_registry_can_hold_is_an_error() {
    let one = name("alpha");
    let big = Value::Array(vec![one; kachat_names_cli::prove::MAX_CLAIMS + 1]);
    let err = collect_pages(|_| Ok(json!({ "names": big.clone() })), later()).unwrap_err();
    assert!(err.to_string().contains("more than"), "{err}");
}
