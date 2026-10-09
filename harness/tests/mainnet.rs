//! The mainnet registry as it launches: v4 (contracts/KachatGap.sil) under
//! params/mainnet.json (the year clock, the mainnet price tables). The other
//! suites run on testnet params; these pin the mainnet boundaries.

use kachat_names_harness::{scenarios::*, *};

const DAY: i64 = 86_400_000;
const YEAR: i64 = 365 * DAY;

fn kit() -> Kit {
    Kit::for_network("mainnet")
}

#[test]
fn mainnet_is_a_v4_registry_on_the_year_clock() {
    let kit = kit();
    let p = &kit.params;
    assert_eq!(p.registry_version, 4);
    assert!(p.migration.is_none());
    assert_eq!((p.period_ms, p.renew_window_ms, p.grace_ms), (YEAR, 30 * DAY, 90 * DAY));
    assert_eq!(p.max_years, 2);
    assert_eq!((p.bond, p.gap_value), (SOMPI_PER_KAS, SOMPI_PER_KAS));
    // the expiry arithmetic stays far inside the contracts' caps (MAX_NOW, MAX_EXPIRES_AT 1e17)
    assert!(p.max_years * p.period_ms <= 1_000_000_000_000);
}

#[test]
fn a_one_char_name_for_two_years_costs_exactly_5000_kas() {
    let kit = kit();
    let mut r = register(&kit, b"a", 2);
    // 4,000 KAS (the 1-char registration) + 1,000 KAS (a renewal year), nothing on top
    r.adjust_fee(-(NET_FEE as i64));
    assert_eq!(r.fee() as u64, 5_000 * SOMPI_PER_KAS);
    ok(&kit, &r.spec, r.block);
    let mut r = register(&kit, b"a", 2);
    r.adjust_fee(-(NET_FEE as i64) - 1);
    input_fails(&kit, &r.spec, r.block, 0);
}

#[test]
fn every_mainnet_tier_registers_at_its_price_and_not_one_sompi_less() {
    let kit = kit();
    for (name, kas) in [(&b"a"[..], 4_000u64), (b"ab", 2_000), (b"abc", 1_000), (b"abcd", 250), (b"kachat", 35)] {
        let mut r = register(&kit, name, 1);
        r.adjust_fee(-(NET_FEE as i64));
        assert_eq!(r.fee() as u64, kas * SOMPI_PER_KAS, "{}", String::from_utf8_lossy(name));
        ok(&kit, &r.spec, r.block);
        r.adjust_fee(-1);
        input_fails(&kit, &r.spec, r.block, 0);
    }
}

#[test]
fn renew_opens_30_days_before_the_expiry_to_the_millisecond() {
    let kit = kit();
    let n = name_case(&kit, b"kachat", 0);
    let opens = n.window_opens(&kit);
    assert_eq!(opens, n.fields.expires_at - 30 * DAY);
    ok(&kit, &renew(&kit, &n, 1), window_block(&kit, &n));
    input_fails(&kit, &renew_at(&kit, &n, 1, (opens - 1) as u64), block_after(opens + DAY), 0);
    // the renewal starts the next year at the old expiry
    let next = n.fields.renewed(1, YEAR);
    assert_eq!((next.period_start, next.expires_at), (n.fields.expires_at, n.fields.expires_at + YEAR));
}

#[test]
fn reclaim_opens_90_days_after_the_expiry_to_the_millisecond() {
    let kit = kit();
    let mut e = reclaim(&kit, b"kachat");
    assert_eq!(e.spec.lock_time as i64, e.n.fields.expires_at + 90 * DAY);
    ok(&kit, &e.spec, e.block);
    e.spec.lock_time -= 1;
    input_fails(&kit, &e.spec, e.block, 1);
}

#[test]
fn a_name_holds_at_most_two_years_past_its_period_start() {
    let kit = kit();
    let n = name_case(&kit, b"kachat", 0);
    ok(&kit, &extend(&kit, &n, 1), active_block());
    input_fails(&kit, &extend(&kit, &n, 2), active_block(), 0);
    let two = n.with_fields(&kit, n.fields.extended(1, YEAR));
    input_fails(&kit, &extend(&kit, &two, 1), active_block(), 0);
    // register for 3 years is refused, 2 passes
    let r = register(&kit, b"kachat", 2);
    ok(&kit, &r.spec, r.block);
    let r = register(&kit, b"kachat", 3);
    input_fails(&kit, &r.spec, r.block, 0);
}

#[test]
fn the_whole_lifecycle_on_mainnet_params() {
    // register, list, buy, renew in the window, release
    let kit = kit();
    let r = register(&kit, b"kachat", 1);
    ok(&kit, &r.spec, r.block);
    let n = name_case(&kit, b"kachat", 0);
    ok(&kit, &list(&kit, &n, 100 * SOMPI_PER_KAS as i64), active_block());
    let listed = n.with_fields(&kit, n.fields.with_price(100 * SOMPI_PER_KAS as i64));
    ok(&kit, &buy(&kit, &listed), active_block());
    ok(&kit, &renew(&kit, &n, 1), window_block(&kit, &n));
    let e = release(&kit, b"kachat");
    ok(&kit, &e.spec, e.block);
}
