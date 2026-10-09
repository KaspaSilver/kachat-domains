//! `--network mainnet`: every network value switches, and the mainnet
//! registry (v4, params/mainnet.json, artifacts/mainnet) runs end to end in
//! the simulator under mainnet consensus params. Its own test binary: the
//! network is chosen once per process.

use std::path::{Path, PathBuf};

use kachat_names_cli::{
    net::{self, consensus_params, net, p2pk_address, parse_owner_address},
    ops::Templates,
    paths::Paths,
    plan::{Sim, Step},
    util::{SOMPI, fmt_kas},
};
use kachat_names_harness::{keypair, name_key, xonly};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn mainnet() {
    net::select("mainnet").unwrap();
}

#[test]
fn every_network_value_is_mainnets() {
    mainnet();
    assert_eq!(net().name, "mainnet");
    assert_eq!(consensus_params().net.to_string(), "mainnet");
    assert_eq!(net().grpc_port, 16110);
    assert!(p2pk_address(&xonly(&keypair(5))).to_string().starts_with("kaspa:"));
    assert_eq!(fmt_kas(SOMPI), "1.00000000 KAS");
    let p = Paths::at(repo());
    assert!(p.deployer_key().ends_with(".secrets/mainnet-deployer.key"));
    assert!(p.commits().ends_with(".secrets/commits-mainnet.json"));
    assert!(p.manifest().ends_with("manifests/kachat-names-mainnet.json"));
    assert!(p.state().ends_with("state/registry-mainnet.json"));
    assert!(p.params().ends_with("params/mainnet.json"));
    assert!(p.artifacts().ends_with("artifacts/mainnet"));
    // switching networks mid-run is refused
    assert!(net::select("testnet-10").is_err());
    assert!(net::select("mainnet").is_ok());
}

#[test]
fn testnet_addresses_are_refused() {
    mainnet();
    let tn = kaspa_addresses::Address::new(kaspa_addresses::Prefix::Testnet, kaspa_addresses::Version::PubKey, &xonly(&keypair(5)));
    assert!(parse_owner_address(&tn.to_string()).is_err());
    let mn = p2pk_address(&xonly(&keypair(5))).to_string();
    assert_eq!(parse_owner_address(&mn).unwrap(), xonly(&keypair(5)));
}

#[test]
fn the_mainnet_registry_is_v4_on_the_year_clock() {
    mainnet();
    let t = Templates::load(&repo());
    assert_eq!(t.params.registry_version, 4);
    assert!(t.params.migration.is_none());
    assert_eq!(t.params.period_ms, 365 * 86_400_000);
    assert_eq!(t.params.grace_ms, 90 * 86_400_000);
    assert_eq!(t.params.renew_window_ms, 30 * 86_400_000);
    // the expiry arithmetic stays far below the contracts' caps
    assert!(t.params.max_years * t.params.period_ms <= 1_000_000_000_000);
}

#[test]
fn a_mainnet_registry_runs_end_to_end_in_the_simulator() {
    mainnet();
    let wall = 1_800_000_000_000;
    let mut sim = Sim::new(Templates::load(&repo()), 6_000 * SOMPI, wall);
    sim.run(&Step::Genesis).unwrap();
    for n in ["a", "kachat"] {
        sim.run(&Step::Commit(n)).unwrap();
    }
    sim.run(&Step::Wait(600, "commit maturity")).unwrap();
    // "a" for 2 years: 4,000 KAS (the 1-char registration) + 1,000 KAS (one renewal year)
    sim.run(&Step::Register { name: "a", years: 2, backdate_minutes: 0 }).unwrap();
    sim.run(&Step::Register { name: "kachat", years: 1, backdate_minutes: 0 }).unwrap();
    sim.run(&Step::Extend("kachat", 1)).unwrap();
    let reg = sim.reg.as_ref().unwrap();
    reg.check_invariants().unwrap();
    let a = reg.names.iter().find(|n| n.fields.key == name_key(b"a")).unwrap();
    assert_eq!(a.fields.expires_at - a.fields.period_start, 2 * 365 * 86_400_000);
    let k = reg.names.iter().find(|n| n.fields.key == name_key(b"kachat")).unwrap();
    assert_eq!(k.fields.expires_at - k.fields.period_start, 2 * 365 * 86_400_000);
    // a third year is past maxYears
    assert!(sim.run(&Step::Extend("kachat", 1)).is_err());
}
