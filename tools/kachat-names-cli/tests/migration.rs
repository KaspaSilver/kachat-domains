//! The migration drill, in-process: a live v4 registry with real names, its
//! snapshot, a v5 genesis that bakes it, the sponsor importing every name,
//! and the checks the testnet drill repeats on chain. Every transaction is
//! built by the CLI's own builders, validated by the consensus validator and
//! applied by the decoder (`Registry::apply`) that `scan` uses.

use std::path::{Path, PathBuf};

use kachat_names_cli::{
    ops::{self, Templates},
    plan::{A, B, L, Sim, Step, e2e_steps},
    snapshot,
    util::{SOMPI, hex},
};
use kachat_names_harness::{keypair, name_key, xonly};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

const WALL: i64 = 1_800_000_000_000;

/// The v4 plan up to (not including) its exits, then alpha-tn listed again: three
/// names, one lapsed (lapse-tn), one listed (alpha-tn), one with a 2-period paid
/// period (bravo-tn).
fn v4_registry() -> Sim {
    let mut sim = Sim::new(Templates::load(&repo()), 100 * SOMPI, WALL);
    for (step, _) in e2e_steps() {
        if matches!(step, Step::Release(_) | Step::Reclaim(_)) {
            break;
        }
        sim.run(&step).unwrap_or_else(|e| panic!("{step:?}: {e}"));
    }
    sim.run(&Step::List(A, 7 * SOMPI)).unwrap();
    sim
}

/// A copy of the repository data with params turned into a v5 registry that
/// migrates from `snapshot_file` (written here too). The v4 gap artifact is
/// left out: the v5 gap is compiled in-process.
fn v5_repo(tag: &str, snapshot_json: &serde_json::Value, deadline_ms: i64) -> PathBuf {
    let dst = std::env::temp_dir().join(format!("kachat-migration-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dst);
    for d in ["contracts", "params", "artifacts"] {
        copy_dir(&repo().join(d), &dst.join(d));
    }
    for f in ["KachatGap.json", "KachatOffer.json"] {
        let _ = std::fs::remove_file(dst.join("artifacts/testnet10").join(f));
    }
    std::fs::create_dir_all(dst.join("manifests/snapshots")).unwrap();
    std::fs::write(dst.join("manifests/snapshots/drill.json"), serde_json::to_string_pretty(snapshot_json).unwrap()).unwrap();
    let p = dst.join("params/testnet10.json");
    let mut params: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    params["registryVersion"] = 5.into();
    params["registryCovenantId"] = serde_json::Value::Null;
    params["migration"] = serde_json::json!({
        "predecessorRegistryId": snapshot_json["predecessorRegistryId"],
        "snapshot": "manifests/snapshots/drill.json",
        "root": snapshot_json["root"],
        "deadlineMs": deadline_ms,
        // the simulator's deployer (keypair 77) is the sponsor
        "sponsor": hex(&xonly(&keypair(77))),
    });
    std::fs::write(&p, serde_json::to_string_pretty(&params).unwrap()).unwrap();
    dst
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), to).unwrap();
        }
    }
}

#[test]
fn the_drill_carries_every_name_over_with_its_owner_and_dates() {
    // 1. the live registry and its snapshot
    let old = v4_registry();
    let old_reg = old.reg.as_ref().unwrap();
    let grace = old.templates.params.grace_ms;
    let at = old.wall_ms;
    let taken = snapshot::take(old_reg, at, grace);
    let kept: Vec<&str> = taken.kept.iter().map(|(n, _)| n.as_str()).collect();
    assert!(kept.contains(&A) && kept.contains(&B), "{kept:?}");
    assert_eq!(taken.lapsed, vec![L.to_string()], "lapse-tn is past its grace: left behind");
    let json = snapshot::to_json(&taken, old_reg, "testnet-10", at, grace);
    let items = ops::snapshot_items(&json).unwrap();
    assert_eq!(items.len(), taken.kept.len());

    // 2. the v5 registry: genesis, then the sponsor imports every name
    let root = v5_repo("drill", &json, at + 6 * 3_600_000);
    let mut new = Sim::new(Templates::load(&root), 100 * SOMPI, at + 60_000);
    assert_eq!(new.templates.params.registry_version, 5);
    new.run(&Step::Genesis).unwrap();
    for item in &items {
        new.import(item).unwrap_or_else(|e| panic!("import {}: {e}", item.name));
    }

    // 3. exactly the snapshot, unlisted; nothing else; the key space still tiles
    let new_reg = new.reg.as_ref().unwrap();
    new_reg.check_invariants().unwrap();
    assert_eq!(new_reg.names.len(), taken.kept.len());
    for (name, e) in &taken.kept {
        let n = new_reg.names.iter().find(|n| n.fields.key == e.key).unwrap_or_else(|| panic!("{name} missing"));
        assert_eq!(n.fields.owner, e.owner, "{name}: owner");
        assert_eq!((n.fields.period_start, n.fields.expires_at), (e.period_start, e.expires_at), "{name}: paid period");
        assert_eq!(n.fields.price, 0, "{name}: listings do not carry over");
        let old_n = old_reg.names.iter().find(|o| o.fields.key == e.key).unwrap();
        assert_eq!((old_n.fields.owner, old_n.fields.expires_at), (n.fields.owner, n.fields.expires_at));
    }
    assert!(old_reg.names.iter().any(|n| n.fields.key == name_key(A.as_bytes()) && n.fields.price > 0), "alpha-tn was listed in v4");
    assert!(new_reg.names.iter().all(|n| n.fields.key != name_key(L.as_bytes())), "lapse-tn not imported");

    // 4. importing again is impossible: no gap holds an imported key
    assert!(new.import(&items[0]).is_err());
}

#[test]
fn registration_waits_for_the_deadline_and_the_lapsed_name_is_free_after_it() {
    let old = v4_registry();
    let old_reg = old.reg.as_ref().unwrap();
    let grace = old.templates.params.grace_ms;
    let taken = snapshot::take(old_reg, old.wall_ms, grace);
    let json = snapshot::to_json(&taken, old_reg, "testnet-10", old.wall_ms, grace);
    let deadline = old.wall_ms + 3_600_000;
    let root = v5_repo("deadline", &json, deadline);
    let mut new = Sim::new(Templates::load(&root), 100 * SOMPI, old.wall_ms + 60_000);
    new.run(&Step::Genesis).unwrap();
    for item in ops::snapshot_items(&json).unwrap() {
        new.import(&item).unwrap();
    }
    // before the deadline: the gap refuses every registration, even of the lapsed name
    new.run(&Step::Commit(L)).unwrap();
    new.run(&Step::Wait(600, "commit maturity")).unwrap();
    let early = new.run(&Step::Register { name: L, years: 1, backdate_minutes: 0 });
    assert!(early.is_err(), "registered before the deadline");
    // after it: lapse-tn, left behind by the snapshot, is anyone's to register
    // `now` runs ~3 min behind the wall clock (median time), so step well past the deadline
    new.advance_ms(deadline - new.wall_ms + 600_000);
    new.run(&Step::Register { name: L, years: 1, backdate_minutes: 0 }).unwrap();
    assert!(new.reg.as_ref().unwrap().names.iter().any(|n| n.fields.key == name_key(L.as_bytes())));
}

#[test]
fn a_tampered_snapshot_file_is_refused() {
    let old = v4_registry();
    let old_reg = old.reg.as_ref().unwrap();
    let grace = old.templates.params.grace_ms;
    let taken = snapshot::take(old_reg, old.wall_ms, grace);
    let good = snapshot::to_json(&taken, old_reg, "testnet-10", old.wall_ms, grace);
    assert!(snapshot::check_file(&good).is_ok());
    let mut owner = good.clone();
    owner["entries"][0]["owner"] = hex(&[9u8; 32]).into();
    let mut proof = good.clone();
    let p = proof["entries"][0]["proof"].as_str().unwrap().to_string();
    proof["entries"][0]["proof"] = format!("ff{}", &p[2..]).into();
    let mut root = good.clone();
    root["root"] = hex(&[1u8; 32]).into();
    let mut name = good.clone();
    name["entries"][0]["name"] = "mallory".into();
    for (what, bad) in [("owner", owner), ("proof", proof), ("root", root), ("name", name)] {
        assert!(snapshot::check_file(&bad).is_err(), "a tampered {what} passed");
    }
}
