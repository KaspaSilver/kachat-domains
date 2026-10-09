//! `verify` and `verify --live` refuse every tampered or wrong answer.
//!
//! Offline `verify` runs on a copy of the repository data with one thing changed.
//! The live proof (`prove`) runs on synthetic claims against a synthetic UTXO set, so
//! no node is needed: what the node would hold is exactly the claimed registry, then
//! one name is hidden, invented or altered, or a UTXO has the wrong covenant or value.

use std::path::{Path, PathBuf};

use kachat_names_cli::{
    manifest,
    net::spk_address,
    ops::Templates,
    paths::Paths,
    prove::{self, Claim},
    verify::verify,
};
use kachat_names_harness::{FF32, Kit, NameFields, ZERO32, gap_state};
use kaspa_addresses::Address;
use kaspa_hashes::Hash;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// A copy of what `verify` reads, in a fresh temporary directory.
fn copy_repo(tag: &str) -> PathBuf {
    let dst = std::env::temp_dir().join(format!("kachat-verify-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dst);
    for dir in ["contracts", "params", "artifacts", "manifests"] {
        copy_dir(&repo().join(dir), &dst.join(dir));
    }
    dst
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            if e.file_name() != "dryrun" {
                copy_dir(&e.path(), &to);
            }
        } else {
            std::fs::copy(e.path(), to).unwrap();
        }
    }
}

/// Replace the first `old` with `new` in `file` (relative to `root`).
fn edit(root: &Path, file: &str, old: &str, new: &str) {
    let p = root.join(file);
    let s = std::fs::read_to_string(&p).unwrap();
    assert!(s.contains(old), "{file} has no {old:?}");
    std::fs::write(&p, s.replacen(old, new, 1)).unwrap();
}

fn refused(root: &Path) -> String {
    let e = verify(&Paths::at(root)).expect_err("verify accepted a tampered repository").to_string();
    std::fs::remove_dir_all(root).unwrap();
    e
}

const MANIFEST: &str = "manifests/kachat-names-testnet-10.json";
const PARAMS: &str = "params/testnet10.json";

#[test]
fn the_committed_registry_verifies() {
    let v = verify(&Paths::at(repo())).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["network"], "testnet-10");
    let root = copy_repo("clean");
    assert_eq!(verify(&Paths::at(&root)).unwrap()["manifestSha256"], v["manifestSha256"]);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_manifest_param_that_differs_from_params_is_refused() {
    let root = copy_repo("grace");
    edit(&root, MANIFEST, "\"graceMs\": 21600000", "\"graceMs\": 21600001");
    assert!(refused(&root).contains("graceMs"));
}

#[test]
fn params_that_do_not_compile_to_the_artifacts_are_refused() {
    let root = copy_repo("price");
    edit(&root, PARAMS, "\"len5plus\": 35000000", "\"len5plus\": 35000001");
    assert!(refused(&root).contains("prices"));
}

#[test]
fn the_same_change_to_params_and_manifest_is_refused_by_the_compile() {
    // consistent with each other, but no longer what the committed contracts were built from
    let root = copy_repo("both");
    edit(&root, PARAMS, "\"len5plus\": 35000000", "\"len5plus\": 35000001");
    edit(&root, MANIFEST, "\"len5plus\": 35000000", "\"len5plus\": 35000001");
    assert!(refused(&root).contains("artifacts/testnet10/KachatGap.json"));
}

#[test]
fn a_manifest_template_hash_that_differs_is_refused() {
    let root = copy_repo("hash");
    let m = std::fs::read_to_string(root.join(MANIFEST)).unwrap();
    let v: serde_json::Value = serde_json::from_str(&m).unwrap();
    let h = v["artifacts"]["KachatOffer"]["templateHash"].as_str().unwrap().to_string();
    let mut wrong = h.clone().into_bytes();
    wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
    edit(&root, MANIFEST, &h, std::str::from_utf8(&wrong).unwrap());
    assert!(refused(&root).contains("KachatOffer template hash"));
}

#[test]
fn a_registry_id_that_is_not_the_genesis_binding_is_refused() {
    let root = copy_repo("regid");
    // the deployed id, whatever registry is live (a v5 one also names its predecessor's id)
    let m: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(root.join(MANIFEST)).unwrap()).unwrap();
    let id = m["registryCovenantId"].as_str().unwrap().to_string();
    let other = format!("{}{}", &id[..63], if id.ends_with('0') { "1" } else { "0" });
    let (id, other) = (id.as_str(), other.as_str());
    for f in [MANIFEST, PARAMS] {
        let p = root.join(f);
        std::fs::write(&p, std::fs::read_to_string(&p).unwrap().replace(id, other)).unwrap();
    }
    // the offer artifact no longer matches the registry id first, or the genesis binding does not
    let e = refused(&root);
    assert!(e.contains("covenant_id") || e.contains("KachatOffer"), "{e}");
}

#[test]
fn a_dry_run_manifest_is_refused() {
    let root = copy_repo("dryrun");
    edit(&root, MANIFEST, "\"status\": \"deployed\"", "\"status\": \"dry run\"");
    assert!(refused(&root).contains("dry run"));
}

// ---------------------------------------------------------------- live proof

fn kit() -> (Kit, Hash) {
    let d = manifest::load(&Paths::at(repo()).manifest(), None).unwrap();
    (Templates::load(&repo()).kit(d.registry_id).unwrap(), d.registry_id)
}

fn claim(name: &str, owner: u8, expires: i64) -> Claim {
    Claim { name: name.into(), fields: NameFields::new(name.as_bytes(), &[owner; 32], 0, expires - 86_400_000, expires) }
}

fn registry() -> Vec<Claim> {
    vec![claim("alice", 1, 1_800_000_000_000), claim("bob", 2, 1_800_000_000_000), claim("k", 3, 1_800_000_100_000)]
}

/// What the node would hold for exactly `claims`: every gap and name UTXO, with the
/// registry covenant id and their values.
fn chain(claims: &[Claim], kit: &Kit, id: Hash) -> Vec<(Address, Option<Hash>, u64)> {
    let mut keys: Vec<[u8; 32]> = claims.iter().map(|c| c.fields.key).collect();
    keys.sort();
    let mut out = vec![];
    let mut lo = ZERO32;
    for hi in keys.iter().chain(std::iter::once(&FF32)) {
        out.push((spk_address(&kit.gap.spk(&gap_state(&lo, hi))).unwrap(), Some(id), kit.params.gap_value));
        lo = *hi;
    }
    for c in claims {
        out.push((spk_address(&kit.name.spk(&c.fields.encode())).unwrap(), Some(id), kit.params.bond));
    }
    out
}

fn proves(claims: &[Claim], held: Vec<(Address, Option<Hash>, u64)>) -> Result<prove::Report, String> {
    let (kit, id) = kit();
    let p = prove::probe(claims, &kit).map_err(|e| e.to_string())?;
    prove::check(&p, held, &kit, id).map_err(|e| e.to_string())
}

#[test]
fn the_true_list_proves() {
    let (kit, id) = kit();
    let r = proves(&registry(), chain(&registry(), &kit, id)).unwrap();
    assert_eq!((r.names, r.gaps), (3, 4));
    // an empty registry: the lone genesis gap
    let r = proves(&[], chain(&[], &kit, id)).unwrap();
    assert_eq!((r.names, r.gaps), (0, 1));
}

#[test]
fn a_hidden_name_fails() {
    let (kit, id) = kit();
    let shown: Vec<Claim> = registry().into_iter().filter(|c| c.name != "bob").collect();
    let e = proves(&shown, chain(&registry(), &kit, id)).unwrap_err();
    assert!(e.contains("gaps the source implies hold no registry UTXO"), "{e}");
}

#[test]
fn an_invented_name_fails() {
    let (kit, id) = kit();
    let mut claimed = registry();
    claimed.push(claim("mallory", 4, 1_800_000_000_000));
    let e = proves(&claimed, chain(&registry(), &kit, id)).unwrap_err();
    assert!(e.contains("gaps the source implies"), "{e}");
}

#[test]
fn a_wrong_owner_or_date_or_price_fails() {
    let (kit, id) = kit();
    let held = chain(&registry(), &kit, id);
    for change in 0..3 {
        let mut claimed = registry();
        let f = &mut claimed[1].fields;
        match change {
            0 => f.owner = [9; 32],
            1 => f.expires_at += 1,
            _ => f.price = 5,
        }
        let e = proves(&claimed, held.clone()).unwrap_err();
        assert!(e.contains("bob"), "change {change}: {e}");
    }
}

#[test]
fn a_utxo_of_another_covenant_or_value_fails() {
    let (kit, id) = kit();
    let mut held = chain(&registry(), &kit, id);
    held[0].1 = Some(Hash::from_bytes([7; 32]));
    assert!(proves(&registry(), held).is_err(), "a gap under another covenant id counted");
    let mut held = chain(&registry(), &kit, id);
    held[0].1 = None;
    assert!(proves(&registry(), held).is_err(), "a gap with no covenant id counted");
    let mut held = chain(&registry(), &kit, id);
    let last = held.len() - 1;
    held[last].2 += 1;
    assert!(proves(&registry(), held).is_err(), "a name of the wrong value counted");
}

#[test]
fn a_bad_source_list_is_refused_before_the_node() {
    let (kit, _) = kit();
    let mut dup = registry();
    dup.push(claim("alice", 5, 1_800_000_000_000));
    assert!(prove::probe(&dup, &kit).unwrap_err().to_string().contains("twice"));
    // the indexer's key must be blake3(name)
    let v = serde_json::json!({
        "name": "alice", "key": "00".repeat(32), "ownerKey": "01".repeat(32),
        "price": "0", "periodStart": 1, "expiresAt": 2
    });
    assert!(Claim::from_indexer(&v).unwrap_err().to_string().contains("blake3(name)"));
    let ok = serde_json::json!({
        "name": "alice", "ownerKey": "01".repeat(32), "price": "0", "periodStart": 1, "expiresAt": 2
    });
    assert_eq!(Claim::from_indexer(&ok).unwrap().fields.owner, [1; 32]);
}

#[test]
fn the_docker_build_uses_the_pinned_toolchain() {
    let toml = std::fs::read_to_string(repo().join("rust-toolchain.toml")).unwrap();
    let pinned = toml.lines().find_map(|l| l.strip_prefix("channel = ")).unwrap().trim_matches('"').to_string();
    let docker = std::fs::read_to_string(repo().join("Dockerfile")).unwrap();
    let arg = docker.lines().find_map(|l| l.strip_prefix("ARG RUST_VERSION=")).unwrap().trim().to_string();
    assert_eq!(arg, pinned, "Dockerfile RUST_VERSION must match rust-toolchain.toml");
}
