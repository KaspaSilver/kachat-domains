//! `kachat-names snapshot`: the migration snapshot of the live registry
//! (registry v5's `import`, docs/REGISTRY_V5.md).
//!
//! It takes this CLI's scanned state, which `verify --live` should have proven
//! against the chain first, and keeps every name that is **active or in grace**
//! at the snapshot time. Lapsed names stay behind: they are free in the next
//! version, and their bonds come back through `reclaim` in the old registry.
//! The tree is `kachat_names_harness::snapshot` (the contract's exact rules).
//! The file it writes is what the v5 genesis bakes (`root`) and what the
//! imports read (`entries[].index`, `proof`), and anyone can rebuild it from
//! the chain.

use anyhow::{Result, ensure};
use kachat_names_harness::snapshot::{DEPTH, Entry, Snapshot};
use serde_json::{Value, json};

use crate::{
    net::p2pk_address,
    registry::{Registry, name_str},
    util::{fmt_ms, hex},
};

/// Names kept and left behind at `at_ms`.
pub struct Taken {
    pub snapshot: Snapshot,
    /// (name, entry) in snapshot (key) order
    pub kept: Vec<(String, Entry)>,
    /// names lapsed at `at_ms` (not imported)
    pub lapsed: Vec<String>,
}

/// Active or in grace at `at_ms`: `at_ms < expiresAt + graceMs`.
pub fn take(reg: &Registry, at_ms: i64, grace_ms: i64) -> Taken {
    let mut kept = Vec::new();
    let mut lapsed = Vec::new();
    for n in &reg.names {
        let name = name_str(&n.fields.name);
        if at_ms < n.fields.expires_at.saturating_add(grace_ms) {
            kept.push((name, Entry::of(&n.fields)));
        } else {
            lapsed.push(name);
        }
    }
    kept.sort_by(|a, b| a.1.key.cmp(&b.1.key));
    lapsed.sort();
    let snapshot = Snapshot::new(kept.iter().map(|(_, e)| e.clone()).collect());
    Taken { snapshot, kept, lapsed }
}

/// The snapshot file: everything a deployer, an importer and a checker need.
pub fn to_json(t: &Taken, reg: &Registry, network: &str, at_ms: i64, grace_ms: i64) -> Value {
    json!({
        "kind": "kachat-names-snapshot",
        "version": 1,
        "network": network,
        "predecessorRegistryId": reg.registry_id.to_string(),
        "checkpoint": reg.scan_from.map(|h| h.to_string()),
        "atMs": at_ms,
        "at": fmt_ms(at_ms),
        "rule": format!("names with atMs < expiresAt + graceMs ({grace_ms} ms): active or in grace"),
        "depth": DEPTH,
        "leaf": "blake3(\"kachat-snapshot-leaf:v1\" || key || owner || num8(periodStart) || num8(expiresAt))",
        "root": hex(&t.snapshot.root()),
        "entries": t.kept.iter().enumerate().map(|(i, (name, e))| json!({
            "index": i,
            "name": name,
            "key": hex(&e.key),
            "owner": hex(&e.owner),
            "ownerAddress": p2pk_address(&e.owner).to_string(),
            "periodStart": e.period_start,
            "expiresAt": e.expires_at,
            "proof": hex(&t.snapshot.proof(i)),
        })).collect::<Vec<_>>(),
        "lapsed": t.lapsed,
    })
}

/// Rebuild a snapshot file's tree from its entries and check every stored
/// index, proof and the root (it never trusts the stored values).
pub fn check_file(v: &Value) -> Result<Snapshot> {
    ensure!(v["kind"] == "kachat-names-snapshot", "not a snapshot file");
    ensure!(v["depth"].as_u64() == Some(DEPTH as u64), "snapshot depth is not {DEPTH}");
    let entries = v["entries"].as_array().cloned().unwrap_or_default();
    let mut list = Vec::with_capacity(entries.len());
    for e in &entries {
        let key = crate::util::unhex32(e["key"].as_str().unwrap_or(""))?;
        let name = e["name"].as_str().unwrap_or("");
        ensure!(kachat_names_harness::name_key(name.as_bytes()) == key, "{name}: key is not blake3(name)");
        list.push(Entry {
            key,
            owner: crate::util::unhex32(e["owner"].as_str().unwrap_or(""))?,
            period_start: e["periodStart"].as_i64().unwrap_or(-1),
            expires_at: e["expiresAt"].as_i64().unwrap_or(-1),
        });
    }
    let snap = Snapshot::new(list);
    ensure!(v["root"].as_str() == Some(hex(&snap.root()).as_str()), "the stored root is not the entries' root");
    for e in &entries {
        let i = e["index"].as_u64().unwrap_or(u64::MAX) as usize;
        ensure!(i < snap.entries.len(), "index {i} out of range");
        ensure!(e["proof"].as_str() == Some(hex(&snap.proof(i)).as_str()), "entry {i}: stored proof differs");
    }
    Ok(snap)
}
