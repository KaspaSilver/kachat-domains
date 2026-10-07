//! `verify --live`: prove that a claimed list of names is exactly the registry on chain.
//!
//! The registry's live gaps and live names partition the 32-byte key space: `register`
//! splits a gap around the new key and the exit merges it back, and every gap and name
//! carries the registry covenant id, which only those entries can authorize. So given a
//! claimed set of names (from an indexer, or this CLI's own scan):
//! 1. sort their keys and derive every gap between them, `(00..00, k1)`, `(k1, k2)`, …,
//!    `(kn, ff..ff)`, and the P2SH address each gap's state gives under the gap template;
//! 2. derive each claimed name's address from its full state (key, name, owner, price,
//!    periodStart, expiresAt) under the name template;
//! 3. ask a node for the UTXOs at those addresses.
//!
//! If every derived gap holds a registry UTXO of the gap value, no other key can be
//! registered: it would lie inside one of those gaps. If every claimed name holds a
//! registry UTXO of the bond, each one is registered with exactly the claimed owner, price
//! and dates. A hidden, invented or altered name fails one of the two. Trusted: the node,
//! the pinned compiler (the templates come from `verify`) and rusty-kaspa.
//!
//! After the approach of supertypo/dotk-covenants' verifier.

use std::collections::HashSet;

use anyhow::{Result, anyhow, bail, ensure};
use kachat_names_harness::{FF32, Kit, NameFields, ZERO32, gap_state, name_key, pad_name};
use kaspa_addresses::Address;
use kaspa_hashes::Hash;
use serde_json::Value;

use crate::{net::spk_address, util::hex};

/// One name as a source claims it.
#[derive(Clone, Debug)]
pub struct Claim {
    pub name: String,
    pub fields: NameFields,
}

impl Claim {
    /// From an indexer name object (`/names/all`, `/names/by-owner`, …): `name`, `key`,
    /// `ownerKey`, `price` (string or number), `periodStart`, `expiresAt`.
    pub fn from_indexer(v: &Value) -> Result<Claim> {
        let name = v["name"].as_str().ok_or_else(|| anyhow!("indexer name without `name`: {v}"))?.to_string();
        ensure!((1..=32).contains(&name.len()), "{name:?} is not 1 to 32 bytes");
        let owner = unhex32(v["ownerKey"].as_str().ok_or_else(|| anyhow!("{name}: no ownerKey"))?)?;
        let price = match &v["price"] {
            Value::String(s) => s.parse::<i64>().map_err(|_| anyhow!("{name}: price {s:?}"))?,
            p => p.as_i64().ok_or_else(|| anyhow!("{name}: price {p}"))?,
        };
        let int = |k: &str| v[k].as_i64().ok_or_else(|| anyhow!("{name}: no {k}"));
        let fields = NameFields::new(name.as_bytes(), &owner, price, int("periodStart")?, int("expiresAt")?);
        // the source's key must be the name's: a mismatch is a lie about which key is taken
        if let Some(k) = v["key"].as_str() {
            ensure!(unhex32(k)? == fields.key, "{name}: the source says key {k}, but blake3(name) is {}", hex(&fields.key));
        }
        Ok(Claim { name, fields })
    }
}

fn unhex32(s: &str) -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    faster_hex::hex_decode(s.as_bytes(), &mut b).map_err(|_| anyhow!("{s:?} is not 32 hex bytes"))?;
    Ok(b)
}

/// The addresses a claimed set implies.
#[derive(Debug)]
pub struct Probe {
    /// (lo, hi) label and address of every gap
    pub gaps: Vec<(String, Address)>,
    /// name and address of every claimed name
    pub names: Vec<(String, Address)>,
}

impl Probe {
    pub fn addresses(&self) -> Vec<Address> {
        self.gaps.iter().chain(self.names.iter()).map(|(_, a)| a.clone()).collect()
    }
}

pub fn probe(claims: &[Claim], kit: &Kit) -> Result<Probe> {
    let mut keys = Vec::with_capacity(claims.len());
    let mut names = Vec::with_capacity(claims.len());
    for c in claims {
        // the stored name is the padded name; `NameFields::new` derived key and padding from it
        ensure!(c.fields.key == name_key(c.name.as_bytes()) && c.fields.name == pad_name(c.name.as_bytes()), "{}: key or padding", c.name);
        keys.push(c.fields.key);
        names.push((c.name.clone(), spk_address(&kit.name.spk(&c.fields.encode()))?));
    }
    keys.sort_unstable();
    ensure!(keys.windows(2).all(|w| w[0] < w[1]), "the source lists a key twice");
    ensure!(keys.first().is_none_or(|k| *k > ZERO32) && keys.last().is_none_or(|k| *k < FF32), "the source lists a key-space bound as a key");
    let mut gaps = Vec::with_capacity(keys.len() + 1);
    let mut lo = ZERO32;
    for hi in keys.iter().chain(std::iter::once(&FF32)) {
        let label = format!("({}…, {}…)", &hex(&lo)[..8], &hex(hi)[..8]);
        gaps.push((label, spk_address(&kit.gap.spk(&gap_state(&lo, hi)))?));
        lo = *hi;
    }
    Ok(Probe { gaps, names })
}

/// What was proven: every gap and every name of the claimed set is on chain.
#[derive(Debug)]
pub struct Report {
    pub gaps: usize,
    pub names: usize,
}

/// Every gap must hold a registry UTXO of the gap value, and every name one of the bond.
/// `held`: (address, covenant id, amount) of every UTXO the node has at the probed addresses.
pub fn check(probe: &Probe, held: impl IntoIterator<Item = (Address, Option<Hash>, u64)>, kit: &Kit, registry_id: Hash) -> Result<Report> {
    let mut gap_ok = HashSet::new();
    let mut name_ok = HashSet::new();
    for (addr, cov, amount) in held {
        if cov != Some(registry_id) {
            continue;
        }
        if amount == kit.params.gap_value {
            gap_ok.insert(addr.clone());
        }
        if amount == kit.params.bond {
            name_ok.insert(addr);
        }
    }
    let missing_gaps: Vec<&str> = probe.gaps.iter().filter(|(_, a)| !gap_ok.contains(a)).map(|(l, _)| l.as_str()).collect();
    let missing_names: Vec<&str> = probe.names.iter().filter(|(_, a)| !name_ok.contains(a)).map(|(n, _)| n.as_str()).collect();
    if !missing_gaps.is_empty() {
        bail!(
            "{} of {} gaps the source implies hold no registry UTXO (e.g. {}): its list of names is not the registry's - a name is hidden or invented",
            missing_gaps.len(),
            probe.gaps.len(),
            missing_gaps.iter().take(5).copied().collect::<Vec<_>>().join(", ")
        );
    }
    if !missing_names.is_empty() {
        bail!(
            "{} of {} names hold no registry UTXO with the claimed owner, price and dates (e.g. {})",
            missing_names.len(),
            probe.names.len(),
            missing_names.iter().take(10).copied().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(Report { gaps: probe.gaps.len(), names: probe.names.len() })
}
