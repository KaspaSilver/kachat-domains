//! `verify`: offline check that the published manifest is what the sources say.
//!
//! Anyone who runs the registry's manifest (a Kaspa Quick Start operator, an
//! indexer) can check it without trusting whoever committed it:
//! - the name, gap and offer are compiled in-process from `contracts/*.sil` and
//!   `params/<net>.json` with the pinned compiler library, and must equal the
//!   committed artifacts;
//! - the manifest's genesis output, registry id (the covenant id of the genesis
//!   outpoint and gap), template hashes, prefixes and suffixes must match those
//!   templates;
//! - every manifest param must equal params, because the templates bake them
//!   and the app reads them from the manifest.
//!
//! No node, no key, nothing written.

use anyhow::{Result, anyhow, ensure};
use kaspa_hashes::Hash;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{manifest, net::NETWORK, ops::Templates, paths::Paths, util::hex};

/// The params the manifest copies from params/<net>.json (the templates bake them all).
const PARAM_KEYS: &[&str] = &["bond", "gapValue", "tCommit", "maxYears", "periodMs", "graceMs", "renewWindowMs", "prices", "offerMaxFee", "registryVersion", "migration"];

/// Verify the deployed manifest; the summary is what an operator needs to point an indexer at it.
pub fn verify(paths: &Paths) -> Result<Value> {
    let path = paths.manifest();
    let text = std::fs::read_to_string(&path).map_err(|e| anyhow!("{}: {e}", paths.rel(&path)))?;
    let m: Value = serde_json::from_str(&text)?;
    let id_hex = m["registryCovenantId"].as_str().ok_or_else(|| anyhow!("manifest has no registryCovenantId"))?;
    let mut raw = [0u8; 32];
    faster_hex::hex_decode(id_hex.as_bytes(), &mut raw).map_err(|_| anyhow!("registryCovenantId is not 32 hex bytes"))?;
    let registry_id = Hash::from_bytes(raw);

    let params_text = std::fs::read_to_string(paths.params())?;
    let p: Value = serde_json::from_str(&params_text)?;
    ensure!(
        p["registryCovenantId"].as_str() == Some(id_hex),
        "params registryCovenantId {} != the manifest's {id_hex}",
        p["registryCovenantId"]
    );
    for k in PARAM_KEYS {
        ensure!(m["params"][*k] == p[*k], "manifest params.{k} = {} but {} says {}", m["params"][*k], paths.rel(&paths.params()), p[*k]);
    }

    // compiles from source and requires the committed artifacts to be identical
    let kit = Templates::load(&paths.root).kit(registry_id)?;
    let d = manifest::load(&path, Some(&kit))?;
    ensure!(!d.dry_run, "the manifest is a dry run, not a deployed registry");

    let mut sha = Sha256::new();
    sha.update(text.as_bytes());
    Ok(json!({
        "ok": true,
        "network": NETWORK,
        "registryVersion": m["registryVersion"],
        "registryCovenantId": id_hex,
        "genesisTxid": d.genesis_txid.to_string(),
        "scanFrom": d.scan_from.map(|h| h.to_string()),
        "templateHashes": {
            "KachatGap": hex(&kit.gap.template_hash),
            "KachatName": hex(&kit.name.template_hash),
            "KachatOffer": hex(&kit.offer.template_hash),
        },
        "params": PARAM_KEYS.iter().map(|k| (k.to_string(), m["params"][*k].clone())).collect::<serde_json::Map<_, _>>(),
        "manifest": format!("manifests/kachat-names-{NETWORK}.json"),
        "manifestSha256": hex(&sha.finalize()),
        "commit": std::env::var("KACHAT_DOMAINS_COMMIT").ok(),
    }))
}
