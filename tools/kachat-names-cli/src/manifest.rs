//! The deployment manifest (`manifests/kachat-names-testnet-10.json`): what
//! the app and the indexer embed and verify before trusting any registry UTXO
//! (KACHAT_NAMES.md section 6): artifacts, template hashes, params, the
//! genesis binding (outpoint + authorized output) and the registry id.
//!
//! Registry v3 has two geneses: the price genesis (K shards under the price
//! covenant) and then the registry genesis (the gap, whose template bakes the
//! price covenant). The price genesis is recorded in
//! `state/price-genesis-<network>.json` when it is broadcast, and both go into
//! the manifest with the registry genesis.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use kachat_names_harness::{FF32, Kit, ZERO32, gap_state, price_state};
use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint};
use kaspa_hashes::Hash;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    net::{NETWORK, PARAMS_FILE, spk_address},
    ops::Plan,
    paths::Paths,
    registry::{PriceRec, Registry},
    util::{fmt_outpoint, hex, parse_outpoint, unhex32},
};

fn sha256_file(p: &Path) -> Result<String> {
    Ok(hex(&Sha256::digest(std::fs::read(p).with_context(|| p.display().to_string())?)))
}

pub struct Deployed {
    pub registry_id: Hash,
    pub genesis_txid: TransactionId,
    pub genesis_outpoint: TransactionOutpoint,
    pub price_id: Hash,
    pub price_genesis_txid: TransactionId,
    /// the shards as the price genesis created them
    pub shards: Vec<PriceRec>,
    /// where the scanner starts: before the price genesis
    pub scan_from: Option<Hash>,
    pub dry_run: bool,
}

impl Deployed {
    /// The registry as both geneses leave it.
    pub fn genesis_registry(&self, gap_value: u64) -> Registry {
        Registry::at_genesis(
            self.registry_id,
            self.genesis_txid,
            gap_value,
            self.scan_from,
            self.price_id,
            self.price_genesis_txid,
            self.shards.clone(),
        )
    }
}

/// The `priceGenesis` record of a price-genesis plan (outputs 0..K-1 are the shards).
pub fn price_genesis_json(kit: &Kit, plan: &Plan, authority: &[u8; 32], scan_from: Option<Hash>) -> Result<Value> {
    let tx = &plan.built.tx;
    let price_id = plan.price_id.ok_or_else(|| anyhow!("not a price genesis plan"))?;
    let k = kit.params.price_shards as usize;
    let mut outs = vec![];
    for (i, o) in tx.outputs[..k].iter().enumerate() {
        ensure!(o.covenant.map(|c| c.covenant_id) == Some(price_id), "output {i} is not a price shard");
        let state = price_state(i as i64, authority, &kit.params.prices);
        ensure!(o.script_public_key == kit.price.spk(&state), "output {i} is not shard {i}");
        outs.push(json!({
            "index": i,
            "value": o.value,
            "scriptPublicKeyVersion": o.script_public_key.version(),
            "scriptPublicKey": hex(o.script_public_key.script()),
            "address": spk_address(&o.script_public_key)?.to_string(),
            "contract": "KachatPrice",
            "state": { "shard": i, "authority": hex(authority), "prices": kit.params.prices },
            "stateScript": hex(&state),
        }));
    }
    Ok(json!({
        "priceCovenantId": price_id.to_string(),
        "txid": tx.id().to_string(),
        "outpoint": fmt_outpoint(&tx.inputs[0].previous_outpoint),
        "fundingValue": plan.built.entries[0].amount,
        "covenantId": "covenant_id(outpoint, [(i, authorizedOutputs[i]) for i in 0..K]) (kaspa_consensus_core::hashing::covenant_id)",
        "authority": hex(authority),
        "authorizedOutputs": outs,
        "scanFrom": scan_from.map(|h| h.to_string()),
    }))
}

/// Read and check a `priceGenesis` record: (price id, txid, shards, scanFrom).
fn parse_price_genesis(pg: &Value, kit_check: Option<&Kit>) -> Result<(Hash, TransactionId, Vec<PriceRec>, Option<Hash>)> {
    let s = |p: &Value| p.as_str().map(str::to_string).ok_or_else(|| anyhow!("priceGenesis field missing"));
    let price_id = Hash::from_bytes(unhex32(&s(&pg["priceCovenantId"])?)?);
    let txid = TransactionId::from_bytes(unhex32(&s(&pg["txid"])?)?);
    let outpoint = parse_outpoint(&s(&pg["outpoint"])?)?;
    let authority = unhex32(&s(&pg["authority"])?)?;
    let outs = pg["authorizedOutputs"].as_array().ok_or_else(|| anyhow!("priceGenesis without authorizedOutputs"))?;
    let mut shards = vec![];
    let mut bound = vec![];
    for (i, o) in outs.iter().enumerate() {
        let pr = o["state"]["prices"].as_array().ok_or_else(|| anyhow!("shard {i} without prices"))?;
        let mut prices = [0u64; 5];
        for (t, x) in prices.iter_mut().enumerate() {
            *x = pr.get(t).and_then(Value::as_u64).ok_or_else(|| anyhow!("shard {i} price {t}"))?;
        }
        let value = o["value"].as_u64().ok_or_else(|| anyhow!("shard {i} value"))?;
        if let Some(kit) = kit_check {
            let spk = kit.price.spk(&price_state(i as i64, &authority, &prices));
            ensure!(o["scriptPublicKey"] == hex(spk.script()), "priceGenesis output {i} is not shard {i} of these templates");
            bound.push(kachat_names_harness::TransactionOutput::new(value, spk));
        }
        shards.push(PriceRec { outpoint: TransactionOutpoint::new(txid, i as u32), shard: i as i64, authority, prices, value });
    }
    if let Some(kit) = kit_check {
        ensure!(shards.len() == kit.params.price_shards as usize, "priceGenesis has {} shards, params say {}", shards.len(), kit.params.price_shards);
        let id = kaspa_consensus_core::hashing::covenant_id::covenant_id(outpoint, bound.iter().enumerate().map(|(i, o)| (i as u32, o)));
        ensure!(id == price_id, "price covenant id {price_id} != covenant_id(price genesis outpoint, [shards]) = {id}");
    }
    let scan_from = pg["scanFrom"].as_str().map(|h| unhex32(h).map(Hash::from_bytes)).transpose()?;
    Ok((price_id, txid, shards, scan_from))
}

/// The price genesis broadcast earlier (state/price-genesis-<network>.json).
pub fn load_price_genesis(paths: &Paths) -> Result<Option<Value>> {
    let p = paths.price_genesis();
    if !p.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&std::fs::read_to_string(&p)?)?))
}

/// The price covenant id and txid of a `priceGenesis` record (unchecked).
pub fn price_genesis_ids(pg: &Value) -> Result<(Hash, TransactionId)> {
    let (id, txid, _, _) = parse_price_genesis(pg, None)?;
    Ok((id, txid))
}

/// Build the manifest for a registry genesis plan, with the price genesis record
/// `price_genesis`. `scan_from` is the sink observed just before submission; the
/// scanner starts at the price genesis's (earlier) one.
#[allow(clippy::too_many_arguments)]
pub fn build(paths: &Paths, kit: &Kit, price_genesis: &Value, plan: &Plan, deployer: &str, scan_from: Option<Hash>, dry_run: bool) -> Result<Value> {
    let tx = &plan.built.tx;
    let registry_id = plan.registry_id.ok_or_else(|| anyhow!("not a genesis plan"))?;
    let gap_out = &tx.outputs[0];
    ensure!(gap_out.covenant.map(|c| c.covenant_id) == Some(registry_id), "output 0 is not the genesis gap");
    ensure!(tx.outputs.iter().filter(|o| o.covenant.is_some()).count() == 1, "genesis authorizes one output only");
    let params: Value = serde_json::from_str(&std::fs::read_to_string(paths.params())?)?;
    let info: Value = serde_json::from_str(&std::fs::read_to_string(paths.artifacts().join("build-info.json"))?)?;
    let mut artifacts = serde_json::Map::new();
    {
        let path = paths.artifacts().join("KachatPrice.json");
        let mut entry = info["contracts"]["KachatPrice"].clone();
        entry["path"] = json!(paths.rel(&path));
        entry["fileSha256"] = json!(sha256_file(&path)?);
        artifacts.insert("KachatPrice".into(), entry);
    }
    ensure!(hex(&kit.price.template_hash) == info["contracts"]["KachatPrice"]["templateHash"], "price template hash mismatch");
    // the name, gap and offer bake covenant ids: compiled in process (scripts/build.sh
    // writes the same bytes once params carry the ids)
    for (c, t, entries, note) in [
        ("KachatName", &kit.name, &["transfer", "list", "buy", "extend", "renew", "release", "reclaim"][..], "priceCovenantId"),
        ("KachatGap", &kit.gap, &["register", "merge", "absorbed"][..], "priceCovenantId"),
        ("KachatOffer", &kit.offer, &["accept", "decline", "withdraw", "refund"][..], "registryCovenantId"),
    ] {
        let span = t.abi.contracts[&t.contract].compiled.state_span;
        let tags: serde_json::Map<String, Value> = entries.iter().map(|e| (e.to_string(), json!(t.dispatch_tag(e)))).collect();
        artifacts.insert(
            c.into(),
            json!({
                "bytecodeLen": t.bytecode.len(),
                "stateSpan": { "offset": span.offset, "len": span.len },
                "prefixLen": t.prefix.len(),
                "suffixLen": t.suffix.len(),
                "templateHash": hex(&t.template_hash),
                "bytecodeSha256": hex(&Sha256::digest(&t.bytecode)),
                "dispatchTags": tags,
                "path": format!("artifacts/{PARAMS_FILE}/{c}.json"),
                "note": format!("compiled for {note} with the pinned compiler library; scripts/build.sh writes the same bytes once params carry it"),
            }),
        );
    }
    {
        let t = &kit.price;
        let tags: serde_json::Map<String, Value> = ["use", "update", "follow"].iter().map(|e| (e.to_string(), json!(t.dispatch_tag(e)))).collect();
        artifacts.get_mut("KachatPrice").unwrap()["dispatchTags"] = json!(tags);
    }
    // prefix and suffix bytes, so the manifest alone lets an indexer build
    // and check every P2SH (KACHAT_NAMES_INDEXER.md B2)
    for (c, t) in [("KachatPrice", &kit.price), ("KachatGap", &kit.gap), ("KachatName", &kit.name), ("KachatOffer", &kit.offer)] {
        let e = artifacts.get_mut(c).unwrap();
        e["prefixHex"] = json!(hex(&t.prefix));
        e["suffixHex"] = json!(hex(&t.suffix));
    }
    let (price_id, _, _, _) = parse_price_genesis(price_genesis, Some(kit))?;
    ensure!(price_id == kit.price_id, "the price genesis record is for another price covenant");
    let funding = tx.inputs[0].previous_outpoint;
    let mut p = params.clone();
    if let Some(m) = p.as_object_mut() {
        m.remove("registryCovenantId");
        m.remove("priceCovenantId");
        m.remove("compiler");
        m.remove("network");
    }
    Ok(json!({
        "name": "kachat-names",
        "registryVersion": 3,
        "network": NETWORK,
        "status": if dry_run { "dry run: NOT broadcast, the registry does not exist" } else { "deployed" },
        "compiler": params["compiler"],
        "params": p,
        "artifacts": artifacts,
        "priceCovenantId": price_id.to_string(),
        "priceGenesis": price_genesis,
        "registryCovenantId": registry_id.to_string(),
        "genesis": {
            "txid": tx.id().to_string(),
            "outpoint": fmt_outpoint(&funding),
            "fundingValue": plan.built.entries[0].amount,
            "covenantId": "covenant_id(outpoint, [(0, authorizedOutputs[0])]) (kaspa_consensus_core::hashing::covenant_id)",
            "authorizedOutputs": [{
                "index": 0,
                "value": gap_out.value,
                "scriptPublicKeyVersion": gap_out.script_public_key.version(),
                "scriptPublicKey": hex(gap_out.script_public_key.script()),
                "address": spk_address(&gap_out.script_public_key)?.to_string(),
                "contract": "KachatGap",
                "state": { "lo": hex(&ZERO32), "hi": hex(&FF32) },
                "stateScript": hex(&gap_state(&ZERO32, &FF32)),
            }],
            "scanFrom": scan_from.map(|h| h.to_string()),
        },
        "deployer": deployer,
    }))
}

pub fn write(path: &Path, v: &Value) -> Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(v)? + "\n")?;
    Ok(())
}

pub fn load(path: &Path, kit_check: Option<&Kit>) -> Result<Deployed> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("{}: no manifest", path.display()))?)?;
    ensure!(v["network"] == NETWORK, "{}: manifest is for {}", path.display(), v["network"]);
    ensure!(
        v["registryVersion"].as_i64() == Some(3),
        "{}: not a registry v3 manifest (a v2 registry needs the v3 geneses: archive it first)",
        path.display()
    );
    let s = |p: &Value| p.as_str().map(str::to_string).ok_or_else(|| anyhow!("manifest field missing"));
    let registry_id = Hash::from_bytes(unhex32(&s(&v["registryCovenantId"])?)?);
    let g = &v["genesis"];
    let (price_id, price_genesis_txid, shards, price_scan_from) = parse_price_genesis(&v["priceGenesis"], kit_check)?;
    ensure!(v["priceCovenantId"] == price_id.to_string(), "manifest priceCovenantId differs from its priceGenesis");
    let d = Deployed {
        registry_id,
        genesis_txid: TransactionId::from_bytes(unhex32(&s(&g["txid"])?)?),
        genesis_outpoint: parse_outpoint(&s(&g["outpoint"])?)?,
        price_id,
        price_genesis_txid,
        shards,
        scan_from: price_scan_from.or(g["scanFrom"].as_str().map(|h| unhex32(h).map(Hash::from_bytes)).transpose()?),
        dry_run: v["status"].as_str().is_some_and(|s| s.starts_with("dry run")),
    };
    if let Some(kit) = kit_check {
        // verify the genesis binding and the templates against the manifest
        let out = &g["authorizedOutputs"][0];
        let spk = kit.gap.spk(&gap_state(&ZERO32, &FF32));
        ensure!(out["scriptPublicKey"] == hex(spk.script()), "manifest genesis output is not the genesis gap of these templates");
        let o = kachat_names_harness::TransactionOutput::new(out["value"].as_u64().unwrap_or(0), spk);
        let id = kaspa_consensus_core::hashing::covenant_id::covenant_id(d.genesis_outpoint, [(0u32, &o)].into_iter());
        if id != registry_id {
            bail!("manifest registry id {registry_id} != covenant_id(genesis outpoint, [gap]) = {id}");
        }
        ensure!(kit.price_id == price_id, "the kit is for another price covenant than the manifest's");
        ensure!(v["artifacts"]["KachatPrice"]["templateHash"] == hex(&kit.price.template_hash), "manifest price template hash differs");
        ensure!(v["artifacts"]["KachatGap"]["templateHash"] == hex(&kit.gap.template_hash), "manifest gap template hash differs");
        ensure!(v["artifacts"]["KachatName"]["templateHash"] == hex(&kit.name.template_hash), "manifest name template hash differs");
        ensure!(v["artifacts"]["KachatOffer"]["templateHash"] == hex(&kit.offer.template_hash), "manifest offer template hash differs");
        for (c, t) in [("KachatPrice", &kit.price), ("KachatGap", &kit.gap), ("KachatName", &kit.name), ("KachatOffer", &kit.offer)] {
            ensure!(
                v["artifacts"][c]["prefixHex"] == hex(&t.prefix) && v["artifacts"][c]["suffixHex"] == hex(&t.suffix),
                "manifest {c} prefix/suffix differ from the templates"
            );
        }
    }
    Ok(d)
}

/// After a real genesis: fill `key` (`priceCovenantId` / `registryCovenantId`) in
/// params/testnet10.json (a textual edit of the one `null`, so nothing else moves).
pub fn fill_params_id(paths: &Paths, key: &str, id: Hash) -> Result<()> {
    let p = paths.params();
    let text = std::fs::read_to_string(&p)?;
    let needle = format!("\"{key}\": null");
    ensure!(text.matches(&needle).count() == 1, "{}: {key} is already set", paths.rel(&p));
    std::fs::write(&p, text.replace(&needle, &format!("\"{key}\": \"{id}\"")))?;
    Ok(())
}

/// For the dry run: a copy of params/testnet10.json with the would-be ids
/// (replacing null, or the ids of an already deployed registry), which
/// `scripts/build.py` accepts to build the name, gap and offer artifacts.
pub fn dryrun_params(paths: &Paths, price_id: Hash, registry_id: Hash) -> Result<std::path::PathBuf> {
    let text = std::fs::read_to_string(paths.params())?;
    let out = paths.dryrun_dir().join(format!("params-{PARAMS_FILE}.json"));
    std::fs::create_dir_all(paths.dryrun_dir())?;
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    for (key, id) in [("priceCovenantId", price_id), ("registryCovenantId", registry_id)] {
        let at = lines
            .iter()
            .position(|l| l.trim_start().starts_with(&format!("\"{key}\":")))
            .ok_or_else(|| anyhow!("params without {key}"))?;
        let indent: String = lines[at].chars().take_while(|c| c.is_whitespace()).collect();
        let comma = if lines[at].trim_end().ends_with(',') { "," } else { "" };
        lines[at] = format!("{indent}\"{key}\": \"{id}\"{comma}");
    }
    std::fs::write(&out, lines.join("\n") + "\n")?;
    Ok(out)
}
