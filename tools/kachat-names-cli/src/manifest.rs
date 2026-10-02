//! The deployment manifest (`manifests/kachat-names-testnet-10.json`): what
//! the app and the indexer embed and verify before trusting any registry UTXO
//! (KACHAT_NAMES.md section 6): artifacts, template hashes, params, the
//! genesis binding (outpoint + authorized output) and the registry id.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use kachat_names_harness::{FF32, Kit, ZERO32, gap_state};
use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint};
use kaspa_hashes::Hash;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    net::{NETWORK, PARAMS_FILE, spk_address},
    ops::Plan,
    paths::Paths,
    util::{fmt_outpoint, hex, parse_outpoint, unhex32},
};

fn sha256_file(p: &Path) -> Result<String> {
    Ok(hex(&Sha256::digest(std::fs::read(p).with_context(|| p.display().to_string())?)))
}

pub struct Deployed {
    pub registry_id: Hash,
    pub genesis_txid: TransactionId,
    pub genesis_outpoint: TransactionOutpoint,
    pub scan_from: Option<Hash>,
    pub dry_run: bool,
}

/// Build the manifest for a genesis plan. `scan_from` is the sink observed
/// just before submission (the scanner starts there).
pub fn build(paths: &Paths, kit: &Kit, plan: &Plan, deployer: &str, scan_from: Option<Hash>, dry_run: bool) -> Result<Value> {
    let tx = &plan.built.tx;
    let registry_id = plan.registry_id.ok_or_else(|| anyhow!("not a genesis plan"))?;
    let gap_out = &tx.outputs[0];
    ensure!(gap_out.covenant.map(|c| c.covenant_id) == Some(registry_id), "output 0 is not the genesis gap");
    ensure!(tx.outputs.iter().filter(|o| o.covenant.is_some()).count() == 1, "genesis authorizes one output only");
    let params: Value = serde_json::from_str(&std::fs::read_to_string(paths.params())?)?;
    let info: Value = serde_json::from_str(&std::fs::read_to_string(paths.artifacts().join("build-info.json"))?)?;
    let mut artifacts = serde_json::Map::new();
    for c in ["KachatGap", "KachatName"] {
        let path = paths.artifacts().join(format!("{c}.json"));
        let mut entry = info["contracts"][c].clone();
        entry["path"] = json!(paths.rel(&path));
        entry["fileSha256"] = json!(sha256_file(&path)?);
        artifacts.insert(c.into(), entry);
    }
    // sanity: the loaded templates are the ones the build-info describes
    ensure!(hex(&kit.gap.template_hash) == info["contracts"]["KachatGap"]["templateHash"], "gap template hash mismatch");
    ensure!(hex(&kit.name.template_hash) == info["contracts"]["KachatName"]["templateHash"], "name template hash mismatch");
    let o = &kit.offer;
    let span = o.abi.contracts[&o.contract].compiled.state_span;
    artifacts.insert(
        "KachatOffer".into(),
        json!({
            "bytecodeLen": o.bytecode.len(),
            "stateSpan": { "offset": span.offset, "len": span.len },
            "prefixLen": o.prefix.len(),
            "suffixLen": o.suffix.len(),
            "templateHash": hex(&o.template_hash),
            "bytecodeSha256": hex(&Sha256::digest(&o.bytecode)),
            "dispatchTags": {
                "accept": o.dispatch_tag("accept"), "withdraw": o.dispatch_tag("withdraw"), "refund": o.dispatch_tag("refund"),
            },
            "path": format!("artifacts/{PARAMS_FILE}/KachatOffer.json"),
            "note": "compiled for registryCovenantId with the pinned compiler library; scripts/build.sh writes the same bytes once params registryCovenantId is set",
        }),
    );
    // prefix and suffix bytes, so the manifest alone lets an indexer build
    // and check every P2SH (KACHAT_NAMES_INDEXER.md B2)
    for (c, t) in [("KachatGap", &kit.gap), ("KachatName", &kit.name), ("KachatOffer", &kit.offer)] {
        let e = artifacts.get_mut(c).unwrap();
        e["prefixHex"] = json!(hex(&t.prefix));
        e["suffixHex"] = json!(hex(&t.suffix));
    }
    let funding = tx.inputs[0].previous_outpoint;
    let mut p = params.clone();
    if let Some(m) = p.as_object_mut() {
        m.remove("registryCovenantId");
        m.remove("compiler");
        m.remove("network");
    }
    Ok(json!({
        "name": "kachat-names",
        "network": NETWORK,
        "status": if dry_run { "dry run: NOT broadcast, the registry does not exist" } else { "deployed" },
        "compiler": params["compiler"],
        "params": p,
        "artifacts": artifacts,
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
    let s = |p: &Value| p.as_str().map(str::to_string).ok_or_else(|| anyhow!("manifest field missing"));
    let registry_id = Hash::from_bytes(unhex32(&s(&v["registryCovenantId"])?)?);
    let g = &v["genesis"];
    let d = Deployed {
        registry_id,
        genesis_txid: TransactionId::from_bytes(unhex32(&s(&g["txid"])?)?),
        genesis_outpoint: parse_outpoint(&s(&g["outpoint"])?)?,
        scan_from: g["scanFrom"].as_str().map(|h| unhex32(h).map(Hash::from_bytes)).transpose()?,
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
        ensure!(v["artifacts"]["KachatGap"]["templateHash"] == hex(&kit.gap.template_hash), "manifest gap template hash differs");
        ensure!(v["artifacts"]["KachatName"]["templateHash"] == hex(&kit.name.template_hash), "manifest name template hash differs");
        ensure!(v["artifacts"]["KachatOffer"]["templateHash"] == hex(&kit.offer.template_hash), "manifest offer template hash differs");
        for (c, t) in [("KachatGap", &kit.gap), ("KachatName", &kit.name), ("KachatOffer", &kit.offer)] {
            ensure!(
                v["artifacts"][c]["prefixHex"] == hex(&t.prefix) && v["artifacts"][c]["suffixHex"] == hex(&t.suffix),
                "manifest {c} prefix/suffix differ from the templates"
            );
        }
    }
    Ok(d)
}

/// After a real genesis: fill `registryCovenantId` in params/testnet10.json
/// (a textual edit of the one `null`, so nothing else in the file moves).
pub fn fill_params_registry_id(paths: &Paths, id: Hash) -> Result<()> {
    let p = paths.params();
    let text = std::fs::read_to_string(&p)?;
    let needle = "\"registryCovenantId\": null";
    ensure!(text.matches(needle).count() == 1, "{}: registryCovenantId is already set", paths.rel(&p));
    std::fs::write(&p, text.replace(needle, &format!("\"registryCovenantId\": \"{id}\"")))?;
    Ok(())
}

/// For the dry run: a copy of params/testnet10.json with the would-be id,
/// which `scripts/build.py` accepts to build the offer artifact.
pub fn dryrun_params(paths: &Paths, id: Hash) -> Result<std::path::PathBuf> {
    let text = std::fs::read_to_string(paths.params())?;
    let out = paths.dryrun_dir().join(format!("params-{PARAMS_FILE}.json"));
    std::fs::create_dir_all(paths.dryrun_dir())?;
    std::fs::write(&out, text.replace("\"registryCovenantId\": null", &format!("\"registryCovenantId\": \"{id}\"")))?;
    Ok(out)
}
