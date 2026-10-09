//! The deployment manifest (`manifests/kachat-names-testnet-10.json`): what
//! the app and the indexer embed and verify before trusting any registry UTXO
//! (KACHAT_NAMES.md section 6): artifacts, template hashes, params, the
//! genesis binding (outpoint + authorized output) and the registry id.
//!
//! Registry v4 has one genesis (the registry's). Its prices are two fixed
//! tables (register: a name's first period, renew: every further one) baked
//! into the gap and the name, so they are in the manifest's params and behind
//! those two template hashes; there is no price record.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use kachat_names_harness::{FF32, Kit, ZERO32, gap_state};
use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint};
use kaspa_hashes::Hash;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    net::{net, spk_address},
    ops::Plan,
    paths::Paths,
    registry::Registry,
    util::{fmt_outpoint, hex, parse_outpoint, unhex32},
};

fn sha256_file(p: &Path) -> Result<String> {
    Ok(hex(&Sha256::digest(std::fs::read(p).with_context(|| p.display().to_string())?)))
}

pub struct Deployed {
    pub registry_id: Hash,
    pub genesis_txid: TransactionId,
    pub genesis_outpoint: TransactionOutpoint,
    /// where the scanner starts: the sink seen just before the genesis
    pub scan_from: Option<Hash>,
    pub dry_run: bool,
}

impl Deployed {
    /// The registry as the genesis leaves it.
    pub fn genesis_registry(&self, gap_value: u64) -> Registry {
        Registry::at_genesis(self.registry_id, self.genesis_txid, gap_value, self.scan_from)
    }
}

/// Build the manifest for a registry genesis plan. `scan_from` is the sink
/// observed just before submission.
pub fn build(paths: &Paths, kit: &Kit, plan: &Plan, deployer: &str, scan_from: Option<Hash>, dry_run: bool) -> Result<Value> {
    let tx = &plan.built.tx;
    let registry_id = plan.registry_id.ok_or_else(|| anyhow!("not a genesis plan"))?;
    let gap_out = &tx.outputs[0];
    ensure!(gap_out.covenant.map(|c| c.covenant_id) == Some(registry_id), "output 0 is not the genesis gap");
    ensure!(tx.outputs.iter().filter(|o| o.covenant.is_some()).count() == 1, "genesis authorizes one output only");
    let params: Value = serde_json::from_str(&std::fs::read_to_string(paths.params())?)?;
    let info: Value = serde_json::from_str(&std::fs::read_to_string(paths.artifacts().join("build-info.json"))?)?;
    let version = kit.params.registry_version as i64;
    ensure!(info["registryVersion"].as_i64() == Some(version), "{}: not a registry v{version} build (run ./scripts/build.sh)", paths.rel(&paths.artifacts()));
    let mut artifacts = serde_json::Map::new();
    // the name and the gap bake only params (both price tables included): the
    // committed artifacts, described by build-info.json
    for (c, t) in [("KachatName", &kit.name), ("KachatGap", &kit.gap)] {
        let path = paths.artifacts().join(format!("{c}.json"));
        let mut entry = info["contracts"][c].clone();
        ensure!(entry["templateHash"] == hex(&t.template_hash), "{c}: build-info template hash differs from the templates in use");
        entry["path"] = json!(paths.rel(&path));
        entry["fileSha256"] = json!(sha256_file(&path)?);
        artifacts.insert(c.into(), entry);
    }
    // the offer bakes the registry id: compiled in process (scripts/build.sh writes the
    // same bytes once params carry the id)
    {
        let t = &kit.offer;
        let span = t.abi.contracts[&t.contract].compiled.state_span;
        let tags: serde_json::Map<String, Value> =
            ["accept", "decline", "withdraw", "refund"].iter().map(|e| (e.to_string(), json!(t.dispatch_tag(e)))).collect();
        artifacts.insert(
            "KachatOffer".into(),
            json!({
                "bytecodeLen": t.bytecode.len(),
                "stateSpan": { "offset": span.offset, "len": span.len },
                "prefixLen": t.prefix.len(),
                "suffixLen": t.suffix.len(),
                "templateHash": hex(&t.template_hash),
                "bytecodeSha256": hex(&Sha256::digest(&t.bytecode)),
                "dispatchTags": tags,
                "path": format!("artifacts/{}/KachatOffer.json", net().params_file),
                "note": "compiled for registryCovenantId with the pinned compiler library; scripts/build.sh writes the same bytes once params carry it",
            }),
        );
    }
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
    // registry v5: the snapshot the gap bakes, by file and hash (anyone can rebuild it:
    // `kachat-names snapshot --check <file>`)
    let snapshot = match params.get("migration").filter(|m| !m.is_null()) {
        Some(m) => match m["snapshot"].as_str() {
            Some(f) => {
                let path = paths.root.join(f);
                let file: Value = serde_json::from_str(&std::fs::read_to_string(&path).with_context(|| f.to_string())?)?;
                ensure!(file["root"] == m["root"], "{f}: its root is not migration.root");
                json!({ "file": f, "sha256": sha256_file(&path)?, "predecessorRegistryId": file["predecessorRegistryId"], "atMs": file["atMs"], "names": file["entries"].as_array().map(|e| e.len()) })
            }
            None => Value::Null,
        },
        None => Value::Null,
    };
    Ok(json!({
        "name": "kachat-names",
        "registryVersion": version,
        "snapshot": snapshot,
        "network": net().name,
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
    ensure!(v["network"] == net().name, "{}: manifest is for {}", path.display(), v["network"]);
    ensure!(
        matches!(v["registryVersion"].as_i64(), Some(4) | Some(5)),
        "{}: not a registry v4 or v5 manifest (registry v{}; a new version needs its own genesis: archive the old manifest first)",
        path.display(),
        v["registryVersion"]
    );
    if let Some(kit) = kit_check {
        ensure!(
            v["registryVersion"].as_i64() == Some(kit.params.registry_version as i64),
            "{}: a registry v{} manifest, but params build v{}",
            path.display(),
            v["registryVersion"],
            kit.params.registry_version
        );
    }
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
        for (c, t) in [("KachatGap", &kit.gap), ("KachatName", &kit.name), ("KachatOffer", &kit.offer)] {
            ensure!(v["artifacts"][c]["templateHash"] == hex(&t.template_hash), "manifest {c} template hash differs");
            ensure!(
                v["artifacts"][c]["prefixHex"] == hex(&t.prefix) && v["artifacts"][c]["suffixHex"] == hex(&t.suffix),
                "manifest {c} prefix/suffix differ from the templates"
            );
        }
        // the gap and name hashes cover the baked tables; the params must say the same
        let tiers = |t: &[u64; 5]| json!({ "len1": t[0], "len2": t[1], "len3": t[2], "len4": t[3], "len5plus": t[4] });
        ensure!(
            v["params"]["prices"] == json!({ "register": tiers(&kit.params.register_prices), "renew": tiers(&kit.params.renew_prices) }),
            "manifest price tables differ from params/{}.json", net().params_file
        );
    }
    Ok(d)
}

/// After a real genesis: fill `registryCovenantId` in params/testnet10.json (a
/// textual edit of the one `null`, so nothing else moves).
pub fn fill_registry_id(paths: &Paths, id: Hash) -> Result<()> {
    let p = paths.params();
    let text = std::fs::read_to_string(&p)?;
    let needle = "\"registryCovenantId\": null";
    ensure!(text.matches(needle).count() == 1, "{}: registryCovenantId is already set", paths.rel(&p));
    std::fs::write(&p, text.replace(needle, &format!("\"registryCovenantId\": \"{id}\"")))?;
    Ok(())
}

/// For the dry run: a copy of params/testnet10.json with the would-be registry id
/// (replacing null, or the id of an already deployed registry), which
/// `scripts/build.py` accepts to build the offer artifact (and the name and gap).
pub fn dryrun_params(paths: &Paths, registry_id: Hash) -> Result<std::path::PathBuf> {
    let text = std::fs::read_to_string(paths.params())?;
    let out = paths.dryrun_dir().join(format!("params-{}.json", net().params_file));
    std::fs::create_dir_all(paths.dryrun_dir())?;
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let at = lines
        .iter()
        .position(|l| l.trim_start().starts_with("\"registryCovenantId\":"))
        .ok_or_else(|| anyhow!("params without registryCovenantId"))?;
    let indent: String = lines[at].chars().take_while(|c| c.is_whitespace()).collect();
    let comma = if lines[at].trim_end().ends_with(',') { "," } else { "" };
    lines[at] = format!("{indent}\"registryCovenantId\": \"{registry_id}\"{comma}");
    std::fs::write(&out, lines.join("\n") + "\n")?;
    Ok(out)
}
