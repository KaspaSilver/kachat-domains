//! `kachat-names-vectors`: test vectors for ports of the transaction core
//! (the KaChat iOS app's Swift `.kachat` name builders).
//!
//! Runs the CLI's own builders (`ops::*`, the same code `--submit` uses) on
//! synthetic UTXOs - the whole e2e plan through `plan::Sim`, plus edge cases -
//! and writes, for every transaction: the builder inputs (environment, wallet,
//! decoded registry records, arguments), and everything a port must reproduce
//! byte for byte (inputs with sequences and compute budgets, outputs with
//! covenant bindings, lock time, payload, masses, fee, the v1 rest preimage,
//! the full hashing preimage, every input's SIGHASH_ALL Schnorr sighash, the
//! signatures, the signature scripts, the txid). It also writes codec vectors
//! (blake3 name keys, commitments, num8, minimal pushes, script numbers, P2SH,
//! covenant ids) and the manifest of the synthetic genesis, in the schema the
//! CLI's `genesis` writes.
//!
//! Every transaction is validated by rusty-kaspa's consensus validator (as in
//! the CLI) and every input is run under its committed compute budget. The
//! generator also checks the budgets the CLI measured never exceed the fixed
//! table an app without a script engine uses (`RECOMMENDED_BUDGETS`).
//!
//! Signatures come from `secp256k1` with random aux data (the harness signs
//! that way), so the signature bytes change between runs; everything else is
//! deterministic. A port feeds the recorded signatures in and must then
//! reproduce the signed transaction exactly.
//!
//! `check <file>` closes the loop the other way: it reads transactions a port
//! built with its own fixed compute budgets (`RECOMMENDED_BUDGETS`, not the
//! measured ones) and placeholder signatures (64 zero bytes + 0x01), signs
//! every placeholder with the vectors' deployer key over the real sighash, and
//! runs the result through the same consensus validator, under the committed
//! budgets, the standardness checks and the relay-fee floor.
//!
//! Nothing here touches the network.
//!
//!     cargo run --release --bin kachat-names-vectors -- <out.json>
//!     cargo run --release --bin kachat-names-vectors -- check <port-built.json>

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail, ensure};
use kachat_names_cli::{
    commits::{CommitRec, find_open},
    manifest,
    net::{p2pk_address, spk_address},
    ops::{self, Env, ExitParts, Plan, Templates},
    paths::Paths,
    plan::{Sim, Step, e2e_steps},
    registry::{GapRec, NameRec, OfferRec},
    util::{SOMPI, hex, parse_pushes},
};
use kachat_names_harness::{
    Block, FF32, NameFields, OfferFields, TransactionId, TransactionOutpoint, Utxo, UtxoEntry, YEAR_MS, ZERO32, commit_redeem,
    commitment, gap_state, keypair, name_key, name_state, num8, offer_state, p2pk_spk, pad_name, push, scenarios::NOW_MS, xonly,
};
use kaspa_consensus_core::{
    hashing::{
        covenant_id::covenant_id,
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{MutableTransaction, ScriptPublicKey, Transaction, TransactionOutput},
};
use kaspa_hashes::HasherBase;
use kaspa_txscript::{EngineFlags, pay_to_script_hash_script, script_builder::ScriptBuilder};
use serde_json::{Value, json};

/// The compute budgets an app without a script engine commits per entry
/// (README "Cost per operation"): every budget the CLI measures must fit.
/// Registry v4: no price input (the tables are baked), so register, merge, extend and
/// renew are back to their v2 budgets (measured: register at most 85,837 script units,
/// merge 46,918, extend / renew ~19,940, which budget 1's 19,999 covers by under 60
/// units: 2 leaves room); offers check the seller's signature.
const RECOMMENDED_BUDGETS: &[(&str, u16)] = &[
    ("p2pk", 10),
    ("commit", 10),
    ("gap.register", 8),
    ("gap.merge", 4),
    ("gap.absorbed", 0),
    ("name.transfer", 12),
    ("name.list", 12),
    ("name.buy", 2),
    ("name.extend", 2),
    ("name.renew", 2),
    ("name.release", 10),
    ("name.reclaim", 0),
    ("offer.accept", 17),
    ("offer.decline", 10),
    ("offer.withdraw", 10),
    ("offer.refund", 0),
];

fn main() -> Result<()> {
    let arg1 = std::env::args().nth(1).ok_or_else(|| anyhow!("usage: kachat-names-vectors <out.json> | check <port-built.json>"))?;
    if arg1 == "check" {
        let file = std::env::args().nth(2).ok_or_else(|| anyhow!("usage: kachat-names-vectors check <port-built.json>"))?;
        return check(&PathBuf::from(file));
    }
    let out = PathBuf::from(arg1);
    let paths = Paths::find(None)?;
    let wall = NOW_MS + 10 * YEAR_MS;

    // ---- the e2e plan, step by step ------------------------------------
    let mut sim = Sim::new(Templates::load(&paths.root), 100 * SOMPI, wall);
    let mut steps = vec![];
    let mut manifest_json = Value::Null;
    let mut tags = vec![];
    for (step, _) in e2e_steps() {
        if matches!(step, Step::Wait(..)) {
            sim.run(&step)?;
            continue;
        }
        let before = Snapshot::of(&sim);
        let records = records_for(&sim, &step)?;
        sim.run(&step)?;
        let plan = sim.plans.last().unwrap();
        if matches!(step, Step::Genesis) {
            let kit = sim.kit.as_ref().unwrap();
            let deployer = p2pk_address(&xonly(&sim.deployer)).to_string();
            manifest_json = manifest::build(&paths, kit, plan, &deployer, None, true)?;
            tags = dispatch_tags(kit);
            continue;
        }
        let args = match &step {
            Step::Commit(_) => commit_args(plan),
            Step::Register { years, .. } => json!({ "years": years, "now": plan.built.tx.lock_time }),
            Step::Extend(_, y) | Step::Renew(_, y) => json!({ "years": y }),
            Step::TransferToSelf(_) => json!({ "newOwner": hex(&xonly(&sim.deployer)) }),
            Step::List(_, p) => json!({ "price": p }),
            Step::Offer(..) => offer_args(plan),
            _ => json!({}),
        };
        steps.push(step_json(op_name(&step), &before, records, args, plan, &tags)?);
    }
    let registry_id = sim.kit.as_ref().unwrap().registry_id;
    let templates_params = sim.kit.as_ref().unwrap().params.clone();

    // ---- edge cases on the same registry ---------------------------------
    let templates = Templates::load(&paths.root);
    let extra = extra_cases(&templates, registry_id, wall, &tags)?;
    steps.extend(extra);

    let v = json!({
        "about": "kachat-names transaction vectors: CLI builders (tools/kachat-names-cli/src/ops.rs) on synthetic UTXOs, \
                  validated by rusty-kaspa a41a333's consensus validator. Signatures are random per run (secp256k1 aux \
                  randomness); everything else is deterministic.",
        "generator": "tools/kachat-names-cli/src/bin/kachat-names-vectors.rs",
        "rustyKaspa": "a41a333b08848f41bf737b72592e463a6011b8ac",
        "network": "testnet-10",
        "addressPrefix": "kaspatest",
        "feerate": ops::MIN_FEERATE,
        "minChange": ops::MIN_CHANGE,
        "targetChange": ops::TARGET_CHANGE,
        "commitValue": ops::COMMIT_VALUE,
        "maxInputsFeeEntry": ops::MAX_IO_FEE_ENTRY,
        "maxInputs": ops::MAX_INPUTS,
        "registry": "v4: fixed register and renew tables baked into KachatGap and KachatName (no price record), periodMs, offers bound to the seller (108 B state), decline",
        "registryCovenantId": hex(&registry_id.as_bytes()),
        "maxYears": templates_params.max_years,
        "periodMs": templates_params.period_ms,
        "graceMs": templates_params.grace_ms,
        "renewWindowMs": templates_params.renew_window_ms,
        "registerPrices": templates_params.register_prices,
        "renewPrices": templates_params.renew_prices,
        "priceRules": {
            "tier": "index = clamp(name length in bytes, 1, 5) - 1 into registerPrices / renewPrices (1, 2, 3, 4, 5+ chars)",
            "register": "priceFee = registerPrices[tier] + renewPrices[tier] * (years - 1)",
            "extendRenew": "priceFee = renewPrices[tier] * years",
        },
        "inputLayouts": {
            "register": "0 gap.register(name, owner, salt, now, years, namePrefix, nameSuffix), 1 commit, 2.. funding; outputs 0 gap (lo,key), 1 gap (key,hi), 2 name, change",
            "extendRenew": "0 name.extend|renew(years), 1.. funding; outputs 0 name, change",
            "acceptOffer": "0 name.transfer(buyer, ownerSig), 1 offer.accept(0, sellerSig)",
            "declineOffer": "0 offer.decline(sellerSig), alone; one output back to the buyer",
        },
        "lockTimeRules": {
            "extend": "lockTime 0, every input sequence 0; valid any time while expiresAt + years*periodMs <= periodStart + maxYears*periodMs",
            "renew": "lockTime = max(min(wallMs - 180000, blockTimeMs - 1000), expiresAt - renewWindowMs) (unix ms, timestamp domain); \
                      every input sequence 0 (not u64::MAX: the CLTV needs a non-final input); final, so valid, only once the past \
                      median time (blockTimeMs) is above the lock time, i.e. once the window opened; a builder refuses before",
            "register": "lockTime = now = min(wallMs - 180000, blockTimeMs - 1000); commit input sequence = tCommit",
            "reclaim": "lockTime = expiresAt + graceMs; every input sequence 0",
            "refundOffer": "lockTime = refundAfter (DAA score); sequence 0",
        },
        "recommendedBudgets": RECOMMENDED_BUDGETS.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>(),
        "deployer": {
            "xonly": hex(&xonly(&sim.deployer)),
            "address": p2pk_address(&xonly(&sim.deployer)).to_string(),
        },
        "manifest": manifest_json,
        "codecs": codecs(&templates, registry_id)?,
        "steps": steps,
    });
    std::fs::write(&out, serde_json::to_string_pretty(&v)? + "\n")?;
    eprintln!("wrote {} ({} transactions)", out.display(), v["steps"].as_array().unwrap().len());
    Ok(())
}

fn op_name(step: &Step) -> &'static str {
    match step {
        Step::Commit(_) => "commit",
        Step::Register { .. } => "register",
        Step::Extend(..) => "extend",
        Step::Renew(..) => "renew",
        Step::TransferToSelf(_) => "transfer",
        Step::List(..) => "list",
        Step::Buy(_) => "buy",
        Step::Offer(..) => "offer",
        Step::Accept(_) => "acceptOffer",
        Step::Decline(_) => "declineOffer",
        Step::Refund(_) => "refundOffer",
        Step::Withdraw(_) => "withdrawOffer",
        Step::Release(_) => "release",
        Step::Reclaim(_) => "reclaim",
        Step::Genesis | Step::Wait(..) => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// builder inputs
// ---------------------------------------------------------------------------

struct Snapshot {
    block: Block,
    wall_ms: i64,
    wallet: Vec<Utxo>,
    deployer: [u8; 32],
}

impl Snapshot {
    fn of(sim: &Sim) -> Snapshot {
        Snapshot { block: sim.block, wall_ms: sim.wall_ms, wallet: sim.wallet.clone(), deployer: xonly(&sim.deployer) }
    }
}

fn utxo_json(u: &Utxo) -> Value {
    json!({
        "txid": hex(&u.outpoint.transaction_id.as_bytes()),
        "index": u.outpoint.index,
        "amount": u.entry.amount,
        "scriptVersion": u.entry.script_public_key.version(),
        "script": hex(u.entry.script_public_key.script()),
        "blockDaaScore": u.entry.block_daa_score,
        "isCoinbase": u.entry.is_coinbase,
        "covenantId": u.entry.covenant_id.map(|h| hex(&h.as_bytes())),
    })
}

fn gap_json(g: &GapRec, u: &Utxo) -> Value {
    json!({ "lo": hex(&g.lo), "hi": hex(&g.hi), "value": g.value, "utxo": utxo_json(u) })
}

fn name_json(n: &NameRec, u: &Utxo) -> Value {
    json!({
        "name": n.name(),
        "key": hex(&n.fields.key),
        "owner": hex(&n.fields.owner),
        "price": n.fields.price,
        "periodStart": n.fields.period_start,
        "expiresAt": n.fields.expires_at,
        "value": n.value,
        "utxo": utxo_json(u),
    })
}

fn offer_json(o: &OfferRec, u: &Utxo) -> Value {
    json!({
        "key": hex(&o.fields.key),
        "buyer": hex(&o.fields.buyer),
        "seller": hex(&o.fields.seller),
        "refundAfter": o.fields.refund_after,
        "value": o.value,
        "name": o.name,
        "utxo": utxo_json(u),
    })
}

fn commit_json(c: &CommitRec, u: &Utxo) -> Value {
    json!({ "name": c.name, "owner": hex(&c.owner), "salt": hex(&c.salt), "value": c.value, "utxo": utxo_json(u) })
}

fn live(sim: &Sim, op: &TransactionOutpoint) -> Result<Utxo> {
    Ok(Utxo::new(*op, sim.utxos.get(op).ok_or_else(|| anyhow!("missing simulated UTXO"))?.clone()))
}

/// The registry records a step reads, exactly as `Sim::run` picks them.
fn records_for(sim: &Sim, step: &Step) -> Result<Value> {
    let me = xonly(&sim.deployer);
    let Some(reg) = sim.reg.as_ref() else { return Ok(json!({})) };
    Ok(match step {
        Step::Register { name, .. } => {
            let c = find_open(&sim.commits, name, &me).ok_or_else(|| anyhow!("no commit"))?;
            let g = reg.gap_for_key(&name_key(name.as_bytes())).ok_or_else(|| anyhow!("no gap"))?;
            json!({ "gap": gap_json(g, &live(sim, &g.outpoint)?), "commit": commit_json(c, &live(sim, &c.outpoint.unwrap())?) })
        }
        Step::Extend(n, _) | Step::Renew(n, _) | Step::TransferToSelf(n) | Step::List(n, _) | Step::Buy(n) => {
            let r = reg.name(n).ok_or_else(|| anyhow!("no name"))?;
            json!({ "name": name_json(r, &live(sim, &r.outpoint)?) })
        }
        Step::Offer(n, ..) => {
            let r = reg.name(n).ok_or_else(|| anyhow!("no name"))?;
            json!({ "target": name_json(r, &live(sim, &r.outpoint)?) })
        }
        Step::Accept(n) | Step::Decline(n) | Step::Refund(n) | Step::Withdraw(n) => {
            let o = *reg.offers_for(&name_key(n.as_bytes())).last().ok_or_else(|| anyhow!("no offer"))?;
            let mut v = json!({ "offer": offer_json(o, &live(sim, &o.outpoint)?) });
            if matches!(step, Step::Accept(_)) {
                let r = reg.name(n).ok_or_else(|| anyhow!("no name"))?;
                v["name"] = name_json(r, &live(sim, &r.outpoint)?);
            }
            v
        }
        Step::Release(n) | Step::Reclaim(n) => {
            let r = reg.name(n).ok_or_else(|| anyhow!("no name"))?;
            let (b, a) = reg.neighbours(&r.fields.key).ok_or_else(|| anyhow!("no gaps"))?;
            json!({
                "below": gap_json(b, &live(sim, &b.outpoint)?),
                "name": name_json(r, &live(sim, &r.outpoint)?),
                "above": gap_json(a, &live(sim, &a.outpoint)?),
            })
        }
        _ => json!({}),
    })
}

// ---------------------------------------------------------------------------
// expected results
// ---------------------------------------------------------------------------

/// The role of an input, from its signature script: `p2pk`, `commit`, or
/// `<contract>.<entry>` from the dispatch tag.
fn role(tx: &Transaction, i: usize, entry: &UtxoEntry, tags: &[(String, String)]) -> Result<String> {
    let pushes = parse_pushes(&tx.inputs[i].signature_script)?;
    let spk = entry.script_public_key.script();
    if spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xac && pushes.len() == 1 && pushes[0].len() == 65 {
        return Ok("p2pk".into());
    }
    let last = pushes.last().ok_or_else(|| anyhow!("empty signature script"))?;
    if pushes.len() == 2 && last.len() == 68 && last[0] == 0x20 && last[33] == 0x75 {
        return Ok("commit".into());
    }
    let tag = hex(&pushes[pushes.len() - 2]);
    tags.iter().find(|(t, _)| *t == tag).map(|(_, r)| r.clone()).ok_or_else(|| anyhow!("unknown dispatch tag {tag}"))
}

fn dispatch_tags(kit: &kachat_names_harness::Kit) -> Vec<(String, String)> {
    let mut v = vec![];
    for e in ["register", "merge", "absorbed"] {
        v.push((kit.gap.dispatch_tag(e), format!("gap.{e}")));
    }
    for e in ["transfer", "list", "buy", "extend", "renew", "release", "reclaim"] {
        v.push((kit.name.dispatch_tag(e), format!("name.{e}")));
    }
    for e in ["accept", "decline", "withdraw", "refund"] {
        v.push((kit.offer.dispatch_tag(e), format!("offer.{e}")));
    }
    v
}

/// `write_transaction(tx, FULL)` of rusty-kaspa (consensus/core/src/hashing/tx.rs):
/// the TransactionHash preimage. Checked against `hashing::tx::hash`.
fn full_preimage(tx: &Transaction) -> Vec<u8> {
    let mut b = vec![];
    b.extend(tx.version.to_le_bytes());
    b.extend((tx.inputs.len() as u64).to_le_bytes());
    for i in &tx.inputs {
        b.extend(i.previous_outpoint.transaction_id.as_bytes());
        b.extend(i.previous_outpoint.index.to_le_bytes());
        b.extend((i.signature_script.len() as u64).to_le_bytes());
        b.extend(&i.signature_script);
        b.extend(i.sequence.to_le_bytes());
        b.extend(i.compute_commit.compute_budget().unwrap_or(0).to_le_bytes());
    }
    b.extend((tx.outputs.len() as u64).to_le_bytes());
    for o in &tx.outputs {
        b.extend(o.value.to_le_bytes());
        b.extend(o.script_public_key.version().to_le_bytes());
        b.extend((o.script_public_key.script().len() as u64).to_le_bytes());
        b.extend(o.script_public_key.script());
        b.push(o.covenant.is_some() as u8);
        if let Some(c) = &o.covenant {
            b.extend(c.authorizing_input.to_le_bytes());
            b.extend(c.covenant_id.as_bytes());
        }
    }
    b.extend(tx.lock_time.to_le_bytes());
    let subnet: &[u8] = tx.subnetwork_id.as_ref();
    b.extend_from_slice(subnet);
    b.extend(tx.gas.to_le_bytes());
    b.extend((tx.payload.len() as u64).to_le_bytes());
    b.extend(&tx.payload);
    b.extend(tx.storage_mass().to_le_bytes());
    b
}

fn step_json(op: &str, before: &Snapshot, records: Value, args: Value, plan: &Plan, kit_tags: &[(String, String)]) -> Result<Value> {
    ensure!(plan.is_valid(), "{}: {:?} / {:?}", plan.op, plan.validation, plan.standard);
    for (i, r) in plan.built.run_inputs().into_iter().enumerate() {
        r.map_err(|e| anyhow!("{}: input {i} fails under its budget: {e:?}", plan.op))?;
    }
    let tx = &plan.built.tx;
    ensure!(tx.version == 1);
    let entries = &plan.built.entries;

    // the full preimage really is the TransactionHash preimage
    let pre = full_preimage(tx);
    let mut h = kaspa_hashes::TransactionHash::new();
    h.update(&pre);
    ensure!(h.finalize() == kaspa_consensus_core::hashing::tx::hash(tx), "full preimage does not hash to tx.hash()");

    let mtx = MutableTransaction::with_entries(tx.clone(), entries.clone());
    let mut inputs = vec![];
    for (i, input) in tx.inputs.iter().enumerate() {
        let reused = SigHashReusedValuesUnsync::new();
        let sighash = calc_schnorr_signature_hash(&mtx.as_verifiable(), i, SIG_HASH_ALL, &reused);
        let pushes = parse_pushes(&input.signature_script)?;
        let sigs: Vec<String> = pushes.iter().filter(|p| p.len() == 65 && p[64] == 0x01).map(|p| hex(p)).collect();
        let role = role(tx, i, &entries[i], kit_tags)?;
        let budget = input.compute_commit.compute_budget().ok_or_else(|| anyhow!("v1 input without a budget"))?;
        let rec = RECOMMENDED_BUDGETS.iter().find(|(r, _)| *r == role).map(|(_, b)| *b).ok_or_else(|| anyhow!("no budget for {role}"))?;
        if budget > rec {
            bail!("{}: input {i} ({role}) measured budget {budget} > recommended {rec}", plan.op);
        }
        inputs.push(json!({
            "txid": hex(&input.previous_outpoint.transaction_id.as_bytes()),
            "index": input.previous_outpoint.index,
            "sequence": input.sequence,
            "computeBudget": budget,
            "usedScriptUnits": plan.built.used_units[i],
            "role": role,
            "label": plan.input_labels[i],
            "entry": utxo_json(&Utxo::new(input.previous_outpoint, entries[i].clone())),
            "sighash": hex(&sighash.as_bytes()),
            "signatures": sigs,
            "signatureScript": hex(&input.signature_script),
        }));
    }
    let outputs: Vec<Value> = tx
        .outputs
        .iter()
        .zip(&plan.output_labels)
        .map(|(o, l)| {
            json!({
                "value": o.value,
                "scriptVersion": o.script_public_key.version(),
                "script": hex(o.script_public_key.script()),
                "address": spk_address(&o.script_public_key).map(|a| a.to_string()).ok(),
                "covenant": o.covenant.map(|c| json!({ "authorizingInput": c.authorizing_input, "covenantId": hex(&c.covenant_id.as_bytes()) })),
                "label": l,
            })
        })
        .collect();
    let c = &plan.costs;
    Ok(json!({
        "op": op,
        "label": plan.op,
        "env": {
            "blockDaa": before.block.daa,
            "blockTimeMs": before.block.time_ms,
            "wallMs": before.wall_ms,
            "feerate": ops::MIN_FEERATE,
            "me": hex(&before.deployer),
        },
        "wallet": before.wallet.iter().map(utxo_json).collect::<Vec<_>>(),
        "args": args,
        "records": records,
        "expected": {
            "version": tx.version,
            "lockTime": tx.lock_time,
            "subnetworkId": hex(AsRef::<[u8]>::as_ref(&tx.subnetwork_id)),
            "gas": tx.gas,
            "payload": hex(&tx.payload),
            "payloadText": String::from_utf8_lossy(&tx.payload),
            "storageMass": tx.storage_mass(),
            "size": c.size,
            "computeMass": c.compute_mass,
            "transientMass": c.transient_mass,
            "normalizedTransient": c.normalized_transient,
            "minFee": c.min_fee,
            "priceFee": plan.price_fee,
            "networkFee": plan.network_fee,
            "fee": plan.validation.as_ref().unwrap(),
            "inputs": inputs,
            "outputs": outputs,
            "restPreimage": hex(&kaspa_consensus_core::hashing::tx::transaction_v1_rest_preimage(tx)),
            "fullPreimage": hex(&pre),
            "txid": hex(&tx.id().as_bytes()),
            "txHash": hex(&kaspa_consensus_core::hashing::tx::hash(tx).as_bytes()),
            "notes": plan.notes,
        }
    }))
}

fn commit_args(plan: &Plan) -> Value {
    let c = plan.new_commit.as_ref().unwrap();
    json!({ "name": c.name, "salt": hex(&c.salt) })
}

fn offer_args(plan: &Plan) -> Value {
    let o = plan.new_offer.as_ref().unwrap();
    json!({ "name": o.name, "amount": o.value, "refundAfter": o.fields.refund_after, "seller": hex(&o.fields.seller) })
}

// ---------------------------------------------------------------------------
// edge cases
// ---------------------------------------------------------------------------

fn synthetic(tag: u8, index: u32, amount: u64, spk: ScriptPublicKey, daa: u64, cov: Option<kaspa_hashes::Hash>) -> Utxo {
    Utxo::new(TransactionOutpoint::new(TransactionId::from_bytes([tag; 32]), index), UtxoEntry::new(amount, spk, daa, false, cov))
}

fn extra_cases(t: &Templates, registry_id: kaspa_hashes::Hash, wall: i64, tags: &[(String, String)]) -> Result<Vec<Value>> {
    let deployer = keypair(77);
    let me = xonly(&deployer);
    let stranger = xonly(&keypair(5));
    let block = Block { daa: 600_000_000, time_ms: (wall - 132_000) as u64 };
    let env = Env { kit: t.kit(registry_id)?, deployer, block, wall_ms: wall, feerate: ops::MIN_FEERATE };
    let id = Some(registry_id);
    let snap = |wallet: &[Utxo]| Snapshot { block, wall_ms: wall, wallet: wallet.to_vec(), deployer: me };
    let mut out = vec![];
    let p = &env.kit.params;
    let period = p.period_ms;

    // register a 32-character name for 2 periods from six small UTXOs (the 8-input bound)
    {
        let name = "abcdefghijklmnopqrstuvwxyz-01234";
        ensure!(name.len() == 32);
        let wallet: Vec<Utxo> = (0..7).map(|i| synthetic(0xd0 + i, i as u32, 45_000_000, p2pk_spk(&me), block.daa - 5_000, None)).collect();
        let salt = [0x31; 32];
        let c = CommitRec { name: name.into(), owner: me, salt, value: ops::COMMIT_VALUE, outpoint: None, used_by: None, created_ms: 0 };
        let cu = synthetic(0xc1, 0, ops::COMMIT_VALUE, pay_to_script_hash_script(&commit_redeem(&commitment(name.as_bytes(), &me, &salt), &me)), block.daa - 700, None);
        let c = CommitRec { outpoint: Some(cu.outpoint), ..c };
        let g = GapRec { outpoint: TransactionOutpoint::new(TransactionId::from_bytes([0xa1; 32]), 1), lo: ZERO32, hi: FF32, value: p.gap_value };
        let gu = synthetic(0xa1, 1, p.gap_value, env.kit.gap.spk(&gap_state(&ZERO32, &FF32)), block.daa - 900, id);
        let now = ops::register_now(&env);
        let plan = ops::register(&env, &wallet, &g, &gu, &c, &cu, 2, now)?;
        ensure!(plan.built.tx.inputs.len() == 8, "expected the 8-input bound, got {}", plan.built.tx.inputs.len());
        ensure!(plan.price_fee == p.register_prices[4] + p.renew_prices[4], "2 periods: the 5+ registration price + one renewal");
        let args = json!({ "years": 2, "now": now });
        let recs = json!({ "gap": gap_json(&g, &gu), "commit": commit_json(&c, &cu) });
        out.push(step_json("register", &snap(&wallet), recs, args, &plan, tags)?);
    }

    // register a 1-character name for 2 periods (40 TKAS for the first on testnet, 10 for
    // the second) inside a narrower gap
    {
        let name = "x";
        let key = name_key(name.as_bytes());
        let mut lo = key;
        lo[31] = lo[31].wrapping_sub(1);
        let mut hi = key;
        hi[0] = 0xff;
        let lo = if lo < key { lo } else { ZERO32 };
        let wallet = vec![synthetic(0xd8, 3, 200 * SOMPI, p2pk_spk(&me), block.daa - 5_000, None)];
        let salt = [0x32; 32];
        let cu = synthetic(0xc2, 0, ops::COMMIT_VALUE, pay_to_script_hash_script(&commit_redeem(&commitment(name.as_bytes(), &me, &salt), &me)), block.daa - 600, None);
        let c = CommitRec { name: name.into(), owner: me, salt, value: ops::COMMIT_VALUE, outpoint: Some(cu.outpoint), used_by: None, created_ms: 0 };
        let g = GapRec { outpoint: TransactionOutpoint::new(TransactionId::from_bytes([0xa2; 32]), 0), lo, hi, value: p.gap_value };
        let gu = synthetic(0xa2, 0, p.gap_value, env.kit.gap.spk(&gap_state(&lo, &hi)), block.daa - 900, id);
        let now = ops::register_now(&env);
        ensure!(lo < key && key < hi);
        let plan = ops::register(&env, &wallet, &g, &gu, &c, &cu, 2, now)?;
        ensure!(plan.price_fee == p.register_prices[0] + p.renew_prices[0], "the 1-char registration price + one 1-char renewal");
        let args = json!({ "years": 2, "now": now });
        let recs = json!({ "gap": gap_json(&g, &gu), "commit": commit_json(&c, &cu) });
        out.push(step_json("register", &snap(&wallet), recs, args, &plan, tags)?);
    }

    // a commit whose leftover is below MIN_CHANGE: no change output, the rest goes to the miner
    {
        let wallet = vec![synthetic(0xd9, 0, 25_000_000, p2pk_spk(&me), block.daa - 5_000, None)];
        let salt = [0x33; 32];
        let plan = ops::commit(&env, &wallet, "nochange", salt)?;
        ensure!(plan.built.tx.outputs.len() == 1);
        out.push(step_json("commit", &snap(&wallet), json!({}), commit_args(&plan), &plan, tags)?);
    }

    let wallet: Vec<Utxo> = vec![
        synthetic(0xe0, 0, 3 * SOMPI, p2pk_spk(&me), block.daa - 5_000, None),
        synthetic(0xe1, 2, 60 * SOMPI, p2pk_spk(&me), block.daa - 5_000, None),
        synthetic(0xe2, 1, 3 * SOMPI, p2pk_spk(&me), block.daa - 5_000, None),
    ];
    let name_utxo = |fields: &NameFields, tag: u8| synthetic(tag, 2, p.bond, env.kit.name.spk(&fields.encode()), block.daa - 2_000, id);
    let rec = |fields: NameFields, u: &Utxo| NameRec { outpoint: u.outpoint, fields, value: p.bond };

    // delist (list at 0)
    {
        let f = NameFields::new(b"listed-one", &me, 7 * SOMPI as i64, wall, wall + period);
        let u = name_utxo(&f, 0xb1);
        let n = rec(f, &u);
        let plan = ops::list(&env, &wallet, &n, &u, 0)?;
        out.push(step_json("list", &snap(&wallet), json!({ "name": name_json(&n, &u) }), json!({ "price": 0 }), &plan, tags)?);
    }

    // transfer to another key
    {
        let f = NameFields::new(b"gift", &me, 0, wall, wall + period);
        let u = name_utxo(&f, 0xb2);
        let n = rec(f, &u);
        let plan = ops::transfer(&env, &wallet, &n, &u, &stranger)?;
        out.push(step_json("transfer", &snap(&wallet), json!({ "name": name_json(&n, &u) }), json!({ "newOwner": hex(&stranger) }), &plan, tags)?);
    }

    // buy another owner's listing (payout to them at continuation + 1)
    {
        let f = NameFields::new(b"for-sale", &stranger, 12 * SOMPI as i64, wall, wall + period);
        let u = name_utxo(&f, 0xb3);
        let n = rec(f, &u);
        let plan = ops::buy(&env, &wallet, &n, &u)?;
        out.push(step_json("buy", &snap(&wallet), json!({ "name": name_json(&n, &u) }), json!({}), &plan, tags)?);
    }

    // renew in grace: another owner's 4-character name, expired 5 minutes ago (grace is 30),
    // for 2 periods
    {
        let e = wall - 5 * 60_000;
        let f = NameFields::new(b"four", &stranger, 0, e - period, e);
        let u = name_utxo(&f, 0xb4);
        let n = rec(f, &u);
        let w = vec![synthetic(0xe3, 0, 20 * SOMPI, p2pk_spk(&me), block.daa - 5_000, None)];
        let plan = ops::renew(&env, &w, &n, &u, 2)?;
        ensure!(plan.built.tx.lock_time as i64 == ops::register_now(&env), "renew in grace: lock time = now - 3 min");
        ensure!(plan.price_fee == 2 * p.renew_prices[3], "2 periods at the 4-char renewal price");
        out.push(step_json("renew", &snap(&w), json!({ "name": name_json(&n, &u) }), json!({ "years": 2 }), &plan, tags)?);
    }

    // renew in the window: expires in 5 minutes (the window opened 5 minutes ago), 1 period
    {
        let e = wall + 5 * 60_000;
        let f = NameFields::new(b"in-window", &me, 0, e - period, e);
        let u = name_utxo(&f, 0xba);
        let n = rec(f, &u);
        let plan = ops::renew(&env, &wallet, &n, &u, 1)?;
        ensure!(plan.built.tx.lock_time as i64 == ops::register_now(&env), "renew in the window: lock time = now - 3 min");
        out.push(step_json("renew", &snap(&wallet), json!({ "name": name_json(&n, &u) }), json!({ "years": 1 }), &plan, tags)?);
    }

    // renew right as the window opens (30 s before the median time): now - 3 min
    // is still before the window, so the lock time is the window opening itself
    {
        let opens = block.time_ms as i64 - 30_000;
        let e = opens + p.renew_window_ms;
        let f = NameFields::new(b"just-opened", &me, 0, e - period, e);
        let u = name_utxo(&f, 0xbb);
        let n = rec(f, &u);
        let plan = ops::renew(&env, &wallet, &n, &u, 1)?;
        ensure!(plan.built.tx.lock_time as i64 == opens, "renew at the window opening: lock time = expiresAt - renewWindowMs");
        out.push(step_json("renew", &snap(&wallet), json!({ "name": name_json(&n, &u) }), json!({ "years": 1 }), &plan, tags)?);
    }

    // extend another owner's 1-period name (registered 2 minutes ago) to 2 periods (a gift)
    {
        let start = wall - 2 * 60_000;
        let f = NameFields::new(b"gift-two", &stranger, 0, start, start + period);
        let u = name_utxo(&f, 0xbc);
        let n = rec(f, &u);
        let plan = ops::extend(&env, &wallet, &n, &u, 1)?;
        ensure!(plan.built.tx.lock_time == 0);
        out.push(step_json("extend", &snap(&wallet), json!({ "name": name_json(&n, &u) }), json!({ "years": 1 }), &plan, tags)?);
    }

    // accept another buyer's offer (made to the deployer: the seller signs)
    {
        let f = NameFields::new(b"wanted", &me, 0, wall - period, wall + period);
        let u = name_utxo(&f, 0xb5);
        let n = rec(f.clone(), &u);
        let of = OfferFields { key: f.key, buyer: stranger, seller: me, refund_after: (block.daa + 50_000) as i64 };
        let ou = synthetic(0xb6, 0, 9 * SOMPI, env.kit.offer.spk(&of.encode()), block.daa - 1_000, None);
        let o = OfferRec { outpoint: ou.outpoint, fields: of.clone(), value: 9 * SOMPI, name: Some("wanted".into()) };
        let plan = ops::accept_offer(&env, &n, &u, &o, &ou)?;
        out.push(step_json("acceptOffer", &snap(&[]), json!({ "name": name_json(&n, &u), "offer": offer_json(&o, &ou) }), json!({}), &plan, tags)?);
        // an offer made to an earlier owner is refused by the builder
        let of2 = OfferFields { seller: stranger, ..of };
        let o2 = OfferRec { outpoint: ou.outpoint, fields: of2, value: 9 * SOMPI, name: Some("wanted".into()) };
        let ou2 = synthetic(0xb6, 0, 9 * SOMPI, env.kit.offer.spk(&o2.fields.encode()), block.daa - 1_000, None);
        ensure!(ops::accept_offer(&env, &n, &u, &o2, &ou2).is_err(), "an offer to an earlier owner must be refused");
    }

    // decline an offer made to the deployer
    {
        let of = OfferFields { key: name_key(b"wanted"), buyer: stranger, seller: me, refund_after: (block.daa + 50_000) as i64 };
        let ou = synthetic(0xb8, 0, 6 * SOMPI, env.kit.offer.spk(&of.encode()), block.daa - 1_000, None);
        let o = OfferRec { outpoint: ou.outpoint, fields: of, value: 6 * SOMPI, name: Some("wanted".into()) };
        let plan = ops::decline_offer(&env, &o, &ou)?;
        ensure!(plan.built.tx.inputs.len() == 1 && plan.built.tx.outputs.len() == 1);
        out.push(step_json("declineOffer", &snap(&[]), json!({ "offer": offer_json(&o, &ou) }), json!({}), &plan, tags)?);
    }

    // anyone reclaims another owner's lapsed name (expired 45 minutes ago, 15 past its
    // 30-minute grace); the caller keeps the bounty
    {
        let expired = wall - 45 * 60_000;
        ensure!(expired + p.grace_ms < block.time_ms as i64, "the lapsed name must be past expiresAt + grace at the median time");
        let f = NameFields::new(b"lapsed", &stranger, 0, expired - period, expired);
        let key = f.key;
        let u = name_utxo(&f, 0xb7);
        let n = rec(f, &u);
        let below = GapRec { outpoint: TransactionOutpoint::new(TransactionId::from_bytes([0xa7; 32]), 0), lo: ZERO32, hi: key, value: p.gap_value };
        let above = GapRec { outpoint: TransactionOutpoint::new(TransactionId::from_bytes([0xa8; 32]), 1), lo: key, hi: FF32, value: p.gap_value };
        let bu = synthetic(0xa7, 0, p.gap_value, env.kit.gap.spk(&gap_state(&below.lo, &below.hi)), block.daa - 900, id);
        let au = synthetic(0xa8, 1, p.gap_value, env.kit.gap.spk(&gap_state(&above.lo, &above.hi)), block.daa - 900, id);
        let x = ExitParts { below: &below, below_utxo: &bu, name: &n, name_utxo: &u, above: &above, above_utxo: &au };
        let plan = ops::reclaim(&env, x)?;
        out.push(step_json(
            "reclaim",
            &snap(&[]),
            json!({ "below": gap_json(&below, &bu), "name": name_json(&n, &u), "above": gap_json(&above, &au) }),
            json!({}),
            &plan,
            tags,
        )?);
    }

    // spend an unused commit back to its owner (the name was taken meanwhile)
    {
        let name = "taken-meanwhile";
        let salt = [0x34; 32];
        let cu = synthetic(0xc3, 0, ops::COMMIT_VALUE, pay_to_script_hash_script(&commit_redeem(&commitment(name.as_bytes(), &me, &salt), &me)), block.daa - 2_000, None);
        let c = CommitRec { name: name.into(), owner: me, salt, value: ops::COMMIT_VALUE, outpoint: Some(cu.outpoint), used_by: None, created_ms: 0 };
        let plan = ops::cancel_commit(&env, &c, &cu)?;
        ensure!(plan.built.tx.outputs.len() == 1 && plan.built.tx.outputs[0].value >= ops::CANCEL_FLOOR);
        out.push(step_json("cancelCommit", &snap(&[]), json!({ "commit": commit_json(&c, &cu) }), json!({}), &plan, tags)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// codecs
// ---------------------------------------------------------------------------

fn builder() -> ScriptBuilder {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
}

fn codecs(t: &Templates, registry_id: kaspa_hashes::Hash) -> Result<Value> {
    let kit = t.kit(registry_id)?;
    let names = ["a", "x", "z9", "abc", "four", "alice", "alpha-tn", "bravo-tn", "lapse-tn", "a-b", "0", "kachat", "abcdefghijklmnopqrstuvwxyz-01234"];
    let owner = xonly(&keypair(77));
    let name_keys: Vec<Value> = names
        .iter()
        .map(|n| json!({ "name": n, "key": hex(&name_key(n.as_bytes())), "padded": hex(&pad_name(n.as_bytes())) }))
        .collect();
    let commits: Vec<Value> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let salt = [i as u8 * 17 + 3; 32];
            let c = commitment(n.as_bytes(), &owner, &salt);
            let redeem = commit_redeem(&c, &owner);
            json!({
                "name": n, "owner": hex(&owner), "salt": hex(&salt), "commitment": hex(&c),
                "redeem": hex(&redeem), "spk": hex(pay_to_script_hash_script(&redeem).script()),
            })
        })
        .collect();
    let blake3: Vec<Value> = [0usize, 1, 31, 32, 63, 64, 65, 1023, 1024, 1025, 2002, 3965, 5000]
        .iter()
        .map(|&n| {
            let input: Vec<u8> = (0..n).map(|i| (i * 7 % 256) as u8).collect();
            json!({ "len": n, "hash": hex(blake3::hash(&input).as_bytes()) })
        })
        .collect();
    let ints = [0i64, 1, 16, 17, -1, -2, 127, 128, 255, 256, 32767, 32768, -128, 600, 3_500_000_000, 50 * SOMPI as i64, 1_790_000_000_000, YEAR_MS, i64::MAX, -i64::MAX];
    let num8s: Vec<Value> = ints.iter().map(|&v| json!({ "value": v.to_string(), "num8": hex(&num8(v)) })).collect();
    let mut script_nums = vec![];
    for &v in &ints {
        script_nums.push(json!({ "value": v.to_string(), "push": hex(&builder().add_i64(v)?.drain()) }));
    }
    let mut pushes = vec![];
    for data in [vec![], vec![0u8], vec![1], vec![16], vec![17], vec![0x81], vec![0x80], vec![7; 75], vec![7; 76], vec![7; 255], vec![7; 256], vec![9; 1884], vec![9; 3965]] {
        pushes.push(json!({ "data": hex(&data), "push": hex(&push(&data)) }));
    }
    let gap_s = gap_state(&ZERO32, &FF32);
    let nf = NameFields::new(b"alice", &owner, 5 * SOMPI as i64, NOW_MS, NOW_MS + YEAR_MS);
    let seller = xonly(&keypair(5));
    let of = OfferFields { key: name_key(b"alice"), buyer: owner, seller, refund_after: 600_100_000 };
    let states = json!({
        "gap": { "lo": hex(&ZERO32), "hi": hex(&FF32), "state": hex(&gap_s), "spk": hex(kit.gap.spk(&gap_s).script()) },
        "name": {
            "name": "alice", "owner": hex(&owner), "price": nf.price, "periodStart": nf.period_start, "expiresAt": nf.expires_at,
            "layout": "0x20 key 0x20 name 0x20 owner 0x08 price 0x08 periodStart 0x08 expiresAt (126 bytes)",
            "state": hex(&name_state(&nf.key, &nf.name, &nf.owner, nf.price, nf.period_start, nf.expires_at)),
            "spk": hex(kit.name.spk(&nf.encode()).script()),
        },
        "offer": {
            "key": hex(&of.key), "buyer": hex(&of.buyer), "seller": hex(&of.seller), "refundAfter": of.refund_after,
            "layout": "0x20 key 0x20 buyer 0x20 seller 0x08 refundAfter (108 bytes)",
            "state": hex(&offer_state(&of.key, &of.buyer, &of.seller, of.refund_after)),
            "spk": hex(kit.offer.spk(&of.encode()).script()),
        },
    });
    // covenant ids
    let mut covs = vec![];
    for (tag, idx, value) in [(0x11u8, 0u32, SOMPI), (0x5e, 3, 42), (0xff, 7, 300 * SOMPI)] {
        let op = TransactionOutpoint::new(TransactionId::from_bytes([tag; 32]), idx);
        let o = TransactionOutput::new(value, kit.gap.spk(&gap_s));
        let o2 = TransactionOutput::new(value + 1, p2pk_spk(&owner));
        covs.push(json!({
            "outpoint": { "txid": hex(&op.transaction_id.as_bytes()), "index": idx },
            "outputs": [
                { "index": 0, "value": o.value, "scriptVersion": 0, "script": hex(o.script_public_key.script()) },
                { "index": 2, "value": o2.value, "scriptVersion": 0, "script": hex(o2.script_public_key.script()) },
            ],
            "covenantId": hex(&covenant_id(op, [(0u32, &o), (2u32, &o2)].into_iter()).as_bytes()),
            "covenantIdFirstOnly": hex(&covenant_id(op, [(0u32, &o)].into_iter()).as_bytes()),
        }));
    }
    Ok(json!({
        "nameKeys": name_keys,
        "commitments": commits,
        "blake3": blake3,
        "blake3InputRule": "input[i] = (i * 7) % 256",
        "num8": num8s,
        "scriptNumbers": script_nums,
        "pushes": pushes,
        "states": states,
        "covenantIds": covs,
        "p2pk": { "xonly": hex(&owner), "spk": hex(p2pk_spk(&owner).script()), "address": p2pk_address(&owner).to_string() },
    }))
}

// ---------------------------------------------------------------------------
// check: validate port-built transactions (fixed budgets)
// ---------------------------------------------------------------------------

fn h32(v: &Value) -> Result<kaspa_hashes::Hash> {
    let b = faster_hex_decode(v.as_str().ok_or_else(|| anyhow!("expected hex"))?)?;
    Ok(kaspa_hashes::Hash::from_bytes(b.try_into().map_err(|_| anyhow!("expected 32 bytes"))?))
}

fn faster_hex_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).map_err(|e| anyhow!("{s}: {e}"))?;
    Ok(out)
}

fn u(v: &Value) -> Result<u64> {
    v.as_u64().ok_or_else(|| anyhow!("expected an unsigned number"))
}

fn check(file: &std::path::Path) -> Result<()> {
    use kachat_names_harness::{Built, Kit};
    use kaspa_consensus_core::{
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{CovenantBinding, TransactionInput},
    };
    let paths = Paths::find(None)?;
    let v: Value = serde_json::from_str(&std::fs::read_to_string(file)?)?;
    let registry_id = h32(&v["registryCovenantId"])?;
    let kit: Kit = Templates::load(&paths.root).kit(registry_id)?;
    let signer = keypair(77);
    ensure!(hex(&xonly(&signer)) == v["signer"].as_str().unwrap_or(""), "the port signed for another key than the vectors' deployer");
    let placeholder: Vec<u8> = [&[0x41u8][..], &[0u8; 64], &[0x01]].concat();
    let mut ok = 0;
    let txs = v["transactions"].as_array().ok_or_else(|| anyhow!("no transactions"))?;
    for t in txs {
        let label = t["label"].as_str().unwrap_or("?");
        let mut inputs = vec![];
        let mut entries = vec![];
        for i in t["inputs"].as_array().unwrap() {
            let op = TransactionOutpoint::new(h32(&i["txid"])?, u(&i["index"])? as u32);
            inputs.push(TransactionInput::new_with_compute_budget(
                op,
                faster_hex_decode(i["signatureScript"].as_str().unwrap())?,
                u(&i["sequence"])?,
                u(&i["computeBudget"])? as u16,
            ));
            let e = &i["entry"];
            let cov = if e["covenantId"].is_null() { None } else { Some(h32(&e["covenantId"])?) };
            entries.push(UtxoEntry::new(
                u(&e["amount"])?,
                ScriptPublicKey::from_vec(u(&e["scriptVersion"])? as u16, faster_hex_decode(e["script"].as_str().unwrap())?),
                u(&e["blockDaaScore"])?,
                e["isCoinbase"].as_bool().unwrap_or(false),
                cov,
            ));
        }
        let mut outputs = vec![];
        for o in t["outputs"].as_array().unwrap() {
            let spk = ScriptPublicKey::from_vec(u(&o["scriptVersion"])? as u16, faster_hex_decode(o["script"].as_str().unwrap())?);
            let cov = if o["covenant"].is_null() {
                None
            } else {
                Some(CovenantBinding { authorizing_input: u(&o["covenant"]["authorizingInput"])? as u16, covenant_id: h32(&o["covenant"]["covenantId"])? })
            };
            outputs.push(TransactionOutput::with_covenant(u(&o["value"])?, spk, cov));
        }
        let mut tx = Transaction::new(
            u(&t["version"])? as u16,
            inputs,
            outputs,
            u(&t["lockTime"])?,
            SUBNETWORK_ID_NATIVE,
            0,
            faster_hex_decode(t["payload"].as_str().unwrap())?,
        );
        tx.set_storage_mass(u(&t["storageMass"])?);
        // the port's storage-mass commitment must be the consensus one
        let mc = kaspa_consensus_core::mass::MassCalculator::new_with_consensus_params(&kit.consensus);
        let populated = kaspa_consensus_core::tx::PopulatedTransaction::new(&tx, entries.clone());
        let storage = mc.calc_contextual_masses(&populated).map(|m| m.storage_mass);
        ensure!(storage == Some(tx.storage_mass()), "{label}: storage mass {} != consensus {:?}", tx.storage_mass(), storage);
        // sign every placeholder over the real sighash
        let mtx = MutableTransaction::with_entries(tx.clone(), entries.clone());
        for i in 0..tx.inputs.len() {
            let script = tx.inputs[i].signature_script.clone();
            let Some(at) = script.windows(placeholder.len()).position(|w| w == placeholder.as_slice()) else { continue };
            let reused = SigHashReusedValuesUnsync::new();
            let h = calc_schnorr_signature_hash(&mtx.as_verifiable(), i, SIG_HASH_ALL, &reused);
            let msg = secp256k1::Message::from_digest_slice(h.as_bytes().as_slice())?;
            let sig = signer.sign_schnorr(msg);
            let mut s2 = script.clone();
            s2[at + 1..at + 65].copy_from_slice(sig.as_ref());
            tx.inputs[i].signature_script = s2;
        }
        tx.finalize();
        ensure!(hex(&tx.id().as_bytes()) == t["txid"].as_str().unwrap_or(""), "{label}: txid differs from the port's");
        let built = Built { tx, entries, budgets: vec![], used_units: vec![] };
        let block = Block { daa: u(&t["blockDaa"])?, time_ms: u(&t["blockTimeMs"])? };
        let fee = kit.validate(&built, block).map_err(|e| anyhow!("{label}: rejected: {e}"))?;
        for (i, r) in built.run_inputs().into_iter().enumerate() {
            r.map_err(|e| anyhow!("{label}: input {i} fails under its committed budget: {e:?}"))?;
        }
        for (i, input) in built.tx.inputs.iter().enumerate() {
            let n = kaspa_txscript::post_toccata_p2sh_sig_scanner(&input.signature_script, &built.entries[i].script_public_key);
            ensure!(n <= 15, "{label}: input {i} scans {n} sig ops");
        }
        for (i, o) in built.tx.outputs.iter().enumerate() {
            ensure!(
                kaspa_txscript::script_class::ScriptClass::from_script(&o.script_public_key) != kaspa_txscript::script_class::ScriptClass::NonStandard,
                "{label}: output {i} non-standard"
            );
        }
        let costs = kit.costs(&built);
        let network = u(&t["networkFee"])?;
        let price = u(&t["priceFee"])?;
        ensure!(fee == price + network, "{label}: fee {fee} != price {price} + network {network}");
        ensure!(network >= costs.min_fee, "{label}: network fee {network} below the relay floor {}", costs.min_fee);
        ensure!(costs.compute_mass == u(&t["computeMass"])?, "{label}: compute mass differs");
        println!("valid  {label}  (fee {fee}, budgets {:?})", built.tx.inputs.iter().map(|i| i.compute_commit.compute_budget().unwrap_or(0)).collect::<Vec<_>>());
        ok += 1;
    }
    println!("{ok}/{} port-built transactions valid", txs.len());
    Ok(())
}
