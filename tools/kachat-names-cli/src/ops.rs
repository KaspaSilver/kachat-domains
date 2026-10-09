//! Transaction builders: one per operation, each producing exactly the shape
//! in the README's "Transaction shapes" table, built and signed by the
//! harness kit (budgets measured in the engine, SIGHASH_ALL) and validated by
//! rusty-kaspa's consensus `TransactionValidator` at a given block point.
//!
//! Builders are pure: they take decoded registry records with their live
//! UTXOs, the deployer's spendable P2PK UTXOs and a validation point, and
//! never touch the network. The CLI feeds them node data; tests feed them
//! synthetic UTXOs.

use std::path::Path;

use anyhow::{Result, anyhow, bail, ensure};
use kachat_names_harness::{
    Arg, ArtifactValue, Block, Built, Costs, Input, Kit, NameFields, NetParams, OfferFields, Template, TransactionOutput, TxSpec, Unlock, Utxo, bytes,
    commit_redeem, commitment, compile_gap_in, compile_name_in, compile_offer_in, gap_state, genesis_spec, int, name_key, p2pk_spk, xonly,
};
use kaspa_consensus_core::{
    constants::LOCK_TIME_THRESHOLD,
    tx::{ScriptPublicKey, TransactionOutpoint},
};
use kaspa_hashes::Hash;
use kaspa_txscript::{pay_to_script_hash_script, script_class::ScriptClass};
use secp256k1::Keypair;

use crate::{
    commits::CommitRec,
    net::{consensus_params, net, p2pk_address, spk_address},
    registry::{GapRec, NameRec, OfferRec},
    util::{SOMPI, fmt_dur, fmt_kas, fmt_ms, hex},
};

/// Value of a commit UTXO (returned at registration).
pub const COMMIT_VALUE: u64 = 20_000_000;
/// Change below this is not worth a UTXO (its KIP-9 storage mass alone
/// would outweigh it); the builders aim for at least `TARGET_CHANGE`.
pub const MIN_CHANGE: u64 = 20_000_000;
pub const TARGET_CHANGE: u64 = SOMPI;
/// Relay floor at rusty-kaspa a41a333 (post-Toccata): 100 sompi per gram of
/// max(compute, normalized transient) mass.
pub const MIN_FEERATE: f64 = 100.0;
/// register, extend and renew sum at most 8 inputs and 8 outputs (bounded loops).
pub const MAX_IO_FEE_ENTRY: usize = 8;
/// Every other operation: keep transactions small anyway.
pub const MAX_INPUTS: usize = 24;

// ---------------------------------------------------------------------------
// environment
// ---------------------------------------------------------------------------

/// Templates of the pinned build (artifacts/testnet10) and the params. Registry v4
/// bakes both price tables into the name and the gap, so they are compiled here from
/// the params (the prices the builders charge are then exactly the baked ones) and must
/// be byte-identical with the artifacts scripts/build.sh wrote. The offer bakes the
/// registry id, so it is compiled for a given id (and checked against its artifact once
/// scripts/build.sh has built it for that id).
pub struct Templates {
    pub params: NetParams,
    pub root: std::path::PathBuf,
}

fn params_registry_id(root: &Path) -> Option<String> {
    std::fs::read_to_string(root.join("params").join(format!("{}.json", net().params_file)))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v["registryCovenantId"].as_str().map(str::to_owned))
}

impl Templates {
    pub fn load(root: &Path) -> Templates {
        Templates { params: NetParams::load_in(root, net().params_file), root: root.to_path_buf() }
    }

    /// When the artifact exists, the in-process compile must equal it.
    fn check_artifact(&self, contract: &str, t: &Template, built_for: &str) -> Result<()> {
        let path = self.root.join("artifacts").join(net().params_file).join(format!("{contract}.json"));
        if path.exists() {
            let art = Template::load_in(&self.root, net().params_file, contract);
            ensure!(art.bytecode == t.bytecode, "artifacts/{}/{contract}.json was built for {built_for}: run ./scripts/build.sh", net().params_file);
        }
        Ok(())
    }

    /// The name and gap, with the params' register and renew tables baked in.
    pub fn name_gap(&self) -> Result<(Template, Template)> {
        let name = compile_name_in(&self.root, &self.params);
        let gap = compile_gap_in(&self.root, &self.params, &name);
        self.check_artifact("KachatName", &name, "other params or sources")?;
        self.check_artifact("KachatGap", &gap, "other params or sources")?;
        Ok((name, gap))
    }

    /// The kit for the registry `registry_id`.
    pub fn kit(&self, registry_id: Hash) -> Result<Kit> {
        let (name, gap) = self.name_gap()?;
        let offer = compile_offer_in(&self.root, &self.params, &name, registry_id);
        // the offer artifact is built for the registry id params carry (other ids: tests, dry runs)
        if params_registry_id(&self.root).as_deref() == Some(registry_id.to_string().as_str()) {
            self.check_artifact("KachatOffer", &offer, &format!("another registry id than {registry_id}"))?;
        }
        Ok(Kit::with_registry(self.params.clone(), name, gap, offer, registry_id, consensus_params()))
    }
}

/// Where and how a transaction is built and checked.
pub struct Env {
    pub kit: Kit,
    pub deployer: Keypair,
    /// validation point: the virtual's DAA score and past median time
    pub block: Block,
    /// wall clock, unix ms
    pub wall_ms: i64,
    /// sompi per gram (the node's estimate; never below MIN_FEERATE)
    pub feerate: f64,
}

impl Env {
    pub fn me(&self) -> [u8; 32] {
        xonly(&self.deployer)
    }
    fn my_spk(&self) -> ScriptPublicKey {
        p2pk_spk(&self.me())
    }
}

// ---------------------------------------------------------------------------
// the result
// ---------------------------------------------------------------------------

pub struct Plan {
    pub op: String,
    pub built: Built,
    pub costs: Costs,
    pub lock_time: u64,
    pub input_labels: Vec<String>,
    pub output_labels: Vec<String>,
    /// price paid as miner fee (register / extend / renew: the baked tables)
    pub price_fee: u64,
    pub network_fee: u64,
    /// local consensus validation at `block`: Ok(fee) or the rejection
    pub validation: Result<u64, String>,
    /// mempool standardness checks the harness can reproduce
    pub standard: Result<(), String>,
    pub block: Block,
    pub notes: Vec<String>,
    /// set by `commit`: the record to store once submitted
    pub new_commit: Option<CommitRec>,
    /// set by `offer`: the offer to track once submitted
    pub new_offer: Option<OfferRec>,
    /// set by `genesis`
    pub registry_id: Option<Hash>,
}

impl Plan {
    pub fn is_valid(&self) -> bool {
        self.validation.is_ok() && self.standard.is_ok()
    }
    pub fn txid(&self) -> kaspa_consensus_core::tx::TransactionId {
        self.built.tx.id()
    }
}

// ---------------------------------------------------------------------------
// shared assembly
// ---------------------------------------------------------------------------

enum Fee {
    /// add deployer funding inputs and a change output to the deployer
    Funded { max_inputs: usize },
    /// no funding: take the network fee out of output `idx`, which must keep
    /// at least `floor` (`MIN_CHANGE` everywhere but a cancelled commit)
    FromOutput { idx: usize, cap: Option<u64>, floor: u64 },
}

struct Draft {
    op: String,
    inputs: Vec<(Input, String)>,
    outputs: Vec<(TransactionOutput, String)>,
    lock_time: u64,
    price_fee: u64,
    notes: Vec<String>,
}

fn standardness(built: &Built) -> Result<(), String> {
    for (i, input) in built.tx.inputs.iter().enumerate() {
        let n = kaspa_txscript::post_toccata_p2sh_sig_scanner(&input.signature_script, &built.entries[i].script_public_key);
        if n > 15 {
            return Err(format!("input {i} scans {n} sig ops (> 15, non-standard)"));
        }
    }
    for (i, o) in built.tx.outputs.iter().enumerate() {
        if ScriptClass::from_script(&o.script_public_key) == ScriptClass::NonStandard {
            return Err(format!("output {i} is a non-standard script"));
        }
    }
    Ok(())
}

fn network_fee(env: &Env, c: &Costs) -> u64 {
    let fee_mass = c.compute_mass.max(c.normalized_transient);
    let rate = env.feerate.max(MIN_FEERATE);
    ((fee_mass as f64) * rate).ceil() as u64
}

/// Pick deployer UTXOs (largest first, skipping `used`) worth at least
/// `target`, at most `slots` of them. Returns what it found even if short.
fn select(wallet: &[Utxo], used: &[TransactionOutpoint], target: u64, slots: usize) -> Vec<Utxo> {
    let mut pool: Vec<&Utxo> = wallet.iter().filter(|u| !used.contains(&u.outpoint)).collect();
    pool.sort_by(|a, b| b.entry.amount.cmp(&a.entry.amount).then(a.outpoint.index.cmp(&b.outpoint.index)));
    let mut out = vec![];
    let mut sum = 0u64;
    for u in pool {
        if sum >= target || out.len() >= slots {
            break;
        }
        sum += u.entry.amount;
        out.push(u.clone());
    }
    out
}

fn finish(env: &Env, wallet: &[Utxo], mut d: Draft, payload: Vec<u8>, fee: Fee) -> Result<Plan> {
    let me = env.deployer;
    let spec_of = |inputs: &[(Input, String)], outputs: &[(TransactionOutput, String)]| TxSpec {
        inputs: inputs.iter().map(|(i, _)| i.clone()).collect(),
        outputs: outputs.iter().map(|(o, _)| o.clone()).collect(),
        lock_time: d.lock_time,
    };
    let (spec, network) = match fee {
        Fee::Funded { max_inputs } => {
            let fixed_in: u64 = d.inputs.iter().map(|(i, _)| i.utxo.entry.amount).sum();
            let fixed_out: u64 = d.outputs.iter().map(|(o, _)| o.value).sum();
            let used: Vec<TransactionOutpoint> = d.inputs.iter().map(|(i, _)| i.utxo.outpoint).collect();
            let slots = max_inputs.saturating_sub(d.inputs.len());
            let mut est = 0u64;
            let mut last = None;
            for _round in 0..5 {
                let need = (fixed_out + d.price_fee + est).saturating_sub(fixed_in);
                let mut picked = select(wallet, &used, need + TARGET_CHANGE, slots);
                let have: u64 = picked.iter().map(|u| u.entry.amount).sum();
                if have < need + MIN_CHANGE && need > 0 {
                    picked = select(wallet, &used, need + MIN_CHANGE, slots);
                }
                let have: u64 = picked.iter().map(|u| u.entry.amount).sum();
                if fixed_in + have < fixed_out + d.price_fee + est {
                    let all: u64 = wallet.iter().filter(|u| !used.contains(&u.outpoint)).map(|u| u.entry.amount).sum();
                    bail!(
                        "{}: insufficient funds: need {} more (outputs {} + price {} + network fee ~{}), the deployer has {} spendable{}",
                        d.op,
                        fmt_kas(fixed_out + d.price_fee + est - fixed_in),
                        fmt_kas(fixed_out),
                        fmt_kas(d.price_fee),
                        fmt_kas(est),
                        fmt_kas(all),
                        if slots < wallet.len() { format!(" (at most {slots} funding inputs fit)") } else { String::new() }
                    );
                }
                let mut inputs = d.inputs.clone();
                for u in &picked {
                    inputs.push((Input::new(u.clone(), Unlock::P2pk(me)), "funding (deployer P2PK)".to_string()));
                }
                let total_in = fixed_in + have;
                let change = total_in - fixed_out - d.price_fee - est;
                let mut outputs = d.outputs.clone();
                let with_change = change >= MIN_CHANGE;
                if with_change {
                    outputs.push((TransactionOutput::new(change, env.my_spk()), "change (deployer)".to_string()));
                }
                let spec = spec_of(&inputs, &outputs);
                let built = env.kit.build_with_payload(&spec, &payload);
                let fee_now = network_fee(env, &env.kit.costs(&built));
                if fee_now <= est {
                    if !with_change && change > 0 {
                        d.notes.push(format!("no change output: the {} left over goes to the miner", fmt_kas(change)));
                    }
                    last = Some((inputs, outputs, change, with_change));
                    break;
                }
                est = fee_now;
            }
            let (inputs, outputs, change, with_change) = last.ok_or_else(|| anyhow!("{}: fee did not converge", d.op))?;
            d.inputs = inputs;
            d.outputs = outputs;
            let network = if with_change { est } else { est + change };
            (spec_of(&d.inputs, &d.outputs), network)
        }
        Fee::FromOutput { idx, cap, floor } => {
            // provisional value (zero would break the KIP-9 storage-mass formula)
            let total_in: u64 = d.inputs.iter().map(|(i, _)| i.utxo.entry.amount).sum();
            let others: u64 = d.outputs.iter().enumerate().filter(|(j, _)| *j != idx).map(|(_, (o, _))| o.value).sum();
            d.outputs[idx].0.value = total_in.saturating_sub(others + d.price_fee).max(1);
            let spec = spec_of(&d.inputs, &d.outputs);
            let built = env.kit.build_with_payload(&spec, &payload);
            let fee = network_fee(env, &env.kit.costs(&built));
            if let Some(cap) = cap {
                ensure!(fee <= cap, "{}: network fee {} exceeds the contract's maxFee {}", d.op, fmt_kas(fee), fmt_kas(cap));
            }
            let v = total_in
                .checked_sub(others + d.price_fee + fee)
                .ok_or_else(|| anyhow!("{}: inputs do not cover the outputs and the fee", d.op))?;
            ensure!(v >= floor, "{}: output {idx} would be only {}", d.op, fmt_kas(v));
            d.outputs[idx].0.value = v;
            (spec_of(&d.inputs, &d.outputs), fee)
        }
    };
    ensure!(spec.inputs.len() <= 255 && spec.outputs.len() <= 255, "too many inputs/outputs");
    let built = env.kit.build_with_payload(&spec, &payload);
    let costs = env.kit.costs(&built);
    let validation = env.kit.validate(&built, env.block);
    if let Ok(fee) = &validation {
        debug_assert_eq!(*fee, d.price_fee + network);
    }
    let standard = standardness(&built);
    Ok(Plan {
        op: d.op,
        lock_time: spec.lock_time,
        built,
        costs,
        input_labels: d.inputs.into_iter().map(|(_, l)| l).collect(),
        output_labels: d.outputs.into_iter().map(|(_, l)| l).collect(),
        price_fee: d.price_fee,
        network_fee: network,
        validation,
        standard,
        block: env.block,
        notes: d.notes,
        new_commit: None,
        new_offer: None,
        registry_id: None,
    })
}

// ---------------------------------------------------------------------------
// payload markers (KACHAT_NAMES_INDEXER.md B4): informational for name
// transactions, the discovery hint for offers. Commits carry none (the name
// must stay hidden until it is registered). The contracts never read them.
// ---------------------------------------------------------------------------

pub fn name_payload(op: &str, name: &str) -> Vec<u8> {
    format!("kchat:1:name:{op}:{name}").into_bytes()
}

/// `kchat:1:offer:<keyHex>:<buyerXonlyHex>:<sellerXonlyHex>:<refundAfterDaa>` (since registry v3)
pub fn offer_payload(f: &OfferFields) -> Vec<u8> {
    format!("kchat:1:offer:{}:{}:{}:{}", hex(&f.key), hex(&f.buyer), hex(&f.seller), f.refund_after).into_bytes()
}

// ---------------------------------------------------------------------------
// names
// ---------------------------------------------------------------------------

/// The gap's name rule: a-z 0-9 '-', 1..32 bytes, no hyphen at either end.
pub fn check_name(name: &str) -> Result<()> {
    let b = name.as_bytes();
    ensure!(!b.is_empty() && b.len() <= 32, "a name is 1..32 characters");
    ensure!(b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-'), "a name is a-z, 0-9 and '-' only");
    ensure!(b[0] != b'-' && b[b.len() - 1] != b'-', "a name cannot start or end with '-'");
    Ok(())
}

fn label_gap(lo: &[u8; 32], hi: &[u8; 32]) -> String {
    format!("gap ({}.., {}..)", hex(&lo[..4]), hex(&hi[..4]))
}

fn name_input(env: &Env, n: &NameRec, utxo: &Utxo, entry: &str, args: Vec<Arg>) -> Input {
    Input::contract(utxo.clone(), &env.kit.name, n.fields.encode(), entry, args)
}

fn gap_input(env: &Env, g: &GapRec, utxo: &Utxo, entry: &str, args: Vec<Arg>) -> Input {
    Input::contract(utxo.clone(), &env.kit.gap, gap_state(&g.lo, &g.hi), entry, args)
}

fn check_live(label: &str, utxo: &Utxo, value: u64, registry: Option<Hash>) -> Result<()> {
    ensure!(utxo.entry.amount == value, "{label}: live UTXO holds {} not {}", fmt_kas(utxo.entry.amount), fmt_kas(value));
    ensure!(utxo.entry.covenant_id == registry, "{label}: live UTXO covenant id {:?}, expected {:?}", utxo.entry.covenant_id, registry);
    Ok(())
}

fn require_owner(env: &Env, n: &NameRec) -> Result<()> {
    ensure!(
        n.fields.owner == env.me(),
        "{} is owned by {}, not by the deployer {}",
        n.name(),
        p2pk_address(&n.fields.owner),
        p2pk_address(&env.me())
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// genesis
// ---------------------------------------------------------------------------

/// The registry genesis (registry v4 has no other): spend one deployer UTXO (the
/// smallest that covers the gap and a change, else the largest); output 0 is the lone
/// genesis gap (00..00, ff..ff) bound to covenant_id(that outpoint, [(0, gap)]);
/// output 1 is change. Nothing else is authorized.
pub fn genesis(t: &Templates, deployer: Keypair, wallet: &[Utxo], block: Block, wall_ms: i64, feerate: f64) -> Result<(Plan, Kit)> {
    let p = &t.params;
    let (_, gap) = t.name_gap()?;
    let me = xonly(&deployer);
    let need = p.gap_value + TARGET_CHANGE;
    let funding = wallet
        .iter()
        .filter(|u| u.entry.amount >= need)
        .min_by_key(|u| u.entry.amount)
        .or_else(|| wallet.iter().max_by_key(|u| u.entry.amount))
        .cloned()
        .ok_or_else(|| anyhow!("genesis: the deployer has no UTXO; fund {} first", p2pk_address(&me)))?;
    ensure!(funding.entry.amount >= p.gap_value + MIN_CHANGE, "genesis: the largest deployer UTXO is only {}", fmt_kas(funding.entry.amount));
    let change = TransactionOutput::new(funding.entry.amount - p.gap_value, p2pk_spk(&me));
    let (mut spec, registry_id) = genesis_spec(p, &gap, funding.clone(), deployer, vec![change]);
    let kit = t.kit(registry_id)?;
    let env = Env { kit, deployer, block, wall_ms, feerate };
    let fee = network_fee(&env, &env.kit.costs(&env.kit.build(&spec)));
    spec.outputs[1].value = funding.entry.amount - p.gap_value - fee;
    ensure!(spec.outputs[1].value >= MIN_CHANGE, "genesis: funding too small for the change");
    let d = Draft {
        op: "genesis".into(),
        inputs: vec![(spec.inputs[0].clone(), "funding (deployer P2PK) = the genesis outpoint".into())],
        outputs: vec![
            (spec.outputs[0].clone(), format!("genesis gap (00..00, ff..ff), registry id {registry_id}")),
            (spec.outputs[1].clone(), "change (deployer)".into()),
        ],
        lock_time: 0,
        price_fee: 0,
        notes: vec![
            format!("registry covenant id = covenant_id({}, [(0, gap)]) = {registry_id}", crate::util::fmt_outpoint(&funding.outpoint)),
            format!(
                "prices baked into the gap and the name (per {}, 1/2/3/4/5+ chars): register {}; renew {}",
                fmt_dur(p.period_ms),
                fmt_tiers(&p.register_prices),
                fmt_tiers(&p.renew_prices)
            ),
        ],
    };
    let mut plan = finish(&env, &[], d, vec![], Fee::FromOutput { idx: 1, cap: None, floor: MIN_CHANGE })?;
    plan.registry_id = Some(registry_id);
    ensure!(plan.built.tx.outputs.iter().filter(|o| o.covenant.is_some()).count() == 1, "genesis authorizes exactly one output");
    Ok((plan, env.kit))
}

/// A price table for humans: the five tiers (1, 2, 3, 4, 5+ chars) joined by " / ".
pub fn fmt_tiers(prices: &[u64; 5]) -> String {
    prices.iter().map(|x| fmt_kas(*x)).collect::<Vec<_>>().join(" / ")
}

// ---------------------------------------------------------------------------
// commit / register
// ---------------------------------------------------------------------------

pub fn commit(env: &Env, wallet: &[Utxo], name: &str, salt: [u8; 32]) -> Result<Plan> {
    check_name(name)?;
    let me = env.me();
    let c = commitment(name.as_bytes(), &me, &salt);
    let redeem = commit_redeem(&c, &me);
    let out = TransactionOutput::new(COMMIT_VALUE, pay_to_script_hash_script(&redeem));
    let addr = spk_address(&out.script_public_key)?;
    let d = Draft {
        op: format!("commit {name}"),
        inputs: vec![],
        outputs: vec![(out, format!("commit P2SH {addr} (hides name + owner + salt)"))],
        lock_time: 0,
        price_fee: 0,
        notes: vec![format!(
            "commitment = blake3(\"kachat-commit:v1\" || name || owner || salt) = {}; the salt stays in .secrets/commits.json",
            hex(&c)
        )],
    };
    let mut plan = finish(env, wallet, d, vec![], Fee::Funded { max_inputs: MAX_INPUTS })?;
    plan.new_commit = Some(CommitRec {
        name: name.to_string(),
        owner: me,
        salt,
        value: COMMIT_VALUE,
        outpoint: Some(TransactionOutpoint::new(plan.txid(), 0)),
        used_by: None,
        created_ms: env.wall_ms,
    });
    Ok(plan)
}

/// The least a cancelled commit may return: one 0.2 KAS input and one output
/// just under it keep the KIP-9 storage mass small.
pub const CANCEL_FLOOR: u64 = 10_000_000;

/// Spend an unused commit back to its owner (the name was taken meanwhile, or
/// the owner changed their mind): [commit (owner sig + redeem)] -> [P2PK(owner),
/// the commit's value less the network fee]. No funding, no payload (the name
/// stays hidden), sequence 0, lock time 0.
pub fn cancel_commit(env: &Env, commit: &CommitRec, commit_utxo: &Utxo) -> Result<Plan> {
    let me = env.me();
    ensure!(commit.owner == me, "the commit for {} is for another owner", commit.name);
    let redeem = commit_redeem(&commitment(commit.name.as_bytes(), &me, &commit.salt), &me);
    ensure!(commit_utxo.entry.script_public_key == pay_to_script_hash_script(&redeem), "commit UTXO script does not match the stored salt");
    ensure!(commit_utxo.entry.covenant_id.is_none(), "a commit carries no covenant id");
    let d = Draft {
        op: format!("cancel commit {}", commit.name),
        inputs: vec![(
            Input::new(commit_utxo.clone(), Unlock::Commit { redeem, key: env.deployer }),
            format!("commit for {} (owner sig)", commit.name),
        )],
        outputs: vec![(TransactionOutput::new(0, env.my_spk()), "back to the owner".into())],
        lock_time: 0,
        price_fee: 0,
        notes: vec![],
    };
    finish(env, &[], d, vec![], Fee::FromOutput { idx: 0, cap: None, floor: CANCEL_FLOOR })
}

/// `now` for a registration: wall clock - 3 min (the block median time lags
/// the clock by ~2.2 min), and never at or past the virtual's median time.
pub fn register_now(env: &Env) -> i64 {
    (env.wall_ms - 180_000).min(env.block.time_ms as i64 - 1_000)
}

#[allow(clippy::too_many_arguments)]
pub fn register(
    env: &Env,
    wallet: &[Utxo],
    gap: &GapRec,
    gap_utxo: &Utxo,
    commit: &CommitRec,
    commit_utxo: &Utxo,
    years: i64,
    now: i64,
) -> Result<Plan> {
    let p = &env.kit.params;
    let name = commit.name.as_str();
    check_name(name)?;
    let me = env.me();
    ensure!(commit.owner == me, "the commit for {name} is for another owner");
    ensure!((1..=p.max_years).contains(&years), "years must be 1..{}", p.max_years);
    let key = name_key(name.as_bytes());
    ensure!(gap.lo < key && key < gap.hi, "{name} is not inside {}", label_gap(&gap.lo, &gap.hi));
    check_live("gap", gap_utxo, p.gap_value, Some(env.kit.registry_id))?;
    let redeem = commit_redeem(&commitment(name.as_bytes(), &me, &commit.salt), &me);
    ensure!(commit_utxo.entry.script_public_key == pay_to_script_hash_script(&redeem), "commit UTXO script does not match the stored salt");
    ensure!(now > 0 && (now as u64) >= LOCK_TIME_THRESHOLD, "now must be a unix-ms timestamp");

    // registry v4: the first period at the registration price, each further one at the
    // renewal price (both baked into the gap)
    let price = p.register_cost(name.len(), years);
    let expires = now + years * p.period_ms;
    let fields = NameFields::new(name.as_bytes(), &me, 0, now, expires);
    let mut commit_in = Input::new(commit_utxo.clone(), Unlock::Commit { redeem, key: env.deployer });
    commit_in.sequence = p.t_commit;
    let mut notes = vec![
        format!(
            "price {} = {} (first period) + {} x {} further period(s) of {}, left as miner fee",
            fmt_kas(price),
            fmt_kas(p.price_for(name.len())),
            fmt_kas(p.renew_price_for(name.len())),
            years - 1,
            fmt_dur(p.period_ms)
        ),
        format!("now = periodStart = {now} ({}), expiresAt = {expires} ({})", fmt_ms(now), fmt_ms(expires)),
    ];
    let mature_at = commit_utxo.entry.block_daa_score + p.t_commit;
    if env.block.daa < mature_at {
        notes.push(format!(
            "commit not mature yet: valid from DAA {mature_at} (now {}, ~{} s to go at 10 bps)",
            env.block.daa,
            (mature_at - env.block.daa).div_ceil(10)
        ));
    }
    if expires + p.grace_ms < env.wall_ms {
        notes.push("backdated: this name is already past expiresAt + grace (reclaimable at once)".into());
    } else if expires < env.wall_ms {
        notes.push("backdated: this name is already expired (in grace)".into());
    }
    let d = Draft {
        op: format!("register {name} ({years} period(s))"),
        inputs: vec![
            (
                gap_input(
                    env,
                    gap,
                    gap_utxo,
                    "register",
                    vec![
                        bytes(name.as_bytes()),
                        bytes(&me),
                        bytes(&commit.salt),
                        int(now),
                        int(years),
                        bytes(&env.kit.name.prefix),
                        bytes(&env.kit.name.suffix),
                    ],
                ),
                format!("{} register", label_gap(&gap.lo, &gap.hi)),
            ),
            (commit_in, format!("commit for {name} (sequence = tCommit {})", p.t_commit)),
        ],
        outputs: vec![
            (env.kit.gap_output(&gap.lo, &key, 0), label_gap(&gap.lo, &key)),
            (env.kit.gap_output(&key, &gap.hi, 0), label_gap(&key, &gap.hi)),
            (env.kit.name_output(&fields, 0), format!("name {name} (owner deployer, expires {})", fmt_ms(expires))),
        ],
        lock_time: now as u64,
        price_fee: price,
        notes,
    };
    finish(env, wallet, d, name_payload("register", name), Fee::Funded { max_inputs: MAX_IO_FEE_ENTRY })
}

// ---------------------------------------------------------------------------
// name entries
// ---------------------------------------------------------------------------

/// The most periods `extend` can add to a name now: its paid time (from
/// periodStart) may hold at most maxYears periods.
pub fn extendable_years(p: &NetParams, f: &NameFields) -> i64 {
    let room = f.period_start + p.max_years * p.period_ms - f.expires_at;
    if room < 0 { 0 } else { (room / p.period_ms).min(p.max_years) }
}

/// When `renew` becomes valid: expiresAt - renewWindowMs (unix ms). The
/// transaction is final once the block's past median time passes its lock
/// time, which must be at least this.
pub fn renew_opens(p: &NetParams, f: &NameFields) -> i64 {
    f.expires_at - p.renew_window_ms
}

/// The lock time of a renewal: max(registration-style now, window opening)
/// = max(min(wall - 3 min, median time - 1 s), expiresAt - renewWindowMs).
/// Final (and so valid) only while it is below the median time, i.e. once
/// the window is open.
pub fn renew_lock_time(env: &Env, f: &NameFields) -> i64 {
    register_now(env).max(renew_opens(&env.kit.params, f))
}

/// Is the renewal window open at the validation point (median time past
/// expiresAt - renewWindowMs)?
pub fn renew_window_open(env: &Env, f: &NameFields) -> bool {
    (env.block.time_ms as i64) > renew_opens(&env.kit.params, f)
}

/// Anyone extends the current period: [name.extend(years), funding] -> [continuation
/// (periodStart kept, expiresAt + years periods), change], years x the renewal price as
/// miner fee. No lock time.
pub fn extend(env: &Env, wallet: &[Utxo], n: &NameRec, utxo: &Utxo, years: i64) -> Result<Plan> {
    let p = &env.kit.params;
    ensure!((1..=p.max_years).contains(&years), "years must be 1..{}", p.max_years);
    check_live(&n.name(), utxo, p.bond, Some(env.kit.registry_id))?;
    let name = n.name();
    let f = &n.fields;
    let room = extendable_years(p, f);
    ensure!(
        years <= room,
        "extend {name} by {years} period(s) refused: it is paid until {} and its paid time (from {}) may hold at most {} periods, \
         so {} can be added now; renew opens on {} (expiresAt - {})",
        fmt_ms(f.expires_at),
        fmt_ms(f.period_start),
        p.max_years,
        room,
        fmt_ms(renew_opens(p, f)),
        fmt_dur(p.renew_window_ms)
    );
    let price = p.renew_price_for(name.len()) * years as u64;
    let nf = f.extended(years, p.period_ms);
    let d = Draft {
        op: format!("extend {name} ({years} period(s))"),
        inputs: vec![(name_input(env, n, utxo, "extend", vec![int(years)]), format!("name {name} extend({years})"))],
        outputs: vec![(env.kit.name_output(&nf, 0), format!("name {name} expires {}", fmt_ms(nf.expires_at)))],
        lock_time: 0,
        price_fee: price,
        notes: vec![
            format!(
                "extension price {} = {} x {years} period(s) (the renewal price), left as miner fee",
                fmt_kas(price),
                fmt_kas(p.renew_price_for(name.len()))
            ),
            format!(
                "expiresAt {} -> {}; periodStart {} kept (at most {} periods past it)",
                fmt_ms(f.expires_at),
                fmt_ms(nf.expires_at),
                fmt_ms(f.period_start),
                p.max_years
            ),
        ],
    };
    finish(env, wallet, d, name_payload("extend", &name), Fee::Funded { max_inputs: MAX_IO_FEE_ENTRY })
}

/// Anyone renews once the renewal window opened: [name.renew(years),
/// funding] -> [continuation (periodStart = old expiresAt, expiresAt +
/// years), change], years x the renewal price as miner fee. Lock time =
/// [`renew_lock_time`] (timestamp domain), every input sequence 0 (not final,
/// as the CLTV needs). Before the window opens the plan is built but rejected
/// (not final); the CLI refuses to submit it.
pub fn renew(env: &Env, wallet: &[Utxo], n: &NameRec, utxo: &Utxo, years: i64) -> Result<Plan> {
    let p = &env.kit.params;
    ensure!((1..=p.max_years).contains(&years), "years must be 1..{}", p.max_years);
    check_live(&n.name(), utxo, p.bond, Some(env.kit.registry_id))?;
    let name = n.name();
    let f = &n.fields;
    let opens = renew_opens(p, f);
    ensure!(opens >= 0 && opens as u64 >= LOCK_TIME_THRESHOLD, "{name}: expiresAt - renewWindowMs is not a timestamp");
    let lock = renew_lock_time(env, f);
    let price = p.renew_price_for(name.len()) * years as u64;
    let nf = f.renewed(years, p.period_ms);
    let mut notes = vec![
        format!("renewal price {} = {} x {years} period(s), left as miner fee", fmt_kas(price), fmt_kas(p.renew_price_for(name.len()))),
        format!(
            "new period: periodStart {} -> {} (the old expiry), expiresAt -> {}",
            fmt_ms(f.period_start),
            fmt_ms(nf.period_start),
            fmt_ms(nf.expires_at)
        ),
        format!("lock time {lock} ({}) >= window opening expiresAt - renewWindowMs = {opens} ({})", fmt_ms(lock), fmt_ms(opens)),
    ];
    if !renew_window_open(env, f) {
        notes.push(format!(
            "renewal window not open: it opens {} (the network median time {} must pass it, ~{}); use extend to add periods before",
            fmt_ms(opens),
            fmt_ms(env.block.time_ms as i64),
            fmt_dur(opens - env.block.time_ms as i64)
        ));
    }
    let d = Draft {
        op: format!("renew {name} ({years} period(s))"),
        inputs: vec![(name_input(env, n, utxo, "renew", vec![int(years)]), format!("name {name} renew({years})"))],
        outputs: vec![(env.kit.name_output(&nf, 0), format!("name {name} expires {}", fmt_ms(nf.expires_at)))],
        lock_time: lock as u64,
        price_fee: price,
        notes,
    };
    finish(env, wallet, d, name_payload("renew", &name), Fee::Funded { max_inputs: MAX_IO_FEE_ENTRY })
}

pub fn transfer(env: &Env, wallet: &[Utxo], n: &NameRec, utxo: &Utxo, new_owner: &[u8; 32]) -> Result<Plan> {
    require_owner(env, n)?;
    check_live(&n.name(), utxo, env.kit.params.bond, Some(env.kit.registry_id))?;
    let name = n.name();
    let mut notes = vec![];
    if *new_owner != env.me() {
        notes.push("the new owner is not the deployer: this CLI cannot act for the name after this".into());
    }
    if n.fields.price != 0 {
        notes.push("the listing is cleared".into());
    }
    let d = Draft {
        op: format!("transfer {name}"),
        inputs: vec![(
            name_input(env, n, utxo, "transfer", vec![bytes(new_owner), Arg::Sig(env.deployer)]),
            format!("name {name} transfer (owner sig)"),
        )],
        outputs: vec![(env.kit.name_output(&n.fields.with_owner(new_owner), 0), format!("name {name} -> {}", p2pk_address(new_owner)))],
        lock_time: 0,
        price_fee: 0,
        notes,
    };
    finish(env, wallet, d, name_payload("transfer", &name), Fee::Funded { max_inputs: MAX_INPUTS })
}

pub fn list(env: &Env, wallet: &[Utxo], n: &NameRec, utxo: &Utxo, price: u64) -> Result<Plan> {
    require_owner(env, n)?;
    check_live(&n.name(), utxo, env.kit.params.bond, Some(env.kit.registry_id))?;
    ensure!(price <= 2_900_000_000_000_000_000, "price above the supply");
    let name = n.name();
    let mut notes = vec![];
    if n.fields.expires_at <= env.wall_ms {
        notes.push("the name is expired: the app refuses to list a name in grace".into());
    }
    let d = Draft {
        op: if price == 0 { format!("delist {name}") } else { format!("list {name} at {}", fmt_kas(price)) },
        inputs: vec![(
            name_input(env, n, utxo, "list", vec![int(price as i64), Arg::Sig(env.deployer)]),
            format!("name {name} list (owner sig)"),
        )],
        outputs: vec![(env.kit.name_output(&n.fields.with_price(price as i64), 0), format!("name {name} price {}", fmt_kas(price)))],
        lock_time: 0,
        price_fee: 0,
        notes,
    };
    finish(env, wallet, d, name_payload("list", &name), Fee::Funded { max_inputs: MAX_INPUTS })
}

/// The deployer buys a listed name: [name.buy(me), funding] ->
/// [continuation, payout = price to P2PK(owner), change].
pub fn buy(env: &Env, wallet: &[Utxo], n: &NameRec, utxo: &Utxo) -> Result<Plan> {
    check_live(&n.name(), utxo, env.kit.params.bond, Some(env.kit.registry_id))?;
    ensure!(n.fields.price > 0, "{} is not listed", n.name());
    let name = n.name();
    let me = env.me();
    let price = n.fields.price as u64;
    let mut notes = vec![];
    if n.fields.owner == me {
        notes.push("buyer and seller are both the deployer: the payout comes straight back".into());
    }
    if n.fields.expires_at - 30 * 86_400_000 < env.wall_ms {
        notes.push(format!("expires {} (less than 30 days left)", fmt_ms(n.fields.expires_at)));
    }
    let d = Draft {
        op: format!("buy {name} for {}", fmt_kas(price)),
        inputs: vec![(name_input(env, n, utxo, "buy", vec![bytes(&me)]), format!("name {name} buy(deployer)"))],
        outputs: vec![
            (env.kit.name_output(&n.fields.with_owner(&me), 0), format!("name {name} -> deployer")),
            (TransactionOutput::new(price, p2pk_spk(&n.fields.owner)), format!("payout to seller {}", p2pk_address(&n.fields.owner))),
        ],
        lock_time: 0,
        price_fee: 0,
        notes,
    };
    finish(env, wallet, d, name_payload("buy", &name), Fee::Funded { max_inputs: MAX_INPUTS })
}

// ---------------------------------------------------------------------------
// offers
// ---------------------------------------------------------------------------

/// An offer on a registered name, bound to its current owner (since registry v3: only that
/// owner can accept or decline it; a change of owner ends it).
pub fn offer(env: &Env, wallet: &[Utxo], name: &str, amount: u64, refund_after: u64, target: &NameRec) -> Result<Plan> {
    check_name(name)?;
    let p = &env.kit.params;
    ensure!(amount > p.offer_max_fee + MIN_CHANGE, "offer too small");
    ensure!(refund_after < LOCK_TIME_THRESHOLD, "refundAfter is a DAA score");
    ensure!(target.fields.key == name_key(name.as_bytes()), "the target record is for another name");
    let fields = OfferFields {
        key: name_key(name.as_bytes()),
        buyer: env.me(),
        seller: target.fields.owner,
        refund_after: refund_after as i64,
    };
    let spk = env.kit.offer.spk(&fields.encode());
    let addr = spk_address(&spk)?;
    let mut notes = vec![format!(
        "refundable by anyone from DAA {refund_after} (now {}, ~{} s)",
        env.block.daa,
        refund_after.saturating_sub(env.block.daa).div_ceil(10)
    )];
    notes.push(format!("made to the owner {}: only they can accept or decline it", p2pk_address(&target.fields.owner)));
    if target.fields.price > 0 && (target.fields.price as u64) <= amount {
        notes.push(format!("{name} is listed at {}, at or below this offer: buying it may be cheaper", fmt_kas(target.fields.price as u64)));
    }
    notes.push(format!("{name} expires {}", fmt_ms(target.fields.expires_at)));
    let d = Draft {
        op: format!("offer {} on {name}", fmt_kas(amount)),
        inputs: vec![],
        outputs: vec![(TransactionOutput::new(amount, spk), format!("offer P2SH {addr} (buyer deployer)"))],
        lock_time: 0,
        price_fee: 0,
        notes,
    };
    let mut plan = finish(env, wallet, d, offer_payload(&fields), Fee::Funded { max_inputs: MAX_INPUTS })?;
    plan.new_offer = Some(OfferRec {
        outpoint: TransactionOutpoint::new(plan.txid(), 0),
        fields,
        value: amount,
        name: Some(name.to_string()),
    });
    Ok(plan)
}

fn offer_input(env: &Env, o: &OfferRec, utxo: &Utxo, entry: &str, args: Vec<Arg>) -> Input {
    Input::contract(utxo.clone(), &env.kit.offer, o.fields.encode(), entry, args)
}

/// The owner (deployer) accepts: [name.transfer(buyer, sig) @0,
/// offer.accept(0) @1] -> [continuation to the buyer, payout to the owner].
pub fn accept_offer(env: &Env, n: &NameRec, name_utxo: &Utxo, o: &OfferRec, offer_utxo: &Utxo) -> Result<Plan> {
    require_owner(env, n)?;
    ensure!(
        o.fields.seller == env.me(),
        "that offer was made to {}, an earlier owner of {}: it can't be accepted (an offer is bound to the owner it was made to)",
        p2pk_address(&o.fields.seller),
        n.name()
    );
    check_live(&n.name(), name_utxo, env.kit.params.bond, Some(env.kit.registry_id))?;
    check_live("offer", offer_utxo, o.value, None)?;
    ensure!(o.fields.key == n.fields.key, "that offer is for another name");
    let name = n.name();
    let d = Draft {
        op: format!("accept offer {} on {name}", fmt_kas(o.value)),
        inputs: vec![
            (
                name_input(env, n, name_utxo, "transfer", vec![bytes(&o.fields.buyer), Arg::Sig(env.deployer)]),
                format!("name {name} transfer(buyer) (owner sig)"),
            ),
            (offer_input(env, o, offer_utxo, "accept", vec![int(0), Arg::Sig(env.deployer)]), "offer accept(0) (seller sig)".into()),
        ],
        outputs: vec![
            (env.kit.name_output(&n.fields.with_owner(&o.fields.buyer), 0), format!("name {name} -> buyer {}", p2pk_address(&o.fields.buyer))),
            (TransactionOutput::new(0, p2pk_spk(&n.fields.owner)), format!("payout to owner {} (offer - fee)", p2pk_address(&n.fields.owner))),
        ],
        lock_time: 0,
        price_fee: 0,
        notes: vec![format!("the network fee comes out of the offer (contract maxFee {})", fmt_kas(env.kit.params.offer_max_fee))],
    };
    finish(env, &[], d, name_payload("accept", &name), Fee::FromOutput { idx: 1, cap: Some(env.kit.params.offer_max_fee), floor: MIN_CHANGE })
}

/// The seller turns an offer down (since registry v3): [offer.decline(sellerSig)] alone ->
/// [back to the buyer, the offer less the network fee (at most maxFee)].
pub fn decline_offer(env: &Env, o: &OfferRec, utxo: &Utxo) -> Result<Plan> {
    ensure!(o.fields.seller == env.me(), "only the seller {} can decline this offer", p2pk_address(&o.fields.seller));
    check_live("offer", utxo, o.value, None)?;
    let d = Draft {
        op: format!("decline offer {}", fmt_kas(o.value)),
        inputs: vec![(offer_input(env, o, utxo, "decline", vec![Arg::Sig(env.deployer)]), "offer decline (seller sig)".into())],
        outputs: vec![(TransactionOutput::new(0, p2pk_spk(&o.fields.buyer)), format!("back to the buyer {}", p2pk_address(&o.fields.buyer)))],
        lock_time: 0,
        price_fee: 0,
        notes: vec![format!("the network fee comes out of the offer (contract maxFee {})", fmt_kas(env.kit.params.offer_max_fee))],
    };
    finish(env, &[], d, vec![], Fee::FromOutput { idx: 0, cap: Some(env.kit.params.offer_max_fee), floor: MIN_CHANGE })
}

pub fn withdraw_offer(env: &Env, o: &OfferRec, utxo: &Utxo) -> Result<Plan> {
    ensure!(o.fields.buyer == env.me(), "only the buyer can withdraw this offer");
    check_live("offer", utxo, o.value, None)?;
    let d = Draft {
        op: format!("withdraw offer {}", fmt_kas(o.value)),
        inputs: vec![(offer_input(env, o, utxo, "withdraw", vec![Arg::Sig(env.deployer)]), "offer withdraw (buyer sig)".into())],
        outputs: vec![(TransactionOutput::new(0, p2pk_spk(&o.fields.buyer)), "back to the buyer".into())],
        lock_time: 0,
        price_fee: 0,
        notes: vec![],
    };
    finish(env, &[], d, vec![], Fee::FromOutput { idx: 0, cap: None, floor: MIN_CHANGE })
}

/// Anyone refunds once DAA >= refundAfter: 1 input, 1 output, lock time =
/// refundAfter (DAA domain), sequence 0.
pub fn refund_offer(env: &Env, o: &OfferRec, utxo: &Utxo) -> Result<Plan> {
    check_live("offer", utxo, o.value, None)?;
    let mut notes = vec![];
    if env.block.daa <= o.fields.refund_after as u64 {
        notes.push(format!(
            "not refundable yet: the virtual DAA must pass {} (now {}, ~{} s)",
            o.fields.refund_after,
            env.block.daa,
            (o.fields.refund_after as u64 + 1 - env.block.daa).div_ceil(10)
        ));
    }
    let d = Draft {
        op: format!("refund offer {}", fmt_kas(o.value)),
        inputs: vec![(offer_input(env, o, utxo, "refund", vec![]), "offer refund()".into())],
        outputs: vec![(TransactionOutput::new(0, p2pk_spk(&o.fields.buyer)), format!("refund to the buyer {}", p2pk_address(&o.fields.buyer)))],
        lock_time: o.fields.refund_after as u64,
        price_fee: 0,
        notes,
    };
    finish(env, &[], d, vec![], Fee::FromOutput { idx: 0, cap: Some(env.kit.params.offer_max_fee), floor: MIN_CHANGE })
}

// ---------------------------------------------------------------------------
// the exit
// ---------------------------------------------------------------------------

pub struct ExitParts<'a> {
    pub below: &'a GapRec,
    pub below_utxo: &'a Utxo,
    pub name: &'a NameRec,
    pub name_utxo: &'a Utxo,
    pub above: &'a GapRec,
    pub above_utxo: &'a Utxo,
}

fn exit_checks(env: &Env, x: &ExitParts) -> Result<()> {
    let key = x.name.fields.key;
    ensure!(x.below.hi == key && x.above.lo == key, "the gaps do not sit on {}", x.name.name());
    let id = Some(env.kit.registry_id);
    check_live("lower gap", x.below_utxo, env.kit.params.gap_value, id)?;
    check_live(&x.name.name(), x.name_utxo, env.kit.params.bond, id)?;
    check_live("upper gap", x.above_utxo, env.kit.params.gap_value, id)?;
    Ok(())
}

/// The owner releases: [merge, release(sig), absorbed] -> [merged gap, change].
pub fn release(env: &Env, x: ExitParts) -> Result<Plan> {
    require_owner(env, x.name)?;
    exit_checks(env, &x)?;
    let name = x.name.name();
    let d = Draft {
        op: format!("release {name}"),
        inputs: vec![
            (gap_input(env, x.below, x.below_utxo, "merge", vec![]), format!("{} merge", label_gap(&x.below.lo, &x.below.hi))),
            (name_input(env, x.name, x.name_utxo, "release", vec![Arg::Sig(env.deployer)]), format!("name {name} release (owner sig)")),
            (gap_input(env, x.above, x.above_utxo, "absorbed", vec![]), format!("{} absorbed", label_gap(&x.above.lo, &x.above.hi))),
        ],
        outputs: vec![
            (env.kit.gap_output(&x.below.lo, &x.above.hi, 0), format!("merged {}", label_gap(&x.below.lo, &x.above.hi))),
            (TransactionOutput::new(0, env.my_spk()), "bond + freed gap value - fee (deployer)".into()),
        ],
        lock_time: 0,
        price_fee: 0,
        notes: vec![],
    };
    finish(env, &[], d, name_payload("release", &name), Fee::FromOutput { idx: 1, cap: None, floor: MIN_CHANGE })
}

/// Anyone reclaims a lapsed name: [merge, reclaim(), absorbed] -> [merged
/// gap, bond to the last owner, bounty to the caller]; lock time =
/// expiresAt + graceMs (timestamp domain).
pub fn reclaim(env: &Env, x: ExitParts) -> Result<Plan> {
    exit_checks(env, &x)?;
    let p = &env.kit.params;
    let name = x.name.name();
    let unlock = x.name.fields.expires_at + p.grace_ms;
    ensure!(unlock as u64 >= LOCK_TIME_THRESHOLD, "expiresAt + grace is not a timestamp");
    let mut notes = vec![format!("lock time = expiresAt + grace = {unlock} ({})", fmt_ms(unlock))];
    if env.block.time_ms as i64 <= unlock {
        notes.push(format!(
            "not reclaimable yet: the virtual median time {} must pass {} (~{:.1} days)",
            fmt_ms(env.block.time_ms as i64),
            fmt_ms(unlock),
            (unlock - env.block.time_ms as i64) as f64 / 86_400_000.0
        ));
    }
    let d = Draft {
        op: format!("reclaim {name}"),
        inputs: vec![
            (gap_input(env, x.below, x.below_utxo, "merge", vec![]), format!("{} merge", label_gap(&x.below.lo, &x.below.hi))),
            (name_input(env, x.name, x.name_utxo, "reclaim", vec![]), format!("name {name} reclaim()")),
            (gap_input(env, x.above, x.above_utxo, "absorbed", vec![]), format!("{} absorbed", label_gap(&x.above.lo, &x.above.hi))),
        ],
        outputs: vec![
            (env.kit.gap_output(&x.below.lo, &x.above.hi, 0), format!("merged {}", label_gap(&x.below.lo, &x.above.hi))),
            (TransactionOutput::new(p.bond, p2pk_spk(&x.name.fields.owner)), format!("bond to the last owner {}", p2pk_address(&x.name.fields.owner))),
            (TransactionOutput::new(0, env.my_spk()), "bounty: freed gap value - fee (caller = deployer)".into()),
        ],
        lock_time: unlock as u64,
        price_fee: 0,
        notes,
    };
    finish(env, &[], d, name_payload("reclaim", &name), Fee::FromOutput { idx: 2, cap: None, floor: MIN_CHANGE })
}

// ---------------------------------------------------------------------------
// registry v5: import from the migration snapshot
// ---------------------------------------------------------------------------

/// One name of a checked snapshot file (`snapshot::check_file`), ready to import.
pub struct SnapItem {
    pub name: String,
    pub entry: kachat_names_harness::snapshot::Entry,
    pub index: usize,
    pub proof: Vec<u8>,
}

/// [gap.import, funding..] -> [gap (lo, key), gap (key, hi), name, change]: the
/// snapshot name with its snapshot owner and paid period, unlisted. The
/// deployer signs as the sponsor (or as the owner, for its own names); there
/// is no price, only the network fee, and no time lock.
pub fn import(env: &Env, wallet: &[Utxo], gap: &GapRec, gap_utxo: &Utxo, item: &SnapItem) -> Result<Plan> {
    let p = &env.kit.params;
    ensure!(p.registry_version >= 5, "import needs a registry v5 (params registryVersion 5)");
    let m = p.migration.ok_or_else(|| anyhow!("params carry no migration"))?;
    let name = item.name.as_str();
    check_name(name)?;
    let key = name_key(name.as_bytes());
    ensure!(key == item.entry.key, "{name}: the snapshot key is not blake3(name)");
    ensure!(gap.lo < key && key < gap.hi, "{name} is not inside {} (already imported or registered?)", label_gap(&gap.lo, &gap.hi));
    check_live("gap", gap_utxo, p.gap_value, Some(env.kit.registry_id))?;
    let me = env.me();
    let by_sponsor = item.entry.owner != me;
    ensure!(!by_sponsor || m.sponsor == me, "the deployer is neither {name}'s snapshot owner nor the migration sponsor");
    let e = &item.entry;
    let fields = NameFields::new(name.as_bytes(), &e.owner, 0, e.period_start, e.expires_at);
    let mut notes = vec![
        format!(
            "from the snapshot (leaf {}): owner {}, periodStart {}, expiresAt {}",
            item.index,
            p2pk_address(&e.owner),
            fmt_ms(e.period_start),
            fmt_ms(e.expires_at)
        ),
        format!("signed by the deployer as {}; no price, only the network fee", if by_sponsor { "the migration sponsor" } else { "the owner" }),
    ];
    if e.expires_at + p.grace_ms < env.wall_ms {
        notes.push("already past expiresAt + grace: reclaimable as soon as it is imported".into());
    } else if e.expires_at < env.wall_ms {
        notes.push("expired: in grace, its owner can still renew it".into());
    }
    let d = Draft {
        op: format!("import {name}"),
        inputs: vec![(
            gap_input(
                env,
                gap,
                gap_utxo,
                "import",
                vec![
                    bytes(name.as_bytes()),
                    bytes(&e.owner),
                    int(e.period_start),
                    int(e.expires_at),
                    int(item.index as i64),
                    bytes(&item.proof),
                    Arg::V(ArtifactValue::Bool(by_sponsor)),
                    Arg::Sig(env.deployer),
                    bytes(&env.kit.name.prefix),
                    bytes(&env.kit.name.suffix),
                ],
            ),
            format!("{} import", label_gap(&gap.lo, &gap.hi)),
        )],
        outputs: vec![
            (env.kit.gap_output(&gap.lo, &key, 0), label_gap(&gap.lo, &key)),
            (env.kit.gap_output(&key, &gap.hi, 0), label_gap(&key, &gap.hi)),
            (env.kit.name_output(&fields, 0), format!("name {name} (owner {}, expires {})", p2pk_address(&e.owner), fmt_ms(e.expires_at))),
        ],
        lock_time: 0,
        price_fee: 0,
        notes,
    };
    finish(env, wallet, d, name_payload("import", name), Fee::Funded { max_inputs: MAX_IO_FEE_ENTRY })
}

/// The importable names of a snapshot file, checked (tree rebuilt, every proof matched).
pub fn snapshot_items(v: &serde_json::Value) -> Result<Vec<SnapItem>> {
    let snap = crate::snapshot::check_file(v)?;
    let mut out = Vec::new();
    for e in v["entries"].as_array().into_iter().flatten() {
        let name = e["name"].as_str().unwrap_or("").to_string();
        let index = snap.index_of(&name_key(name.as_bytes())).ok_or_else(|| anyhow!("{name}: not in the rebuilt tree"))?;
        out.push(SnapItem { name, entry: snap.entries[index].clone(), index, proof: snap.proof(index) });
    }
    Ok(out)
}
