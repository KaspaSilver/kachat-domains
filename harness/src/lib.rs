//! Engine-backed test harness for the .kachat name covenants.
//!
//! Everything here mirrors what the app will do on chain: it splices runtime
//! state into the compiled templates by hand (no compiler at run time), builds
//! version-1 transactions with covenant bindings and per-input compute budgets,
//! signs with SIGHASH_ALL, and validates with rusty-kaspa's own
//! `TransactionValidator` (isolation + UTXO context: every input script runs
//! through `TxScriptEngine` under its committed compute budget, plus covenant
//! bindings / genesis ids, sequence locks and amounts) at the exact revision
//! silverscript v1.0.0 pins.
//!
//! The one consensus rule replicated by hand is the header-context finality
//! check (`check_tx_is_finalized`, crate-private upstream); see
//! [`check_tx_is_finalized`].

pub mod scenarios;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

pub use kaspa_consensus_core::Hash;
use kaspa_consensus_core::{
    config::params::{ForkActivation, MAINNET_PARAMS, Params},
    constants::LOCK_TIME_THRESHOLD,
    hashing::{
        covenant_id::covenant_id,
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::{SIG_HASH_ALL, SigHashType},
    },
    mass::{ComputeBudget, Gram, MassCalculator, ScriptUnits},
    subnets::SUBNETWORK_ID_NATIVE,
};
pub use kaspa_consensus_core::tx::{
    ComputeCommit, CovenantBinding, MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId,
    TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus::processes::transaction_validator::{TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags};
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext, pay_to_script_hash_script,
    script_builder::ScriptBuilder,
};
pub use kaspa_txscript_errors::TxScriptError;
use secp256k1::{Keypair, Secp256k1, SecretKey};
pub use silverscript_abi::ArtifactValue;
use silverscript_abi::{SilAbiArtifact, encode_contract_entry_sig_script};

pub const SOMPI_PER_KAS: u64 = 100_000_000;
/// A mainnet period (registry v3 bakes `periodMs`; testnet runs a 10-minute clock).
pub const YEAR_MS: i64 = 31_536_000_000;
/// Default compute budget used while measuring an input that fails (attack tests).
const FALLBACK_BUDGET: u16 = 1_000;
/// Relay floor after Toccata: 100 sompi per gram (mining/src/mempool/config.rs).
pub const MIN_RELAY_FEE_SOMPI_PER_KG: u64 = 100_000;

// ---------------------------------------------------------------------------
// Params and templates
// ---------------------------------------------------------------------------

/// The repository root this crate was built in (the harness's parent
/// directory). Tools that run from elsewhere pass their own root to the
/// `*_in` loaders instead.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

#[derive(Clone, Debug)]
pub struct NetParams {
    pub network: String,
    pub bond: u64,
    pub gap_value: u64,
    pub t_commit: u64,
    /// most periods a registration / extension may prepay
    pub max_years: i64,
    /// one paid period, ms (a year on mainnet, 10 minutes on testnet)
    pub period_ms: i64,
    pub grace_ms: i64,
    /// renew is valid from expiresAt - renew_window_ms on
    pub renew_window_ms: i64,
    /// registry v4, fixed: sompi for a name's first period, by length 1, 2, 3,
    /// 4, 5+ bytes
    pub register_prices: [u64; 5],
    /// sompi per further period (extend, renew, and registering past one period)
    pub renew_prices: [u64; 5],
    pub offer_max_fee: u64,
}

fn tiers(p: &serde_json::Value) -> [u64; 5] {
    let u = |k: &str| p[k].as_u64().unwrap();
    [u("len1"), u("len2"), u("len3"), u("len4"), u("len5plus")]
}

impl NetParams {
    pub fn load(file: &str) -> Self {
        Self::load_in(&repo_root(), file)
    }

    pub fn load_in(root: &Path, file: &str) -> Self {
        let path = root.join("params").join(format!("{file}.json"));
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let u = |x: &serde_json::Value| x.as_u64().unwrap();
        NetParams {
            network: v["network"].as_str().unwrap().to_string(),
            bond: u(&v["bond"]),
            gap_value: u(&v["gapValue"]),
            t_commit: u(&v["tCommit"]),
            max_years: u(&v["maxYears"]) as i64,
            period_ms: u(&v["periodMs"]) as i64,
            grace_ms: u(&v["graceMs"]) as i64,
            renew_window_ms: u(&v["renewWindowMs"]) as i64,
            register_prices: tiers(&v["prices"]["register"]),
            renew_prices: tiers(&v["prices"]["renew"]),
            offer_max_fee: u(&v["offerMaxFee"]),
        }
    }

    /// The registration price of a name's first period.
    pub fn price_for(&self, name_len: usize) -> u64 {
        self.register_prices[name_len.clamp(1, 5) - 1]
    }

    /// The price of every further period (extend, renew).
    pub fn renew_price_for(&self, name_len: usize) -> u64 {
        self.renew_prices[name_len.clamp(1, 5) - 1]
    }

    /// What `register` charges for `years` periods: the first at the
    /// registration price, the rest at the renewal price.
    pub fn register_cost(&self, name_len: usize, years: i64) -> u64 {
        self.price_for(name_len) + self.renew_price_for(name_len) * (years as u64 - 1)
    }
}

/// A compiled template: `redeem = prefix || state || suffix`.
pub struct Template {
    pub abi: SilAbiArtifact,
    pub contract: String,
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub template_hash: [u8; 32],
    pub bytecode: Vec<u8>,
}

impl Template {
    pub fn from_artifact(abi: SilAbiArtifact) -> Self {
        let (name, c) = abi.contracts.iter().next().expect("one contract");
        let bc = c.compiled.bytecode.clone();
        let span = c.compiled.state_span;
        Template {
            contract: name.clone(),
            prefix: bc[..span.offset].to_vec(),
            suffix: bc[span.offset + span.len..].to_vec(),
            template_hash: c.compiled.template_hash,
            bytecode: bc,
            abi,
        }
    }

    pub fn load(network_dir: &str, contract: &str) -> Self {
        Self::load_in(&repo_root(), network_dir, contract)
    }

    pub fn load_in(root: &Path, network_dir: &str, contract: &str) -> Self {
        let path = root.join("artifacts").join(network_dir).join(format!("{contract}.json"));
        let abi: SilAbiArtifact = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        abi.check_consistency().expect("artifact consistency");
        Self::from_artifact(abi)
    }

    pub fn redeem(&self, state: &[u8]) -> Vec<u8> {
        [self.prefix.as_slice(), state, self.suffix.as_slice()].concat()
    }

    pub fn spk(&self, state: &[u8]) -> ScriptPublicKey {
        pay_to_script_hash_script(&self.redeem(state))
    }

    pub fn dispatch_tag(&self, entry: &str) -> String {
        self.abi.contracts[&self.contract].entries[entry].dispatch_tag.to_hex()
    }

    /// `<args> <dispatch tag> <push(redeem)>`
    pub fn sig_script(&self, redeem: &[u8], entry: &str, args: &[ArtifactValue]) -> Vec<u8> {
        let mut s = encode_contract_entry_sig_script(&self.abi, &self.contract, entry, args).expect("encode entry");
        s.extend(push(redeem));
        s
    }
}

pub fn push(data: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() }).add_data(data).unwrap().drain()
}

// ---------------------------------------------------------------------------
// State codecs (hand-written, exactly what the app splices)
// ---------------------------------------------------------------------------

/// Script number in a fixed 8-byte signed-magnitude little-endian encoding
/// (what `OpNum2Bin 8` produces and what state ints use).
pub fn num8(v: i64) -> [u8; 8] {
    assert!(v != i64::MIN);
    let mut out = v.unsigned_abs().to_le_bytes();
    if v < 0 {
        out[7] |= 0x80;
    }
    out
}

/// Gap state, 66 bytes: `0x20 lo 0x20 hi`.
pub fn gap_state(lo: &[u8; 32], hi: &[u8; 32]) -> Vec<u8> {
    [&[0x20u8][..], lo, &[0x20], hi].concat()
}

/// Name state, 126 bytes:
/// `0x20 key 0x20 name 0x20 owner 0x08 price 0x08 periodStart 0x08 expiresAt`.
pub fn name_state(key: &[u8; 32], padded_name: &[u8; 32], owner: &[u8; 32], price: i64, period_start: i64, expires_at: i64) -> Vec<u8> {
    [
        &[0x20u8][..],
        key,
        &[0x20],
        padded_name,
        &[0x20],
        owner,
        &[0x08],
        &num8(price),
        &[0x08],
        &num8(period_start),
        &[0x08],
        &num8(expires_at),
    ]
    .concat()
}

/// Length of the name state.
pub const NAME_STATE_LEN: usize = 126;

/// Offer state, 108 bytes: `0x20 key 0x20 buyer 0x20 seller 0x08 refundAfter`.
pub fn offer_state(key: &[u8; 32], buyer: &[u8; 32], seller: &[u8; 32], refund_after: i64) -> Vec<u8> {
    [&[0x20u8][..], key, &[0x20], buyer, &[0x20], seller, &[0x08], &num8(refund_after)].concat()
}

pub fn name_key(name: &[u8]) -> [u8; 32] {
    *blake3::hash(name).as_bytes()
}

pub fn pad_name(name: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

pub const COMMIT_DOMAIN: &[u8] = b"kachat-commit:v1";

/// `blake3("kachat-commit:v1" || name || ownerKey || salt)`
pub fn commitment(name: &[u8], owner: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(COMMIT_DOMAIN).update(name).update(owner).update(salt);
    *h.finalize().as_bytes()
}

/// The fixed commit redeem script `0x20 <c> OP_DROP 0x20 <ownerKey> OP_CHECKSIG`.
pub fn commit_redeem(c: &[u8; 32], owner: &[u8; 32]) -> Vec<u8> {
    [&[0x20u8][..], c, &[0x75, 0x20], owner, &[0xac]].concat()
}

pub fn p2pk_spk(x_only: &[u8; 32]) -> ScriptPublicKey {
    ScriptPublicKey::new(0, [&[0x20u8][..], x_only, &[0xac]].concat().into())
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

pub fn keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let mut sk = [0u8; 32];
    sk[0] = 0x5a;
    sk[31] = seed.max(1);
    Keypair::from_secret_key(&secp, &SecretKey::from_slice(&sk).unwrap())
}

pub fn xonly(kp: &Keypair) -> [u8; 32] {
    kp.x_only_public_key().0.serialize()
}

// ---------------------------------------------------------------------------
// The kit: templates, registry genesis, validator
// ---------------------------------------------------------------------------

pub struct Kit {
    pub params: NetParams,
    pub name: Arc<Template>,
    pub gap: Arc<Template>,
    pub offer: Arc<Template>,
    pub registry_id: Hash,
    pub genesis_tx: Built,
    /// consensus params the validator and the mass/fee figures use
    pub consensus: Params,
    validator: TransactionValidator,
    mass_calculator: MassCalculator,
}

pub const ZERO32: [u8; 32] = [0u8; 32];
pub const FF32: [u8; 32] = [0xffu8; 32];

impl Kit {
    /// Loads the testnet-10 artifacts produced by scripts/build.sh and compiles
    /// the offer for the registry id minted by this kit's genesis transaction.
    pub fn new() -> Self {
        Self::for_network("testnet10")
    }

    pub fn for_network(params_file: &str) -> Self {
        let root = repo_root();
        let params = NetParams::load_in(&root, params_file);
        let deployer = keypair(200);

        // Registry v4: the prices are baked, so the name and gap compile first.
        let name = Arc::new(compile_name_in(&root, &params));
        let gap = Arc::new(compile_gap_in(&root, &params, &name));

        // Registry genesis: one ordinary UTXO creates the lone genesis gap
        // (00..00, ff..ff), the only output of its covenant group.
        let genesis_funding = Utxo::new(
            TransactionOutpoint::new(TransactionId::from_bytes([0x42; 32]), 0),
            UtxoEntry::new(10 * SOMPI_PER_KAS, p2pk_spk(&xonly(&deployer)), 1_000, false, None),
        );
        let change = TransactionOutput::new(10 * SOMPI_PER_KAS - params.gap_value - 500_000, p2pk_spk(&xonly(&deployer)));
        let (spec, registry_id) = genesis_spec(&params, &gap, genesis_funding, deployer, vec![change]);
        let offer = Arc::new(compile_offer_in(&root, &params, &name, registry_id));
        let mut kit = Self::assemble_kit(params, name, gap, offer, registry_id, MAINNET_PARAMS);
        kit.genesis_tx = kit.build(&spec);
        kit
    }

    /// A kit for an existing registry (`registry_id` from a real or would-be
    /// genesis), validating under `consensus` params. `name`, `gap` and `offer`
    /// are compiled for that registry. The genesis tx is left empty.
    pub fn with_registry(params: NetParams, name: Template, gap: Template, offer: Template, registry_id: Hash, consensus: Params) -> Self {
        Self::assemble_kit(params, Arc::new(name), Arc::new(gap), Arc::new(offer), registry_id, consensus)
    }

    fn assemble_kit(params: NetParams, name: Arc<Template>, gap: Arc<Template>, offer: Arc<Template>, registry_id: Hash, p: Params) -> Self {
        let mass_calculator = MassCalculator::new_with_consensus_params(&p);
        let validator = TransactionValidator::new(
            p.max_tx_inputs,
            p.max_tx_outputs,
            p.max_signature_script_len(),
            p.max_script_public_key_len,
            p.coinbase_payload_script_public_key_max_len,
            p.coinbase_maturity(),
            p.ghostdag_k(),
            Default::default(),
            mass_calculator.clone(),
            ForkActivation::always(),
            p.mass_per_sig_op,
        );
        let empty = || Built { tx: Transaction::new(1, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]), entries: vec![], budgets: vec![], used_units: vec![] };
        Kit {
            params,
            name,
            gap,
            offer,
            registry_id,
            genesis_tx: empty(),
            consensus: p,
            validator,
            mass_calculator,
        }
    }

    pub fn registry_utxo(&self, spk: ScriptPublicKey, value: u64, daa: u64, tag: u8) -> Utxo {
        Utxo::new(
            TransactionOutpoint::new(TransactionId::from_bytes([tag; 32]), tag as u32),
            UtxoEntry::new(value, spk, daa, false, Some(self.registry_id)),
        )
    }

    pub fn gap_utxo(&self, lo: &[u8; 32], hi: &[u8; 32], tag: u8) -> Utxo {
        self.registry_utxo(self.gap.spk(&gap_state(lo, hi)), self.params.gap_value, 1_000, tag)
    }

    pub fn name_utxo(&self, state: &NameFields, tag: u8) -> Utxo {
        self.registry_utxo(self.name.spk(&state.encode()), self.params.bond, 1_000, tag)
    }

    pub fn offer_utxo(&self, state: &OfferFields, value: u64, tag: u8) -> Utxo {
        Utxo::new(
            TransactionOutpoint::new(TransactionId::from_bytes([tag; 32]), tag as u32),
            UtxoEntry::new(value, self.offer.spk(&state.encode()), 1_000, false, None),
        )
    }

    pub fn p2pk_utxo(&self, owner: &Keypair, value: u64, tag: u8) -> Utxo {
        Utxo::new(
            TransactionOutpoint::new(TransactionId::from_bytes([tag; 32]), tag as u32),
            UtxoEntry::new(value, p2pk_spk(&xonly(owner)), 1_000, false, None),
        )
    }

    pub fn registry_output(&self, value: u64, spk: ScriptPublicKey, authorizing_input: u16) -> TransactionOutput {
        TransactionOutput::with_covenant(value, spk, Some(CovenantBinding { authorizing_input, covenant_id: self.registry_id }))
    }

    pub fn gap_output(&self, lo: &[u8; 32], hi: &[u8; 32], auth: u16) -> TransactionOutput {
        self.registry_output(self.params.gap_value, self.gap.spk(&gap_state(lo, hi)), auth)
    }

    pub fn name_output(&self, state: &NameFields, auth: u16) -> TransactionOutput {
        self.registry_output(self.params.bond, self.name.spk(&state.encode()), auth)
    }

    // -- building ----------------------------------------------------------

    /// Two passes: sign with a provisional budget and measure every input's
    /// script units, then commit the smallest covering budget and sign again.
    pub fn build(&self, spec: &TxSpec) -> Built {
        self.build_with_payload(spec, &[])
    }

    /// [`Kit::build`] with a transaction payload (signed over, counted in
    /// the masses). The contracts never read the payload.
    pub fn build_with_payload(&self, spec: &TxSpec, payload: &[u8]) -> Built {
        let entries: Vec<UtxoEntry> = spec.inputs.iter().map(|i| i.utxo.entry.clone()).collect();
        let provisional = vec![FALLBACK_BUDGET; spec.inputs.len()];
        let tx = self.assemble(spec, &provisional, payload);
        let mut budgets = Vec::with_capacity(spec.inputs.len());
        let mut used = Vec::with_capacity(spec.inputs.len());
        for i in 0..spec.inputs.len() {
            match run_input(&tx, &entries, i, None) {
                Ok(units) => {
                    budgets.push(ComputeBudget::checked_covering_script_units(units).expect("budget fits u16").0);
                    used.push(Some(units.0));
                }
                Err(_) => {
                    budgets.push(FALLBACK_BUDGET);
                    used.push(None);
                }
            }
        }
        let tx = self.assemble(spec, &budgets, payload);
        Built { tx, entries, budgets, used_units: used }
    }

    fn assemble(&self, spec: &TxSpec, budgets: &[u16], payload: &[u8]) -> Transaction {
        let inputs = spec
            .inputs
            .iter()
            .zip(budgets)
            .map(|(i, b)| TransactionInput::new_with_compute_budget(i.utxo.outpoint, vec![], i.sequence, *b))
            .collect();
        let mut tx = Transaction::new(1, inputs, spec.outputs.clone(), spec.lock_time, SUBNETWORK_ID_NATIVE, 0, payload.to_vec());
        let entries: Vec<UtxoEntry> = spec.inputs.iter().map(|i| i.utxo.entry.clone()).collect();

        // storage mass commitment (KIP-9), independent of signature scripts
        if let Some(m) = self.mass_calculator.calc_contextual_masses(&PopulatedTransaction::new(&tx, entries.clone())) {
            tx.set_storage_mass(m.storage_mass);
        }

        let mtx = MutableTransaction::with_entries(tx.clone(), entries.clone());
        let reused = SigHashReusedValuesUnsync::new();
        let sign_with = |idx: usize, kp: &Keypair, t: SigHashType| -> Vec<u8> {
            let h = calc_schnorr_signature_hash(&mtx.as_verifiable(), idx, t, &reused);
            let msg = secp256k1::Message::from_digest_slice(h.as_bytes().as_slice()).unwrap();
            let mut s = kp.sign_schnorr(msg).as_ref().to_vec();
            s.push(t.to_u8());
            s
        };
        let sign = |idx: usize, kp: &Keypair| sign_with(idx, kp, SIG_HASH_ALL);
        for (idx, input) in spec.inputs.iter().enumerate() {
            let script = match &input.unlock {
                Unlock::P2pk(kp) => push(&sign(idx, kp)),
                Unlock::Commit { redeem, key } => [push(&sign(idx, key)), push(redeem)].concat(),
                Unlock::Contract { tpl, redeem, entry, args } => {
                    let args: Vec<ArtifactValue> = args
                        .iter()
                        .map(|a| match a {
                            Arg::V(v) => v.clone(),
                            Arg::Sig(kp) => ArtifactValue::Bytes(sign(idx, kp)),
                            Arg::SigWithType(kp, t) => {
                                ArtifactValue::Bytes(sign_with(idx, kp, SigHashType::from_u8(*t).expect("valid sighash type")))
                            }
                        })
                        .collect();
                    tpl.sig_script(redeem, entry, &args)
                }
                Unlock::Raw(s) => s.clone(),
            };
            tx.inputs[idx].signature_script = script;
        }
        tx.finalize();
        tx
    }

    // -- validating --------------------------------------------------------

    /// Full consensus validation of the transaction in a block with DAA score
    /// `block.daa` (also the UTXO-context point of view) and past median time
    /// `block.time_ms`. Returns the fee.
    pub fn validate(&self, built: &Built, block: Block) -> Result<u64, String> {
        let tx = &built.tx;
        self.validator.validate_tx_in_isolation(tx).map_err(|e| format!("isolation: {e}"))?;
        check_tx_is_finalized(tx, block).map_err(|e| format!("header: {e}"))?;
        let populated = PopulatedTransaction::new(tx, built.entries.clone());
        self.validator
            .validate_populated_transaction_and_get_fee(&populated, block.daa, block.daa, TxValidationFlags::Full, None, None)
            .map_err(|e| format!("utxo: {e}"))
    }

    pub fn costs(&self, built: &Built) -> Costs {
        let tx = &built.tx;
        let nc = self.mass_calculator.calc_non_contextual_masses(tx);
        let cof = self.consensus.mempool_block_mass_limits().raw_post().cofactors();
        let norm_transient = nc.normalized_transient(&cof);
        let fee_mass = nc.compute_mass.max(norm_transient);
        Costs {
            size: kaspa_consensus_core::mass::transaction_estimated_serialized_size(tx),
            compute_mass: nc.compute_mass,
            transient_mass: nc.transient_mass,
            normalized_transient: norm_transient,
            storage_mass: tx.storage_mass(),
            min_fee: fee_mass * MIN_RELAY_FEE_SOMPI_PER_KG / 1000,
            budgets: built.budgets.clone(),
            used_units: built.used_units.clone(),
        }
    }
}

impl Default for Kit {
    fn default() -> Self {
        Self::new()
    }
}

/// The block a transaction is validated in.
#[derive(Clone, Copy, Debug)]
pub struct Block {
    pub daa: u64,
    /// past median time, unix ms
    pub time_ms: u64,
}

/// The genesis transaction: `funding` (an ordinary P2PK UTXO of `deployer`)
/// creates the lone genesis gap `(genesisLo, genesisHi) = (00..00, ff..ff)`
/// at output 0, bound to `covenant_id(funding outpoint, [(0, gap)])`, plus
/// the given unbound outputs (change). Nothing else is authorized.
/// Returns the spec and the registry covenant id.
pub fn genesis_spec(
    params: &NetParams,
    gap: &Template,
    funding: Utxo,
    deployer: Keypair,
    unbound: Vec<TransactionOutput>,
) -> (TxSpec, Hash) {
    let gap_out = TransactionOutput::new(params.gap_value, gap.spk(&gap_state(&ZERO32, &FF32)));
    let registry_id = covenant_id(funding.outpoint, [(0u32, &gap_out)].into_iter());
    let mut out = gap_out;
    out.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: registry_id });
    assert!(unbound.iter().all(|o| o.covenant.is_none()), "genesis authorizes only the gap");
    let mut outputs = vec![out];
    outputs.extend(unbound);
    (TxSpec { inputs: vec![Input::new(funding, Unlock::P2pk(deployer))], outputs, lock_time: 0 }, registry_id)
}

/// The five tiers as constructor arguments.
fn tier_args(prices: &[u64; 5]) -> Vec<ArtifactValue> {
    prices.iter().map(|p| ArtifactValue::Int(*p as i64)).collect()
}

/// Compile KachatName with the params' renew table (what scripts/build.py does).
pub fn compile_name_in(root: &Path, params: &NetParams) -> Template {
    let src = std::fs::read_to_string(root.join("contracts/KachatName.sil")).unwrap();
    compile_source(&src, &name_args(params))
}

/// KachatName's constructor arguments, in declaration order.
pub fn name_args(params: &NetParams) -> Vec<ArtifactValue> {
    let mut args = vec![
        ArtifactValue::Bytes(ZERO32.to_vec()),
        ArtifactValue::Bytes(ZERO32.to_vec()),
        ArtifactValue::Bytes(ZERO32.to_vec()),
        ArtifactValue::Int(0),
        ArtifactValue::Int(0),
        ArtifactValue::Int(0),
        ArtifactValue::Int(params.bond as i64),
        ArtifactValue::Int(params.max_years),
        ArtifactValue::Int(params.grace_ms),
        ArtifactValue::Int(params.renew_window_ms),
        ArtifactValue::Int(params.period_ms),
    ];
    args.extend(tier_args(&params.renew_prices));
    args
}

/// Compile KachatGap for `name` with the params' register and renew tables.
pub fn compile_gap_in(root: &Path, params: &NetParams, name: &Template) -> Template {
    let src = std::fs::read_to_string(root.join("contracts/KachatGap.sil")).unwrap();
    compile_source(&src, &gap_args(params, name))
}

/// KachatGap's constructor arguments, in declaration order.
pub fn gap_args(params: &NetParams, name: &Template) -> Vec<ArtifactValue> {
    let mut args = vec![
        ArtifactValue::Bytes(ZERO32.to_vec()),
        ArtifactValue::Bytes(FF32.to_vec()),
        ArtifactValue::Bytes(name.template_hash.to_vec()),
        ArtifactValue::Int(name.prefix.len() as i64),
        ArtifactValue::Int(name.suffix.len() as i64),
        ArtifactValue::Int(params.bond as i64),
        ArtifactValue::Int(params.gap_value as i64),
        ArtifactValue::Int(params.t_commit as i64),
        ArtifactValue::Int(params.max_years),
        ArtifactValue::Int(params.period_ms),
    ];
    args.extend(tier_args(&params.register_prices));
    args.extend(tier_args(&params.renew_prices));
    args
}

/// Compile KachatOffer for `registry_id` with the pinned compiler library
/// (the same commit scripts/build.sh uses).
pub fn compile_offer(params: &NetParams, name: &Template, registry_id: Hash) -> Template {
    compile_offer_in(&repo_root(), params, name, registry_id)
}

/// [`compile_offer`] reading `contracts/KachatOffer.sil` under `root`.
pub fn compile_offer_in(root: &Path, params: &NetParams, name: &Template, registry_id: Hash) -> Template {
    let src = std::fs::read_to_string(root.join("contracts/KachatOffer.sil")).unwrap();
    compile_source(&src, &offer_args(params, name, registry_id))
}

/// KachatOffer's constructor arguments, in declaration order.
pub fn offer_args(params: &NetParams, name: &Template, registry_id: Hash) -> Vec<ArtifactValue> {
    vec![
        ArtifactValue::Bytes(ZERO32.to_vec()),
        ArtifactValue::Bytes(ZERO32.to_vec()),
        ArtifactValue::Bytes(ZERO32.to_vec()),
        ArtifactValue::Int(0),
        ArtifactValue::Bytes(registry_id.as_bytes().to_vec()),
        ArtifactValue::Bytes(name.template_hash.to_vec()),
        ArtifactValue::Int(name.prefix.len() as i64),
        ArtifactValue::Int(name.suffix.len() as i64),
        ArtifactValue::Int(params.offer_max_fee as i64),
    ]
}

pub fn compile_source(src: &str, args: &[ArtifactValue]) -> Template {
    let abi = silverscript_lang::compiler::compile_to_sil_abi_artifact_with_options(src, args, Default::default()).expect("compile");
    Template::from_artifact(abi)
}

/// rusty-kaspa `TransactionValidator::check_tx_is_finalized`
/// (consensus/src/processes/transaction_validator/tx_validation_in_header_context.rs:72),
/// crate-private upstream, reproduced verbatim: a lock time below
/// LOCK_TIME_THRESHOLD is compared with the block DAA score, above it with the
/// block's past median time; a transaction whose lock time has not passed is
/// valid only if every input sequence is u64::MAX.
pub fn check_tx_is_finalized(tx: &Transaction, block: Block) -> Result<(), String> {
    if tx.lock_time == 0 {
        return Ok(());
    }
    let reference = if tx.lock_time < LOCK_TIME_THRESHOLD { block.daa } else { block.time_ms };
    if tx.lock_time < reference {
        return Ok(());
    }
    for (i, input) in tx.inputs.iter().enumerate() {
        if input.sequence != u64::MAX {
            return Err(format!("transaction input {i} is not finalized"));
        }
    }
    Ok(())
}

/// Execute one input's script with the consensus flags. `limit` = None runs
/// unmetered (used to measure); Some(limit) enforces a script-unit limit.
pub fn run_input(tx: &Transaction, entries: &[UtxoEntry], idx: usize, limit: Option<ScriptUnits>) -> Result<ScriptUnits, TxScriptError> {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
    let reused = SigHashReusedValuesUnsync::new();
    let cache = Cache::new(10_000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(MAINNET_PARAMS.mass_per_sig_op).into() };
    let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        &tx.inputs[idx],
        idx,
        &entries[idx],
        EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov_ctx),
        flags,
        limit.unwrap_or(ScriptUnits(u64::MAX)),
    );
    vm.execute()?;
    Ok(vm.used_script_units())
}

// ---------------------------------------------------------------------------
// Transaction specs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Utxo {
    pub outpoint: TransactionOutpoint,
    pub entry: UtxoEntry,
}

impl Utxo {
    pub fn new(outpoint: TransactionOutpoint, entry: UtxoEntry) -> Self {
        Utxo { outpoint, entry }
    }

    pub fn with_daa(mut self, daa: u64) -> Self {
        self.entry.block_daa_score = daa;
        self
    }
}

#[derive(Clone)]
pub enum Arg {
    V(ArtifactValue),
    /// A SIGHASH_ALL schnorr signature by this key over the input it sits in.
    Sig(Keypair),
    /// A valid schnorr signature by this key with another sighash type
    /// (e.g. 0x81 = ALL|ANYONECANPAY, 0x02 = NONE).
    SigWithType(Keypair, u8),
}

pub fn bytes(b: &[u8]) -> Arg {
    Arg::V(ArtifactValue::Bytes(b.to_vec()))
}

pub fn int(v: i64) -> Arg {
    Arg::V(ArtifactValue::Int(v))
}

#[derive(Clone)]
pub enum Unlock {
    P2pk(Keypair),
    Commit { redeem: Vec<u8>, key: Keypair },
    Contract { tpl: Arc<Template>, redeem: Vec<u8>, entry: String, args: Vec<Arg> },
    Raw(Vec<u8>),
}

#[derive(Clone)]
pub struct Input {
    pub utxo: Utxo,
    pub sequence: u64,
    pub unlock: Unlock,
}

impl Input {
    pub fn new(utxo: Utxo, unlock: Unlock) -> Self {
        Input { utxo, sequence: 0, unlock }
    }

    pub fn contract(utxo: Utxo, tpl: &Arc<Template>, state: Vec<u8>, entry: &str, args: Vec<Arg>) -> Self {
        let redeem = tpl.redeem(&state);
        Input::new(utxo, Unlock::Contract { tpl: tpl.clone(), redeem, entry: entry.to_string(), args })
    }

    pub fn args_mut(&mut self) -> &mut Vec<Arg> {
        match &mut self.unlock {
            Unlock::Contract { args, .. } => args,
            _ => panic!("not a contract input"),
        }
    }

    pub fn set_entry(&mut self, name: &str, new_args: Vec<Arg>) {
        match &mut self.unlock {
            Unlock::Contract { entry, args, .. } => {
                *entry = name.to_string();
                *args = new_args;
            }
            _ => panic!("not a contract input"),
        }
    }
}

#[derive(Clone)]
pub struct TxSpec {
    pub inputs: Vec<Input>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u64,
}

impl TxSpec {
    pub fn total_in(&self) -> u64 {
        self.inputs.iter().map(|i| i.utxo.entry.amount).sum()
    }

    pub fn total_out(&self) -> u64 {
        self.outputs.iter().map(|o| o.value).sum()
    }

    pub fn fee(&self) -> i64 {
        self.total_in() as i64 - self.total_out() as i64
    }
}

pub struct Built {
    pub tx: Transaction,
    pub entries: Vec<UtxoEntry>,
    pub budgets: Vec<u16>,
    /// script units used by each input when it executed successfully
    pub used_units: Vec<Option<u64>>,
}

impl Built {
    /// Run every input under its committed budget; returns per-input results.
    pub fn run_inputs(&self) -> Vec<Result<ScriptUnits, TxScriptError>> {
        (0..self.tx.inputs.len())
            .map(|i| run_input(&self.tx, &self.entries, i, Some(self.tx.inputs[i].compute_commit.allowed_script_units())))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Costs {
    pub size: u64,
    pub compute_mass: u64,
    pub transient_mass: u64,
    pub normalized_transient: u64,
    pub storage_mass: u64,
    /// 100 sompi/gram over max(compute, normalized transient)
    pub min_fee: u64,
    pub budgets: Vec<u16>,
    pub used_units: Vec<Option<u64>>,
}

// ---------------------------------------------------------------------------
// Typed states
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameFields {
    pub key: [u8; 32],
    pub name: [u8; 32],
    pub owner: [u8; 32],
    pub price: i64,
    /// start of the current paid period, unix ms
    pub period_start: i64,
    pub expires_at: i64,
}

impl NameFields {
    pub fn new(name: &[u8], owner: &[u8; 32], price: i64, period_start: i64, expires_at: i64) -> Self {
        NameFields { key: name_key(name), name: pad_name(name), owner: *owner, price, period_start, expires_at }
    }

    pub fn encode(&self) -> Vec<u8> {
        name_state(&self.key, &self.name, &self.owner, self.price, self.period_start, self.expires_at)
    }

    pub fn with_owner(&self, owner: &[u8; 32]) -> Self {
        NameFields { owner: *owner, price: 0, ..self.clone() }
    }

    pub fn with_price(&self, price: i64) -> Self {
        NameFields { price, ..self.clone() }
    }

    /// The expiry moves, the period start stays (what extend does).
    pub fn with_expiry(&self, expires_at: i64) -> Self {
        NameFields { expires_at, ..self.clone() }
    }

    pub fn with_period(&self, period_start: i64, expires_at: i64) -> Self {
        NameFields { period_start, expires_at, ..self.clone() }
    }

    /// What `extend(years)` leaves: same period start, expiry + years periods.
    pub fn extended(&self, years: i64, period_ms: i64) -> Self {
        self.with_expiry(self.expires_at + years * period_ms)
    }

    /// What `renew(years)` leaves: a new period from the old expiry.
    pub fn renewed(&self, years: i64, period_ms: i64) -> Self {
        self.with_period(self.expires_at, self.expires_at + years * period_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferFields {
    pub key: [u8; 32],
    pub buyer: [u8; 32],
    /// the name's owner the offer was made to (registry v3)
    pub seller: [u8; 32],
    pub refund_after: i64,
}

impl OfferFields {
    pub fn encode(&self) -> Vec<u8> {
        offer_state(&self.key, &self.buyer, &self.seller, self.refund_after)
    }
}
