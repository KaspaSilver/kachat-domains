//! The end-to-end testnet plan, and an in-process simulator that runs the
//! same plan through the same builders against synthetic UTXOs (every
//! transaction validated by the consensus validator, every output fed to the
//! next step), which is also how `e2e-plan` computes the TKAS needed.

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail, ensure};
use kachat_names_harness::{Block, Kit, TransactionId, TransactionOutpoint, Utxo, UtxoEntry, keypair, name_key, p2pk_spk, xonly};
use secp256k1::Keypair;

use crate::{
    commits::CommitRec,
    ops::{self, Env, ExitParts, Plan, Templates},
    registry::{PriceRec, Registry, TxView},
    util::{SOMPI, fmt_kas},
};

/// The funding the deployer is planned to receive.
pub const PLANNED_FUNDING: u64 = 100 * SOMPI;

#[derive(Clone, Debug)]
pub enum Step {
    /// the price record first (registry v3): K shards, the deployer as the authority
    PriceGenesis,
    Genesis,
    /// the authority sets every price to genesis x `num` / `den`
    SetPrices(u64, u64),
    Commit(&'static str),
    /// wait this many DAA (commit maturity, offer refundAfter)
    Wait(u64, &'static str),
    Register { name: &'static str, years: i64, backdate_minutes: i64 },
    Extend(&'static str, i64),
    Renew(&'static str, i64),
    /// transfer to the deployer's own address (the only key this tool holds)
    TransferToSelf(&'static str),
    List(&'static str, u64),
    Buy(&'static str),
    /// name, amount, refundAfter relative to the virtual DAA
    Offer(&'static str, u64, u64),
    Accept(&'static str),
    Decline(&'static str),
    Refund(&'static str),
    Withdraw(&'static str),
    Release(&'static str),
    Reclaim(&'static str),
}

pub const A: &str = "alpha-tn";
pub const B: &str = "bravo-tn";
pub const L: &str = "lapse-tn";

/// On the testnet short clock (10-minute periods, 10-minute grace), backdating
/// `now` by 45 minutes makes a 1-period name expire 35 minutes ago: its renewal
/// window is long open, so `renew` (a new period from the old expiry) runs at
/// once and leaves it expired 25 minutes ago, past expiresAt + grace, so
/// `reclaim` is valid at once. The gap only proves `now` is not in the future,
/// so a backdated registration is valid (it pays for periods already over).
pub const LAPSE_BACKDATE_MINUTES: i64 = 45;

pub fn e2e_steps() -> Vec<(Step, &'static str)> {
    use Step::*;
    vec![
        (PriceGenesis, "mints the price covenant: 8 shards with the genesis prices, the deployer as the authority"),
        (Genesis, "mints the registry id (baking the price covenant): one gap (00..00, ff..ff), nothing else authorized"),
        (Commit(A), "salted commit: name hidden, only P2SH(commitment, owner) is public"),
        (Commit(B), "second commit"),
        (Commit(L), "third commit (for the reclaim scenario)"),
        (Wait(600, "commit maturity: tCommit = 600 DAA (~1 min)"), "consensus sequence lock on input 1"),
        (Register { name: A, years: 1, backdate_minutes: 0 }, "register 1 period (0.35 TKAS miner fee, read from a price shard); time-locked tx (lockTime = now) is final"),
        (Register { name: B, years: 2, backdate_minutes: 0 }, "register 2 periods (0.7 TKAS) in the gap the first name left"),
        (Register { name: L, years: 1, backdate_minutes: LAPSE_BACKDATE_MINUTES }, "backdated register: lapsed 35 minutes ago"),
        (SetPrices(2, 1), "the authority doubles every price at once (all 8 shards in one transaction)"),
        (Extend(A, 1), "anyone extends: 1 -> 2 periods (the most a name holds), periodStart kept, at the new price 0.7 TKAS"),
        (Renew(L, 1), "anyone renews after lapse: timestamp lock time past expiresAt - 10 min; new period from the old expiry, still lapsed"),
        (SetPrices(1, 1), "the authority sets the prices back (decreases are instant too)"),
        (TransferToSelf(A), "owner-signed transfer, continuation keeps bond, periodStart and expiry"),
        (List(A, 50 * SOMPI), "owner lists at 50 TKAS"),
        (Buy(A), "anyone buys: payout output right after the continuation; listing cleared"),
        (Offer(B, 10 * SOMPI, 100_000), "offer 10 TKAS on bravo-tn, refundable after ~3 h"),
        (Accept(B), "the seller accepts: transfer(buyer) + offer.accept(0, sellerSig), fee taken from the offer (<= maxFee)"),
        (Offer(A, 4 * SOMPI, 100_000), "offer 4 TKAS on alpha-tn"),
        (Decline(A), "the seller declines: the offer goes straight back to the buyer (1 in / 1 out)"),
        (Offer(A, 5 * SOMPI, 600), "offer 5 TKAS on alpha-tn, refundable after 600 DAA (~1 min)"),
        (Wait(601, "offer refundAfter (600 DAA)"), "DAA lock time must pass"),
        (Refund(A), "anyone refunds: DAA lock time = refundAfter, 1 in / 1 out"),
        (Offer(A, 3 * SOMPI, 100_000), "offer 3 TKAS on alpha-tn"),
        (Withdraw(A), "buyer withdraws (SIGHASH_ALL signature)"),
        (Release(B), "owner exit: merge + release + absorbed; bond and a gap value come back"),
        (Reclaim(L), "permissionless exit after grace: bond to the last owner at output 1, bounty to the caller"),
    ]
}

/// The CLI command for a step (`me` = the deployer's address).
pub fn command(step: &Step, me: &str) -> String {
    let c = "kachat-names";
    match step {
        Step::PriceGenesis => format!("{c} price-genesis --submit"),
        Step::Genesis => format!("{c} genesis --submit"),
        Step::SetPrices(num, den) => format!("{c} set-prices --times {num}/{den} --submit"),
        Step::Commit(n) => format!("{c} commit {n} --submit"),
        Step::Wait(d, why) => format!("# wait {d} DAA (~{} s): {why}", d.div_ceil(10)),
        Step::Register { name, years, backdate_minutes: 0 } => format!("{c} register {name} --years {years} --submit"),
        Step::Register { name, years, backdate_minutes } => {
            format!("{c} register {name} --years {years} --backdate-minutes {backdate_minutes} --submit")
        }
        Step::Extend(n, y) => format!("{c} extend {n} --years {y} --submit"),
        Step::Renew(n, y) => format!("{c} renew {n} --years {y} --submit"),
        Step::TransferToSelf(n) => format!("{c} transfer {n} {me} --submit"),
        Step::List(n, p) => format!("{c} list {n} {} --submit", p / SOMPI),
        Step::Buy(n) => format!("{c} buy {n} --submit"),
        Step::Offer(n, a, r) => format!("{c} offer {n} {} --refund-after +{r} --submit", a / SOMPI),
        Step::Accept(n) => format!("{c} accept-offer {n} --submit"),
        Step::Decline(n) => format!("{c} decline-offer {n} --submit"),
        Step::Refund(n) => format!("{c} refund-offer {n} --submit"),
        Step::Withdraw(n) => format!("{c} withdraw-offer {n} --submit"),
        Step::Release(n) => format!("{c} release {n} --submit"),
        Step::Reclaim(n) => format!("{c} reclaim {n} --submit"),
    }
}

// ---------------------------------------------------------------------------
// simulator
// ---------------------------------------------------------------------------

pub struct Sim {
    pub templates: Templates,
    pub deployer: Keypair,
    pub kit: Option<Kit>,
    pub reg: Option<Registry>,
    /// the price covenant and its shards from the price genesis (until the registry exists)
    pub price_id: Option<kachat_names_harness::Hash>,
    pub genesis_shards: Vec<PriceRec>,
    /// which shard the next paid operation reads (round robin)
    next_shard: usize,
    pub wallet: Vec<Utxo>,
    /// every output the simulation created, by outpoint (the "UTXO index")
    pub utxos: HashMap<TransactionOutpoint, UtxoEntry>,
    pub commits: Vec<CommitRec>,
    pub block: Block,
    pub wall_ms: i64,
    pub funding: u64,
    /// most the plan ever drew from the wallet above what it had spent so far
    pub peak_need: u64,
    pub plans: Vec<Plan>,
    salt_counter: u8,
}

impl Sim {
    pub fn new(templates: Templates, funding: u64, wall_ms: i64) -> Sim {
        let deployer = keypair(77);
        let daa = 590_000_000;
        let u = Utxo::new(
            TransactionOutpoint::new(TransactionId::from_bytes([0xab; 32]), 0),
            UtxoEntry::new(funding, p2pk_spk(&xonly(&deployer)), daa, false, None),
        );
        let mut utxos = HashMap::new();
        utxos.insert(u.outpoint, u.entry.clone());
        Sim {
            templates,
            deployer,
            kit: None,
            reg: None,
            price_id: None,
            genesis_shards: vec![],
            next_shard: 0,
            wallet: vec![u],
            utxos,
            commits: vec![],
            // the virtual's median time lags the wall clock by ~2.2 min
            block: Block { daa: daa + 10, time_ms: (wall_ms - 132_000) as u64 },
            wall_ms,
            funding,
            peak_need: 0,
            plans: vec![],
            salt_counter: 0,
        }
    }

    pub fn balance(&self) -> u64 {
        self.wallet.iter().map(|u| u.entry.amount).sum()
    }

    fn env(&self) -> Result<Env> {
        let kit = self.kit.as_ref().ok_or_else(|| anyhow!("no genesis yet"))?;
        // rebuild a kit handle cheaply: Env owns a Kit, so reuse the templates
        Ok(Env {
            kit: self.templates.kit(kit.price_id, kit.registry_id)?,
            deployer: self.deployer,
            block: self.block,
            wall_ms: self.wall_ms,
            feerate: ops::MIN_FEERATE,
        })
    }

    fn live(&self, op: &TransactionOutpoint) -> Result<Utxo> {
        let e = self.utxos.get(op).ok_or_else(|| anyhow!("simulated UTXO {op} missing"))?;
        Ok(Utxo::new(*op, e.clone()))
    }

    fn advance(&mut self, daa: u64) {
        self.block.daa += daa;
        self.block.time_ms += daa * 100;
        self.wall_ms += (daa * 100) as i64;
    }

    /// Accept a valid plan: spend its inputs, create its outputs, update the
    /// registry, the wallet and the commit store.
    fn accept(&mut self, plan: Plan) -> Result<()> {
        if let Err(e) = &plan.validation {
            bail!("{}: rejected by the local validator: {e}", plan.op);
        }
        if let Err(e) = &plan.standard {
            bail!("{}: non-standard: {e}", plan.op);
        }
        let tx = &plan.built.tx;
        let before = self.balance();
        let me = p2pk_spk(&xonly(&self.deployer));
        let spent: Vec<TransactionOutpoint> = tx.inputs.iter().map(|i| i.previous_outpoint).collect();
        let drawn: u64 = self.wallet.iter().filter(|u| spent.contains(&u.outpoint)).map(|u| u.entry.amount).sum();
        let change: u64 = tx
            .outputs
            .iter()
            .zip(&plan.output_labels)
            .filter(|(o, l)| o.script_public_key == me && l.starts_with("change"))
            .map(|(o, _)| o.value)
            .sum();
        // the wallet must hold what was already spent plus what this step
        // takes from it (payouts that come straight back included), plus room
        // for a change output
        if drawn > 0 {
            let need = (self.funding - before) + drawn.saturating_sub(change) + ops::MIN_CHANGE;
            self.peak_need = self.peak_need.max(need);
        }
        for op in &spent {
            self.utxos.remove(op);
        }
        self.wallet.retain(|u| !spent.contains(&u.outpoint));
        self.advance(10);
        let id = tx.id();
        for (i, o) in tx.outputs.iter().enumerate() {
            let op = TransactionOutpoint::new(id, i as u32);
            let e = UtxoEntry::new(o.value, o.script_public_key.clone(), self.block.daa, false, o.covenant.map(|c| c.covenant_id));
            self.utxos.insert(op, e.clone());
            if o.script_public_key == me {
                self.wallet.push(Utxo::new(op, e));
            }
        }
        if let Some(pid) = plan.price_id {
            let p = &self.templates.params;
            self.price_id = Some(pid);
            self.genesis_shards = Registry::genesis_shards(tx.id(), p.price_shards, &xonly(&self.deployer), &p.prices, p.price_value);
        } else if let Some(id) = plan.registry_id {
            let pid = self.price_id.ok_or_else(|| anyhow!("registry genesis before the price genesis"))?;
            let kit = self.templates.kit(pid, id)?;
            let price_genesis = self.genesis_shards[0].outpoint.transaction_id;
            self.reg = Some(Registry::at_genesis(id, tx.id(), kit.params.gap_value, None, pid, price_genesis, self.genesis_shards.clone()));
            self.kit = Some(kit);
        } else {
            let kit = self.kit.as_ref().unwrap();
            let reg = self.reg.as_mut().unwrap();
            reg.apply(kit, &TxView::from(tx))?;
            reg.check_invariants()?;
        }
        if let (Some(o), Some(reg)) = (&plan.new_offer, self.reg.as_mut()) {
            reg.track_offer(o.clone());
        }
        if let Some(c) = &plan.new_commit {
            self.commits.push(c.clone());
        }
        // a register spends a commit
        for c in self.commits.iter_mut() {
            if c.outpoint.is_some_and(|o| spent.contains(&o)) {
                c.used_by = Some(id.to_string());
            }
        }
        self.plans.push(plan);
        Ok(())
    }

    /// The shard the next paid operation will read (without moving on).
    pub fn peek_shard(&self) -> Option<PriceRec> {
        let reg = self.reg.as_ref()?;
        let mut shards = reg.shards.clone();
        shards.sort_by_key(|s| s.shard);
        shards.get(self.next_shard % shards.len().max(1)).cloned()
    }

    /// The next price shard (round robin) and its live UTXO.
    fn shard(&mut self) -> Result<(PriceRec, Utxo)> {
        let reg = self.reg.as_ref().ok_or_else(|| anyhow!("no registry"))?;
        let mut shards = reg.shards.clone();
        shards.sort_by_key(|s| s.shard);
        let s = shards.get(self.next_shard % shards.len().max(1)).cloned().ok_or_else(|| anyhow!("no price shards"))?;
        self.next_shard += 1;
        let u = self.live(&s.outpoint)?;
        Ok((s, u))
    }

    pub fn run(&mut self, step: &Step) -> Result<()> {
        let me = xonly(&self.deployer);
        let plan = match step {
            Step::PriceGenesis => {
                let (plan, _) = ops::price_genesis(&self.templates, self.deployer, &me, &self.wallet, self.block, self.wall_ms, ops::MIN_FEERATE)?;
                plan
            }
            Step::Genesis => {
                let pid = self.price_id.ok_or_else(|| anyhow!("no price genesis yet"))?;
                let (plan, _) = ops::genesis(&self.templates, pid, self.deployer, &self.wallet, self.block, self.wall_ms, ops::MIN_FEERATE)?;
                plan
            }
            Step::SetPrices(num, den) => {
                let reg = self.reg.as_ref().ok_or_else(|| anyhow!("no registry"))?;
                let shards: Vec<(PriceRec, Utxo)> = reg.shards.iter().map(|s| Ok((s.clone(), self.live(&s.outpoint)?))).collect::<Result<_>>()?;
                let prices = self.templates.params.prices.map(|p| p * num / den);
                ops::price_update(&self.env()?, &self.wallet, &shards, self.deployer, &me, &prices)?
            }
            Step::Wait(d, _) => {
                self.advance(*d);
                return Ok(());
            }
            Step::Commit(n) => {
                self.salt_counter += 1;
                ops::commit(&self.env()?, &self.wallet, n, [self.salt_counter; 32])?
            }
            Step::Register { name, years, backdate_minutes } => {
                let env = self.env()?;
                let (s, su) = self.shard()?;
                let reg = self.reg.as_ref().unwrap();
                let c = crate::commits::find_open(&self.commits, name, &me).ok_or_else(|| anyhow!("no commit for {name}"))?.clone();
                let gap = reg.gap_for_key(&name_key(name.as_bytes())).ok_or_else(|| anyhow!("no gap for {name}"))?.clone();
                let now = ops::register_now(&env) - backdate_minutes * 60_000;
                ops::register(&env, &self.wallet, &gap, &self.live(&gap.outpoint)?, &c, &self.live(&c.outpoint.unwrap())?, &s, &su, *years, now)?
            }
            Step::Extend(n, y) => {
                let (s, su) = self.shard()?;
                let rec = self.reg.as_ref().unwrap().name(n).ok_or_else(|| anyhow!("{n} not registered"))?.clone();
                ops::extend(&self.env()?, &self.wallet, &rec, &self.live(&rec.outpoint)?, &s, &su, *y)?
            }
            Step::Renew(n, y) => {
                let (s, su) = self.shard()?;
                let rec = self.reg.as_ref().unwrap().name(n).ok_or_else(|| anyhow!("{n} not registered"))?.clone();
                ops::renew(&self.env()?, &self.wallet, &rec, &self.live(&rec.outpoint)?, &s, &su, *y)?
            }
            Step::TransferToSelf(n) => {
                let rec = self.reg.as_ref().unwrap().name(n).ok_or_else(|| anyhow!("{n} not registered"))?.clone();
                ops::transfer(&self.env()?, &self.wallet, &rec, &self.live(&rec.outpoint)?, &me)?
            }
            Step::List(n, p) => {
                let rec = self.reg.as_ref().unwrap().name(n).ok_or_else(|| anyhow!("{n} not registered"))?.clone();
                ops::list(&self.env()?, &self.wallet, &rec, &self.live(&rec.outpoint)?, *p)?
            }
            Step::Buy(n) => {
                let rec = self.reg.as_ref().unwrap().name(n).ok_or_else(|| anyhow!("{n} not registered"))?.clone();
                ops::buy(&self.env()?, &self.wallet, &rec, &self.live(&rec.outpoint)?)?
            }
            Step::Offer(n, a, r) => {
                let target = self.reg.as_ref().unwrap().name(n).cloned().ok_or_else(|| anyhow!("{n} not registered"))?;
                ops::offer(&self.env()?, &self.wallet, n, *a, self.block.daa + r, &target)?
            }
            Step::Accept(n) | Step::Decline(n) | Step::Refund(n) | Step::Withdraw(n) => {
                let reg = self.reg.as_ref().unwrap();
                let key = name_key(n.as_bytes());
                let o = reg.offers_for(&key).last().cloned().ok_or_else(|| anyhow!("no offer on {n}"))?.clone();
                let ou = self.live(&o.outpoint)?;
                let env = self.env()?;
                match step {
                    Step::Accept(_) => {
                        let rec = reg.name(n).ok_or_else(|| anyhow!("{n} not registered"))?.clone();
                        ops::accept_offer(&env, &rec, &self.live(&rec.outpoint)?, &o, &ou)?
                    }
                    Step::Decline(_) => ops::decline_offer(&env, &o, &ou)?,
                    Step::Refund(_) => ops::refund_offer(&env, &o, &ou)?,
                    _ => ops::withdraw_offer(&env, &o, &ou)?,
                }
            }
            Step::Release(n) | Step::Reclaim(n) => {
                let reg = self.reg.as_ref().unwrap();
                let rec = reg.name(n).ok_or_else(|| anyhow!("{n} not registered"))?.clone();
                let (below, above) = reg.neighbours(&rec.fields.key).ok_or_else(|| anyhow!("no gaps around {n}"))?;
                let (below, above) = (below.clone(), above.clone());
                let (bu, nu, au) = (self.live(&below.outpoint)?, self.live(&rec.outpoint)?, self.live(&above.outpoint)?);
                let x = ExitParts { below: &below, below_utxo: &bu, name: &rec, name_utxo: &nu, above: &above, above_utxo: &au };
                let env = self.env()?;
                if matches!(step, Step::Release(_)) { ops::release(&env, x)? } else { ops::reclaim(&env, x)? }
            }
        };
        self.accept(plan)
    }
}

pub struct Budget {
    pub funding: u64,
    pub final_balance: u64,
    pub prices: u64,
    pub network_fees: u64,
    pub locked_in_registry: u64,
    pub peak_need: u64,
    pub txs: usize,
}

/// Run the whole plan with `funding` TKAS.
pub fn simulate(templates: Templates, funding: u64, wall_ms: i64) -> Result<(Sim, Budget)> {
    let mut sim = Sim::new(templates, funding, wall_ms);
    for (step, _) in e2e_steps() {
        sim.run(&step).map_err(|e| anyhow!("step {:?}: {e}", step))?;
    }
    let reg = sim.reg.as_ref().unwrap();
    let locked = reg.gaps.iter().map(|g| g.value).sum::<u64>()
        + reg.names.iter().map(|n| n.value).sum::<u64>()
        + reg.shards.iter().map(|s| s.value).sum::<u64>();
    let prices: u64 = sim.plans.iter().map(|p| p.price_fee).sum();
    let network_fees: u64 = sim.plans.iter().map(|p| p.network_fee).sum();
    let final_balance = sim.balance();
    ensure!(final_balance + prices + network_fees + locked == funding, "simulation does not balance");
    let b = Budget { funding, final_balance, prices, network_fees, locked_in_registry: locked, peak_need: sim.peak_need, txs: sim.plans.len() };
    Ok((sim, b))
}

pub fn fmt_budget(b: &Budget) -> String {
    format!(
        "{} transactions; prices (miner fee) {}, network fees {}, left locked in the registry {} (price shards + gaps + names), \
         spent in total {}; the deployer ends with {} of {}",
        b.txs,
        fmt_kas(b.prices),
        fmt_kas(b.network_fees),
        fmt_kas(b.locked_in_registry),
        fmt_kas(b.funding - b.final_balance),
        fmt_kas(b.final_balance),
        fmt_kas(b.funding)
    )
}
