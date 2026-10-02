//! `kachat-names`: testnet-10 deployment CLI for the .kachat name covenants.
//!
//! Every spending command builds the exact transaction shape of the README,
//! validates it locally with rusty-kaspa's consensus TransactionValidator and
//! prints a dry-run summary. Only `--submit` broadcasts, and only to a node
//! that reports `testnet-10`. There is no mainnet mode.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Parser, Subcommand};
use kachat_names_cli::{
    commits::{self, CommitRec},
    keys, manifest,
    net::{NETWORK, consensus_params, p2pk_address, parse_owner_address, spk_address},
    node::{DagPoint, Node},
    ops::{self, Env, ExitParts, Plan, Templates},
    paths::Paths,
    plan::{self, PLANNED_FUNDING},
    registry::{GapRec, OfferRec, Registry, TxView},
    scan, summary,
    util::{SOMPI, fmt_kas, fmt_ms, fmt_outpoint, hex, now_ms, parse_kas, parse_outpoint},
};
use kachat_names_harness::{
    Block, Kit, TransactionId, TransactionOutpoint, Utxo, UtxoEntry, commit_redeem, commitment, gap_state, name_key, p2pk_spk, xonly,
};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_script_hash_script;
use secp256k1::Keypair;

#[derive(Parser)]
#[command(name = "kachat-names", about = "testnet-10 CLI for the .kachat name covenants (dry run unless --submit)")]
struct Cli {
    /// gRPC node, e.g. grpc://host:16210 (default: discover through the testnet-10 DNS seeders)
    #[arg(long, global = true)]
    node: Option<String>,
    /// kachat-domains checkout (default: found from the current directory)
    #[arg(long, global = true)]
    repo: Option<PathBuf>,
    /// broadcast the transaction (without it, nothing is ever sent)
    #[arg(long, global = true)]
    submit: bool,
    #[arg(long, short, global = true)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the deployer key (.secrets/testnet10-deployer.key, mode 600); prints only its address
    Keygen,
    /// Print the deployer's kaspatest: address
    Address,
    /// Connectivity report: GetInfo, network, DAG point, and the deployer's UTXOs (read-only)
    NodeInfo,
    /// UTXOs of the deployer address
    Balance,
    /// Mint the registry: one deployer UTXO -> the lone genesis gap (+ change)
    Genesis {
        /// dry run only: pretend the deployer holds one UTXO of this many TKAS (cannot be submitted)
        #[arg(long)]
        assume_utxo: Option<String>,
    },
    /// Salted commit for a name (salt kept in .secrets/commits.json)
    Commit { name: String },
    /// Register a committed name
    Register {
        name: String,
        #[arg(long, default_value_t = 1)]
        years: i64,
        /// move `now` this many days into the past (testing reclaim: 376 makes a 1-year name lapsed at once)
        #[arg(long, default_value_t = 0)]
        backdate_days: i64,
    },
    /// Renew a name (anyone may)
    Renew {
        name: String,
        #[arg(long, default_value_t = 1)]
        years: i64,
    },
    /// Transfer a name owned by the deployer to a kaspatest: Schnorr address
    Transfer { name: String, to: String },
    /// List a name for sale (price in TKAS; 0 delists)
    List { name: String, price: String },
    /// Buy a listed name for the deployer
    Buy { name: String },
    /// Lock TKAS as an offer for a name
    Offer {
        name: String,
        amount: String,
        /// DAA score from which anyone may refund; "+N" = N DAA after the current virtual
        #[arg(long)]
        refund_after: String,
    },
    /// Accept an offer on a name the deployer owns
    AcceptOffer {
        name: String,
        #[arg(long)]
        offer: Option<String>,
    },
    /// Withdraw the deployer's offer
    WithdrawOffer {
        name: String,
        #[arg(long)]
        offer: Option<String>,
    },
    /// Refund an offer after its refundAfter DAA (anyone may)
    RefundOffer {
        name: String,
        #[arg(long)]
        offer: Option<String>,
    },
    /// Owner exit: release a name (bond and a gap value come back)
    Release { name: String },
    /// Permissionless exit of a lapsed name (after expiresAt + grace)
    Reclaim { name: String },
    /// Walk the chain from the last checkpoint and apply every registry transaction
    Scan {
        /// start again from the manifest's genesis checkpoint
        #[arg(long)]
        from_genesis: bool,
        #[arg(long, default_value_t = 20)]
        min_confirmations: u64,
    },
    /// Decode the registry: gaps, names, offers, commits; check every tracked UTXO is live
    Status {
        /// run `scan` first
        #[arg(long)]
        scan: bool,
    },
    /// The ordered command list for a full testnet run, and the TKAS it needs
    E2ePlan {
        /// also print every simulated transaction (synthetic UTXOs, local validator)
        #[arg(long)]
        simulate: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::find(cli.repo.as_deref())?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(run(cli, paths))
}

async fn run(cli: Cli, paths: Paths) -> Result<()> {
    match &cli.cmd {
        Cmd::Keygen => {
            ensure!(!cli.submit, "keygen sends nothing");
            let kp = keys::keygen(&paths)?;
            println!("created {} (mode 600)", paths.rel(&paths.deployer_key()));
            println!("deployer address: {}", keys::address_of(&kp));
            Ok(())
        }
        Cmd::Address => {
            println!("{}", keys::address_of(&keys::load(&paths)?));
            Ok(())
        }
        Cmd::E2ePlan { simulate } => e2e_plan(&paths, *simulate),
        _ => live(cli, paths).await,
    }
}

// ---------------------------------------------------------------------------
// live commands
// ---------------------------------------------------------------------------

struct Live {
    paths: Paths,
    node: Node,
    point: DagPoint,
    deployer: Keypair,
    templates: Templates,
    submit: bool,
    verbose: bool,
}

impl Live {
    fn block(&self) -> Block {
        Block { daa: self.point.virtual_daa, time_ms: self.point.past_median_time }
    }

    fn me(&self) -> [u8; 32] {
        xonly(&self.deployer)
    }

    /// The deployer's spendable P2PK UTXOs (coinbase only once mature).
    async fn wallet(&self) -> Result<Vec<Utxo>> {
        let addr = p2pk_address(&self.me());
        ensure!(addr.prefix == kaspa_addresses::Prefix::Testnet, "deployer address is not kaspatest:");
        let maturity = consensus_params().coinbase_maturity();
        let spk = p2pk_spk(&self.me());
        Ok(self
            .node
            .utxos(&[addr])
            .await?
            .into_iter()
            .filter(|(_, _, e)| e.script_public_key == spk && e.covenant_id.is_none())
            .filter(|(_, _, e)| !e.is_coinbase || e.block_daa_score + maturity < self.point.virtual_daa)
            .map(|(_, op, e)| Utxo::new(op, e))
            .collect())
    }

    fn env(&self, kit: Kit) -> Env {
        Env { kit, deployer: self.deployer, block: self.block(), wall_ms: now_ms(), feerate: self.point.feerate }
    }

    /// The deployed registry: manifest (verified) + kit + local state.
    fn registry(&self) -> Result<(manifest::Deployed, Kit, Registry)> {
        let mpath = self.paths.manifest();
        if !mpath.exists() {
            bail!(
                "no registry: {} does not exist (no genesis has been broadcast). \
                 `genesis` dry-runs it; `e2e-plan --simulate` runs every operation against a simulated registry",
                self.paths.rel(&mpath)
            );
        }
        let pre = manifest::load(&mpath, None)?;
        let kit = self.templates.kit(pre.registry_id)?;
        let d = manifest::load(&mpath, Some(&kit))?;
        ensure!(!d.dry_run, "{} is a dry-run manifest", self.paths.rel(&mpath));
        let reg = match Registry::load(&self.paths.state())? {
            Some(r) => {
                ensure!(r.registry_id == d.registry_id, "state file is for another registry");
                r
            }
            None => Registry::at_genesis(d.registry_id, d.genesis_txid, kit.params.gap_value, d.scan_from),
        };
        Ok((d, kit, reg))
    }

    /// Live UTXOs (from the node's UTXO index) of tracked outpoints, looked
    /// up by the P2SH address their state implies.
    async fn live_utxos(&self, wanted: &[(TransactionOutpoint, ScriptPublicKey)]) -> Result<Vec<Utxo>> {
        let addrs: Vec<_> = wanted.iter().map(|(_, spk)| spk_address(spk)).collect::<Result<_>>()?;
        let found = self.node.utxos(&addrs).await?;
        wanted
            .iter()
            .map(|(op, _)| {
                found.iter().find(|(_, o, _)| o == op).map(|(_, o, e)| Utxo::new(*o, e.clone())).ok_or_else(|| {
                    anyhow!("{} is not in the UTXO set (not accepted yet, or spent by someone else: run `scan`)", fmt_outpoint(op))
                })
            })
            .collect()
    }

    /// Print, and with --submit broadcast. Returns whether it was submitted.
    async fn finish(&self, plan: &Plan) -> Result<bool> {
        println!("{}", summary::render(plan, self.submit));
        if !self.submit {
            println!("dry run: nothing was broadcast (add --submit to send it)");
            return Ok(false);
        }
        if !plan.is_valid() {
            bail!("refusing to submit: the transaction does not pass the local checks");
        }
        ensure!(self.point.network == NETWORK, "node network {}", self.point.network);
        let id = self.node.submit(&plan.built.tx).await?;
        ensure!(id == plan.txid(), "node returned txid {id}, expected {}", plan.txid());
        println!("SUBMITTED {id} to {}", self.node.url);
        Ok(true)
    }

    fn save_after(&self, kit: &Kit, reg: &mut Registry, plan: &Plan) -> Result<()> {
        let events = reg.apply(kit, &TxView::from(&plan.built.tx))?;
        if let Some(o) = &plan.new_offer {
            reg.track_offer(o.clone());
        }
        reg.save(&self.paths.state())?;
        for e in events {
            println!("state: {e}");
        }
        println!("state saved to {} (the outputs are spendable once the transaction is accepted)", self.paths.rel(&self.paths.state()));
        Ok(())
    }
}

async fn live(cli: Cli, paths: Paths) -> Result<()> {
    let deployer = keys::load(&paths)?;
    if cli.submit
        && let Cmd::Genesis { assume_utxo: Some(_) } = &cli.cmd
    {
        bail!("--assume-utxo is a dry-run aid; it cannot be submitted");
    }
    let node = Node::connect(cli.node.as_deref(), cli.verbose).await?;
    let point = node.check_network().await?;
    eprintln!(
        "node {} ({} {}), virtual DAA {}, median time {}, feerate {} sompi/g",
        node.url,
        point.network,
        point.server_version,
        point.virtual_daa,
        fmt_ms(point.past_median_time as i64),
        point.feerate
    );
    let l = Live { templates: Templates::load(&paths.root), paths, node, point, deployer, submit: cli.submit, verbose: cli.verbose };
    let res = command(&l, &cli.cmd).await;
    l.node.disconnect().await;
    res
}

fn pick_offer<'a>(reg: &'a Registry, name: &str, explicit: &Option<String>) -> Result<&'a OfferRec> {
    let key = name_key(name.as_bytes());
    if let Some(s) = explicit {
        let op = parse_outpoint(s)?;
        return reg.offers.iter().find(|o| o.outpoint == op).ok_or_else(|| anyhow!("offer {s} is not tracked"));
    }
    let all = reg.offers_for(&key);
    match all.as_slice() {
        [] => bail!("no tracked offer on {name}"),
        [one] => Ok(one),
        many => bail!(
            "{} offers on {name}; pick one with --offer: {}",
            many.len(),
            many.iter().map(|o| fmt_outpoint(&o.outpoint)).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn gap_spk(kit: &Kit, g: &GapRec) -> ScriptPublicKey {
    kit.gap.spk(&gap_state(&g.lo, &g.hi))
}

async fn command(l: &Live, cmd: &Cmd) -> Result<()> {
    match cmd {
        Cmd::NodeInfo => {
            ensure!(!l.submit, "node-info sends nothing");
            let info = l.node.info().await?;
            println!("node          {}", l.node.url);
            println!(
                "GetInfo       server {}, synced {}, utxo index {}, mempool {}",
                info.server_version, info.is_synced, info.is_utxo_indexed, info.mempool_size
            );
            println!("network       {} (required: {NETWORK})", l.point.network);
            println!("virtual DAA   {}", l.point.virtual_daa);
            println!("median time   {} ({})", l.point.past_median_time, fmt_ms(l.point.past_median_time as i64));
            println!("sink          {}", l.point.sink);
            println!("feerate       {} sompi/gram (normal bucket)", l.point.feerate);
            let addr = p2pk_address(&l.me());
            let utxos = l.node.utxos(std::slice::from_ref(&addr)).await?;
            println!("deployer      {addr}");
            println!("GetUtxosByAddresses(deployer): {} UTXO(s), {}", utxos.len(), fmt_kas(utxos.iter().map(|u| u.2.amount).sum()));
            Ok(())
        }
        Cmd::Balance => {
            let w = l.wallet().await?;
            println!("{}", p2pk_address(&l.me()));
            for u in &w {
                println!("  {}  {:>22}  DAA {}", fmt_outpoint(&u.outpoint), fmt_kas(u.entry.amount), u.entry.block_daa_score);
            }
            println!("total {} in {} UTXO(s)", fmt_kas(w.iter().map(|u| u.entry.amount).sum()), w.len());
            Ok(())
        }
        Cmd::Genesis { assume_utxo } => genesis(l, assume_utxo.as_deref()).await,
        Cmd::Scan { from_genesis, min_confirmations } => {
            let (d, kit, mut reg) = l.registry()?;
            if *from_genesis {
                reg = Registry::at_genesis(d.registry_id, d.genesis_txid, kit.params.gap_value, d.scan_from);
            }
            let rep = scan::scan(&l.node, &kit, &mut reg, *min_confirmations, 10_000, true).await?;
            reg.check_invariants()?;
            reg.save(&l.paths.state())?;
            for w in &rep.warnings {
                println!("warning: {w}");
            }
            println!(
                "scanned {} chain blocks, {} accepted transactions, {} registry events; checkpoint {}",
                rep.blocks,
                rep.txs,
                rep.events.len(),
                reg.scan_from.map(|h| h.to_string()).unwrap_or_default()
            );
            Ok(())
        }
        Cmd::Status { scan: do_scan } => status(l, *do_scan).await,
        _ => spend(l, cmd).await,
    }
}

async fn spend(l: &Live, cmd: &Cmd) -> Result<()> {
    let (_, kit, mut reg) = l.registry()?;
    let env = l.env(l.templates.kit(kit.registry_id)?);
    let wallet = l.wallet().await?;
    let me = l.me();
    let name_rec = |reg: &Registry, n: &str| {
        reg.name(n).cloned().ok_or_else(|| anyhow!("{n} is not registered (as far as the local state knows; try `scan`)"))
    };
    let plan = match cmd {
        Cmd::Commit { name } => {
            ops::check_name(name)?;
            if reg.gap_for_key(&name_key(name.as_bytes())).is_none() {
                bail!("{name} is already registered");
            }
            let mut salt = [0u8; 32];
            secp256k1::rand::RngCore::fill_bytes(&mut secp256k1::rand::rngs::OsRng, &mut salt);
            let plan = ops::commit(&env, &wallet, name, salt)?;
            if l.finish(&plan).await? {
                let mut all = commits::load(&l.paths)?;
                all.push(plan.new_commit.clone().unwrap());
                commits::save(&l.paths, &all)?;
                println!("commit saved to {} (matures {} DAA after acceptance)", l.paths.rel(&l.paths.commits()), kit.params.t_commit);
            }
            return Ok(());
        }
        Cmd::Register { name, years, backdate_days } => {
            ops::check_name(name)?;
            ensure!(*backdate_days >= 0, "--backdate-days must be >= 0");
            let mut all = commits::load(&l.paths)?;
            let c: CommitRec =
                commits::find_open(&all, name, &me).cloned().ok_or_else(|| anyhow!("no open commit for {name}; run `commit {name}` first"))?;
            let gap = reg
                .gap_for_key(&name_key(name.as_bytes()))
                .cloned()
                .ok_or_else(|| anyhow!("{name} is already registered (no gap contains its key)"))?;
            let redeem = commit_redeem(&commitment(name.as_bytes(), &me, &c.salt), &me);
            let lives =
                l.live_utxos(&[(gap.outpoint, gap_spk(&kit, &gap)), (c.outpoint.unwrap(), pay_to_script_hash_script(&redeem))]).await?;
            let now = ops::register_now(&env) - backdate_days * 86_400_000;
            let plan = ops::register(&env, &wallet, &gap, &lives[0], &c, &lives[1], *years, now)?;
            if l.finish(&plan).await? {
                l.save_after(&kit, &mut reg, &plan)?;
                for x in all.iter_mut() {
                    if x.outpoint == c.outpoint {
                        x.used_by = Some(plan.txid().to_string());
                    }
                }
                commits::save(&l.paths, &all)?;
            }
            return Ok(());
        }
        Cmd::Renew { name, years } => {
            let n = name_rec(&reg, name)?;
            let u = l.live_utxos(&[(n.outpoint, kit.name.spk(&n.fields.encode()))]).await?;
            ops::renew(&env, &wallet, &n, &u[0], *years)?
        }
        Cmd::Transfer { name, to } => {
            let to = parse_owner_address(to)?;
            let n = name_rec(&reg, name)?;
            let u = l.live_utxos(&[(n.outpoint, kit.name.spk(&n.fields.encode()))]).await?;
            ops::transfer(&env, &wallet, &n, &u[0], &to)?
        }
        Cmd::List { name, price } => {
            let n = name_rec(&reg, name)?;
            let u = l.live_utxos(&[(n.outpoint, kit.name.spk(&n.fields.encode()))]).await?;
            ops::list(&env, &wallet, &n, &u[0], parse_kas(price)?)?
        }
        Cmd::Buy { name } => {
            let n = name_rec(&reg, name)?;
            let u = l.live_utxos(&[(n.outpoint, kit.name.spk(&n.fields.encode()))]).await?;
            ops::buy(&env, &wallet, &n, &u[0])?
        }
        Cmd::Offer { name, amount, refund_after } => {
            let ra = match refund_after.strip_prefix('+') {
                Some(rel) => l.point.virtual_daa + rel.parse::<u64>().context("--refund-after +N")?,
                None => refund_after.parse::<u64>().context("--refund-after <daa>")?,
            };
            let target = reg.name(name).cloned();
            ops::offer(&env, &wallet, name, parse_kas(amount)?, ra, target.as_ref())?
        }
        Cmd::AcceptOffer { name, offer } | Cmd::WithdrawOffer { name, offer } | Cmd::RefundOffer { name, offer } => {
            let o = pick_offer(&reg, name, offer)?.clone();
            let ou = l.live_utxos(&[(o.outpoint, kit.offer.spk(&o.fields.encode()))]).await?.remove(0);
            match cmd {
                Cmd::AcceptOffer { .. } => {
                    let n = name_rec(&reg, name)?;
                    let u = l.live_utxos(&[(n.outpoint, kit.name.spk(&n.fields.encode()))]).await?;
                    ops::accept_offer(&env, &n, &u[0], &o, &ou)?
                }
                Cmd::WithdrawOffer { .. } => ops::withdraw_offer(&env, &o, &ou)?,
                _ => ops::refund_offer(&env, &o, &ou)?,
            }
        }
        Cmd::Release { name } | Cmd::Reclaim { name } => {
            let n = name_rec(&reg, name)?;
            let (below, above) = reg
                .neighbours(&n.fields.key)
                .map(|(a, b)| (a.clone(), b.clone()))
                .ok_or_else(|| anyhow!("the gaps around {name} are not tracked; run `scan`"))?;
            let u = l
                .live_utxos(&[
                    (below.outpoint, gap_spk(&kit, &below)),
                    (n.outpoint, kit.name.spk(&n.fields.encode())),
                    (above.outpoint, gap_spk(&kit, &above)),
                ])
                .await?;
            let x = ExitParts { below: &below, below_utxo: &u[0], name: &n, name_utxo: &u[1], above: &above, above_utxo: &u[2] };
            if matches!(cmd, Cmd::Release { .. }) { ops::release(&env, x)? } else { ops::reclaim(&env, x)? }
        }
        _ => unreachable!(),
    };
    if l.finish(&plan).await? {
        l.save_after(&kit, &mut reg, &plan)?;
    }
    Ok(())
}

async fn genesis(l: &Live, assume_utxo: Option<&str>) -> Result<()> {
    let paths = &l.paths;
    if paths.manifest().exists() {
        bail!("{} exists: the registry is already deployed", paths.rel(&paths.manifest()));
    }
    let params_text = std::fs::read_to_string(paths.params())?;
    ensure!(params_text.contains("\"registryCovenantId\": null"), "params already carry a registryCovenantId");
    let mut wallet = l.wallet().await?;
    if let Some(a) = assume_utxo {
        ensure!(!l.submit, "--assume-utxo cannot be submitted");
        let v = parse_kas(a)?;
        println!(
            "DRY RUN with an ASSUMED deployer UTXO of {} (synthetic outpoint 5e5e..5e:0; the registry id below is hypothetical)",
            fmt_kas(v)
        );
        wallet = vec![Utxo::new(
            TransactionOutpoint::new(TransactionId::from_bytes([0x5e; 32]), 0),
            UtxoEntry::new(v, p2pk_spk(&l.me()), l.point.virtual_daa.saturating_sub(100), false, None),
        )];
    }
    let (plan, kit) = ops::genesis(&l.templates, l.deployer, &wallet, l.block(), now_ms(), l.point.feerate)?;
    let id = plan.registry_id.unwrap();
    let deployer_addr = keys::address_of(&l.deployer);
    // the scanner starts from the sink seen before submission
    let scan_from = Some(l.point.sink);
    let submitted = l.finish(&plan).await?;
    let m = manifest::build(paths, &kit, &plan, &deployer_addr, scan_from, !submitted)?;
    if submitted {
        manifest::write(&paths.manifest(), &m)?;
        manifest::fill_params_registry_id(paths, id)?;
        Registry::at_genesis(id, plan.txid(), kit.params.gap_value, scan_from).save(&paths.state())?;
        println!("manifest  {}", paths.rel(&paths.manifest()));
        println!("params    {} registryCovenantId = {id}", paths.rel(&paths.params()));
        println!("state     {}", paths.rel(&paths.state()));
        println!(
            "next: ./scripts/build.sh   (builds artifacts/testnet10/KachatOffer.json for {id}); commit params, artifacts and the manifest"
        );
        return Ok(());
    }
    let mp = paths.dryrun_manifest();
    manifest::write(&mp, &m)?;
    println!("would-be manifest written to {} (registry id {id})", paths.rel(&mp));
    let pp = manifest::dryrun_params(paths, id)?;
    println!("would-be params written to {}", paths.rel(&pp));
    demo_offer_build(paths, &kit, &pp)
}

/// Dry run: build the offer artifact for the would-be registry id with
/// scripts/build.py into manifests/dryrun/artifacts (when the pinned silverc
/// is available) and check it equals the in-process compile.
fn demo_offer_build(paths: &Paths, kit: &Kit, params: &std::path::Path) -> Result<()> {
    let ss = std::env::var("SILVERSCRIPT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("silverscript"));
    let silverc = ss.join("target/release/silverc");
    let out = paths.dryrun_dir().join("artifacts");
    let cmd = format!("python3 scripts/build.py $SILVERSCRIPT_DIR/target/release/silverc {} {}", paths.rel(params), paths.rel(&out));
    if !silverc.exists() {
        println!("offer build (not run, silverc not found): {cmd}");
        return Ok(());
    }
    let st = std::process::Command::new("python3")
        .current_dir(&paths.root)
        .arg("scripts/build.py")
        .arg(&silverc)
        .arg(params)
        .arg(&out)
        .status()?;
    ensure!(st.success(), "{cmd} failed");
    let art: silverscript_abi::SilAbiArtifact = serde_json::from_str(&std::fs::read_to_string(out.join("KachatOffer.json"))?)?;
    let t = kachat_names_harness::Template::from_artifact(art);
    ensure!(t.bytecode == kit.offer.bytecode, "build.py offer differs from the in-process compile");
    println!(
        "offer artifact built by `{cmd}`: {} B, template hash {} (identical to the in-process compile)",
        t.bytecode.len(),
        hex(&t.template_hash)
    );
    Ok(())
}

async fn status(l: &Live, do_scan: bool) -> Result<()> {
    let (d, kit, mut reg) = l.registry()?;
    if do_scan {
        let rep = scan::scan(&l.node, &kit, &mut reg, 20, 10_000, l.verbose).await?;
        reg.save(&l.paths.state())?;
        println!("scan: {} chain blocks, {} registry events", rep.blocks, rep.events.len());
    }
    reg.check_invariants()?;
    println!("registry {}  (genesis tx {}, funded by {})", d.registry_id, d.genesis_txid, fmt_outpoint(&d.genesis_outpoint));
    let tracked = reg.tracked(&kit)?;
    let addrs: Vec<_> = tracked.iter().map(|t| t.address.clone()).collect();
    let found = l.node.utxos(&addrs).await?;
    let now = l.point.past_median_time as i64;
    let live_of = |op: &TransactionOutpoint, registry: bool| -> String {
        match found.iter().find(|(_, o, _)| o == op) {
            Some((_, _, e)) if registry && e.covenant_id != Some(reg.registry_id) => "LIVE BUT WRONG COVENANT ID".into(),
            Some((_, _, e)) => format!("live (DAA {})", e.block_daa_score),
            None => "NOT IN UTXO SET (pending, or spent elsewhere: run `scan`)".into(),
        }
    };
    let mut gaps = reg.gaps.clone();
    gaps.sort_by_key(|g| g.lo);
    println!("gaps ({}):", gaps.len());
    for g in &gaps {
        println!("  ({} .. {})  {}  {}  {}", hex(&g.lo), hex(&g.hi), fmt_kas(g.value), fmt_outpoint(&g.outpoint), live_of(&g.outpoint, true));
    }
    println!("names ({}):", reg.names.len());
    for n in &reg.names {
        let f = &n.fields;
        let phase = if now < f.expires_at {
            "active"
        } else if now < f.expires_at + kit.params.grace_ms {
            "grace"
        } else {
            "lapsed: reclaimable"
        };
        println!(
            "  {:<20} owner {}  {}  expires {} [{phase}]  {}  {}",
            n.name(),
            p2pk_address(&f.owner),
            if f.price > 0 { format!("listed {}", fmt_kas(f.price as u64)) } else { "unlisted".into() },
            fmt_ms(f.expires_at),
            fmt_outpoint(&n.outpoint),
            live_of(&n.outpoint, true)
        );
    }
    println!("offers ({}):", reg.offers.len());
    for o in &reg.offers {
        println!(
            "  {} on {}  buyer {}  refundAfter DAA {}  {}  {}",
            fmt_kas(o.value),
            o.name.clone().unwrap_or_else(|| hex(&o.fields.key)),
            p2pk_address(&o.fields.buyer),
            o.fields.refund_after,
            fmt_outpoint(&o.outpoint),
            live_of(&o.outpoint, false)
        );
    }
    let me = l.me();
    let open: Vec<_> = commits::load(&l.paths)?.into_iter().filter(|c| c.used_by.is_none()).collect();
    if !open.is_empty() {
        println!("open commits ({}):", open.len());
        for c in open {
            let redeem = commit_redeem(&commitment(c.name.as_bytes(), &me, &c.salt), &me);
            let a = spk_address(&pay_to_script_hash_script(&redeem))?;
            let u = l.node.utxos(std::slice::from_ref(&a)).await?;
            let st = match u.iter().find(|(_, o, _)| Some(*o) == c.outpoint) {
                Some((_, _, e)) => {
                    let m = e.block_daa_score + kit.params.t_commit;
                    if l.point.virtual_daa >= m {
                        "mature".to_string()
                    } else {
                        format!("matures at DAA {m} (~{} s)", (m - l.point.virtual_daa).div_ceil(10))
                    }
                }
                None => "not in the UTXO set yet".into(),
            };
            println!("  {:<20} {}  {st}", c.name, c.outpoint.map(|o| fmt_outpoint(&o)).unwrap_or_default());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// e2e plan
// ---------------------------------------------------------------------------

fn e2e_plan(paths: &Paths, simulate: bool) -> Result<()> {
    let me = keys::load(paths).map(|k| keys::address_of(&k)).unwrap_or_else(|_| "<deployer kaspatest: address>".into());
    let wall = now_ms();
    let (sim, b) = plan::simulate(Templates::load(&paths.root), PLANNED_FUNDING, wall)?;
    // the least funding the same plan completes with, rounded up to whole TKAS, re-checked
    let need = b.peak_need.max(b.funding - b.final_balance).div_ceil(SOMPI) * SOMPI;
    let (_, b_min) =
        plan::simulate(Templates::load(&paths.root), need, wall).map_err(|e| anyhow!("the plan fails with {}: {e}", fmt_kas(need)))?;
    println!("# .kachat names: end-to-end run on {NETWORK}");
    println!("# deployer {me}");
    println!("#");
    println!("# names: alpha-tn, bravo-tn, lapse-tn (8 characters: the 5+ tier, 35 TKAS per year)");
    println!("# simulated with {} (every transaction built and validated locally, each spending the previous outputs):", fmt_kas(b.funding));
    println!("#   {}", plan::fmt_budget(&b));
    println!("#   least funding that completes the plan: {} (re-simulated: ends with {})", fmt_kas(need), fmt_kas(b_min.final_balance));
    println!(
        "#   a 4-character name (250 TKAS per year) does not fit: {} leaves {} beyond the plan",
        fmt_kas(PLANNED_FUNDING),
        fmt_kas(PLANNED_FUNDING.saturating_sub(need))
    );
    println!("#   reclaim: names are yearly with a 10-day grace, so a plain reclaim needs 1 year + 10 days on testnet too;");
    println!("#   lapse-tn is registered with `now` backdated {} days so it is already past expiresAt + grace.", plan::LAPSE_BACKDATE_DAYS);
    println!();
    println!("kachat-names keygen                # once (done if the address above is set)");
    println!("kachat-names node-info             # read-only: network, DAA, deployer UTXOs");
    println!("# fund {me} with {} (at least {})", fmt_kas(PLANNED_FUNDING), fmt_kas(need));
    println!("kachat-names balance");
    for (i, (step, why)) in plan::e2e_steps().iter().enumerate() {
        println!("{:<84} # {:>2}. {why}", plan::command(step, &me), i + 1);
        if matches!(step, plan::Step::Genesis) {
            println!("{:<84} #     offer artifact for the new registry id; commit params + artifacts + manifest", "./scripts/build.sh");
        }
    }
    println!("{:<84} # every tracked UTXO live, tiling invariant holds", "kachat-names status --scan");
    if simulate {
        println!();
        for p in &sim.plans {
            println!("{}", summary::render(p, false));
        }
    }
    Ok(())
}
