//! `kachat-names`: deployment CLI for the .kachat name covenants
//! (registry v4: fixed register and renew tables baked into the templates, one
//! genesis, seller-bound offers, the short clock).
//!
//! Every spending command builds the exact transaction shape of the README,
//! validates it locally with rusty-kaspa's consensus TransactionValidator and
//! prints a dry-run summary. Only `--submit` broadcasts, and only to a node
//! that reports the selected network: testnet-10 by default, mainnet with
//! `--network mainnet`, where `--submit` also needs an explicit `--node` and a
//! `--max-fee` cap, and the testing aids (`--backdate-minutes`, `e2e-plan`)
//! are refused.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Parser, Subcommand};
use kachat_names_cli::{
    commits::{self, CommitRec},
    keys, manifest,
    net::{self, consensus_params, net, p2pk_address, parse_owner_address, spk_address},
    node::{DagPoint, Node},
    ops::{self, Env, ExitParts, Plan, Templates},
    paths::Paths,
    plan::{self, PLANNED_FUNDING},
    registry::{GapRec, OfferRec, Registry, TxView},
    scan, summary,
    util::{SOMPI, fmt_dur, fmt_kas, fmt_ms, fmt_outpoint, hex, now_ms, parse_kas, parse_outpoint},
};
use kachat_names_harness::{
    Block, Kit, TransactionId, TransactionOutpoint, Utxo, UtxoEntry, commit_redeem, commitment, gap_state, name_key, p2pk_spk, xonly,
};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_script_hash_script;
use secp256k1::Keypair;

#[derive(Parser)]
#[command(name = "kachat-names", about = "CLI for the .kachat name covenants (dry run unless --submit)")]
struct Cli {
    /// testnet-10 or mainnet (params/<network>.json, artifacts/, manifests/, state/, .secrets/<network>-deployer.key)
    #[arg(long, global = true, default_value = "testnet-10")]
    network: String,
    /// gRPC node, e.g. grpc://host:16210 on testnet-10, :16110 on mainnet (default: discover
    /// through the network's DNS seeders; mainnet --submit requires it)
    #[arg(long, global = true)]
    node: Option<String>,
    /// refuse to submit a transaction whose network fee (the fee beyond any price) is above
    /// this many KAS; required for mainnet --submit
    #[arg(long, global = true)]
    max_fee: Option<String>,
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
    /// Create the deployer key (.secrets/<network>-deployer.key, mode 600); prints only its address
    Keygen,
    /// Print the deployer's address
    Address,
    /// Connectivity report: GetInfo, network, DAG point, and the deployer's UTXOs (read-only)
    NodeInfo,
    /// UTXOs of the deployer address
    Balance,
    /// Mint the registry: one deployer UTXO -> the lone genesis gap (+ change)
    Genesis {
        /// dry run only: pretend the deployer holds one UTXO of this many KAS (cannot be submitted)
        #[arg(long)]
        assume_utxo: Option<String>,
    },
    /// Show the two price tables baked into the gap and the name (read-only, no node needed)
    Prices,
    /// The migration snapshot of the live registry: every name active or in grace at
    /// `--at` (default now), as the tree registry v5's `import` checks. Run `scan` first;
    /// it then proves the scanned state against a node (as `verify --live`) and refuses a
    /// stale one, so no name can be missed. Writes manifests/snapshots/<registry>-<atMs>.json
    Snapshot {
        /// snapshot time, unix ms (default: now)
        #[arg(long)]
        at: Option<i64>,
        /// instead: rebuild this snapshot file's tree and check its root and every proof
        #[arg(long)]
        check: Option<PathBuf>,
    },
    /// Check the deployed manifest against the sources: compiles the contracts from
    /// contracts/ + params/, requires the committed artifacts and the manifest to match
    /// (offline, no node or key; exit 1 on any mismatch)
    Verify {
        /// print the summary as JSON (for Kaspa Quick Start)
        #[arg(long)]
        json: bool,
        /// also prove a list of names is exactly the registry on chain: derive every gap
        /// and name address from it and require each to hold a registry UTXO (needs a node
        /// with --utxoindex; see --node)
        #[arg(long)]
        live: bool,
        /// with --live: prove this indexer's `/names/all` (default: this CLI's own scan, state/)
        #[arg(long)]
        indexer: Option<String>,
    },
    /// Salted commit for a name (salt kept in .secrets/commits.json)
    Commit { name: String },
    /// Register a committed name
    Register {
        name: String,
        #[arg(long, default_value_t = 1)]
        years: i64,
        /// move `now` this many minutes into the past (testing reclaim on the testnet day clock
        /// with its 6-hour grace: 3300 (55 h) leaves a 1-period name lapsed even after one renewal;
        /// refused on mainnet)
        #[arg(long, default_value_t = 0)]
        backdate_minutes: i64,
    },
    /// Registry v5: import one snapshot name (the deployer signs as the migration sponsor)
    Import {
        name: String,
        /// the snapshot file the registry was deployed with (default: params migration.snapshot)
        #[arg(long)]
        snapshot: Option<PathBuf>,
    },
    /// Registry v5: import every snapshot name not yet in the registry, one transaction each
    ImportAll {
        #[arg(long)]
        snapshot: Option<PathBuf>,
    },
    /// Extend a name's current period (anyone may; at most maxYears past its periodStart)
    Extend {
        name: String,
        #[arg(long, default_value_t = 1)]
        years: i64,
    },
    /// Renew a name: a new period from the old expiry (anyone may; once the renewal window is open)
    Renew {
        name: String,
        #[arg(long, default_value_t = 1)]
        years: i64,
    },
    /// Transfer a name owned by the deployer to a Schnorr address of the network
    Transfer { name: String, to: String },
    /// List a name for sale (price in KAS; 0 delists)
    List { name: String, price: String },
    /// Buy a listed name for the deployer
    Buy { name: String },
    /// Lock KAS as an offer for a registered name (bound to its current owner)
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
    /// Decline an offer made to the deployer (it goes straight back to the buyer)
    DeclineOffer {
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
    /// The ordered command list for a full testnet run, and the TKAS it needs (testnet-10 only)
    E2ePlan {
        /// also print every simulated transaction (synthetic UTXOs, local validator)
        #[arg(long)]
        simulate: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    net::select(&cli.network)?;
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
        Cmd::Prices => {
            ensure!(!cli.submit, "prices sends nothing");
            prices(&paths)
        }
        Cmd::Snapshot { at, check } => {
            ensure!(!cli.submit, "snapshot sends nothing");
            if let Some(file) = check {
                let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file)?)?;
                ensure!(v["network"] == net().name, "{} is a {} snapshot, not {}", file.display(), v["network"], net().name);
                let snap = kachat_names_cli::snapshot::check_file(&v)?;
                println!("OK  {} names, root {} (rebuilt from the entries; every stored proof matches)", snap.entries.len(), hex(&snap.root()));
                return Ok(());
            }
            let reg = Registry::load(&paths.state())?
                .ok_or_else(|| anyhow!("{} not found: run `scan` first", paths.rel(&paths.state())))?;
            // A snapshot of a stale state would silently leave names out: prove the state is
            // exactly the registry on chain first, against a node.
            let proof = verify_live(&cli, &paths, None)
                .await
                .map_err(|e| anyhow!("the scanned state is not the registry on chain ({e}); run `scan` and try again"))?;
            println!("state proven against {}: {} names, {} gaps", proof["node"].as_str().unwrap_or(""), proof["names"], proof["gaps"]);
            let grace = Templates::load(&paths.root).params.grace_ms;
            let at_ms = at.unwrap_or_else(now_ms);
            let taken = kachat_names_cli::snapshot::take(&reg, at_ms, grace);
            let v = kachat_names_cli::snapshot::to_json(&taken, &reg, net().name, at_ms, grace);
            let dir = paths.root.join("manifests").join("snapshots");
            std::fs::create_dir_all(&dir)?;
            let out = dir.join(format!("{}-{at_ms}.json", &reg.registry_id.to_string()[..16]));
            std::fs::write(&out, serde_json::to_string_pretty(&v)? + "\n")?;
            println!("snapshot of registry {} at {}", reg.registry_id, fmt_ms(at_ms));
            println!("  kept   {} name(s), active or in grace: {}", taken.kept.len(), taken.kept.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", "));
            println!("  lapsed {} name(s), left behind: {}", taken.lapsed.len(), taken.lapsed.join(", "));
            println!("  root   {}", hex(&taken.snapshot.root()));
            println!("written to {}", paths.rel(&out));
            Ok(())
        }
        Cmd::Verify { json, live, indexer } => {
            ensure!(!cli.submit, "verify sends nothing");
            ensure!(*live || indexer.is_none(), "--indexer needs --live");
            let mut v = kachat_names_cli::verify::verify(&paths)?;
            if *live {
                v["live"] = verify_live(&cli, &paths, indexer.as_deref()).await?;
            }
            if *json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                println!("OK  {} registry v{} {}", v["network"].as_str().unwrap_or(""), v["registryVersion"], v["registryCovenantId"].as_str().unwrap_or(""));
                println!("    genesis {}  manifest sha256 {}", v["genesisTxid"].as_str().unwrap_or(""), v["manifestSha256"].as_str().unwrap_or(""));
                for (c, h) in v["templateHashes"].as_object().into_iter().flatten() {
                    println!("    {c:<11} {}", h.as_str().unwrap_or(""));
                }
                println!("    compiled from contracts/ + params/: identical to the committed artifacts and the manifest");
                if let Some(l) = v.get("live") {
                    println!(
                        "OK  live: {} names from {} are exactly the registry - all {} gaps and {} names hold registry UTXOs at {}",
                        l["names"], l["source"].as_str().unwrap_or(""), l["gaps"], l["names"], l["node"].as_str().unwrap_or("")
                    );
                }
            }
            Ok(())
        }
        Cmd::E2ePlan { simulate } => {
            ensure!(!net().mainnet, "e2e-plan is the testnet-10 test run");
            e2e_plan(&paths, *simulate)
        }
        _ => live(cli, paths).await,
    }
}

/// `verify --live`: the claimed names (an indexer's `/names/all`, or this CLI's scan) are
/// exactly the registry on chain (src/prove.rs).
async fn verify_live(cli: &Cli, paths: &Paths, indexer: Option<&str>) -> Result<serde_json::Value> {
    use kachat_names_cli::prove::{self, Claim};
    let d = manifest::load(&paths.manifest(), None)?;
    let kit = Templates::load(&paths.root).kit(d.registry_id)?;
    let (source, claims) = match indexer {
        Some(base) => {
            let base = base.trim_end_matches('/').to_string();
            let id = d.registry_id.to_string();
            let claims = tokio::task::spawn_blocking(move || -> Result<Vec<Claim>> {
                let get = |path: &str| -> Result<serde_json::Value> {
                    ureq::get(&format!("{base}{path}"))
                        .timeout(std::time::Duration::from_secs(30))
                        .call()
                        .map_err(|e| anyhow!("{base}{path}: {e}"))?
                        .into_json()
                        .map_err(|e| anyhow!("{base}{path}: {e}"))
                };
                let status = get("/names/status")?;
                ensure!(
                    status["registryCovenantId"].as_str() == Some(id.as_str()),
                    "the indexer follows registry {}, not {id}",
                    status["registryCovenantId"]
                );
                let mut claims = vec![];
                let mut cursor: Option<String> = None;
                loop {
                    let page = get(&format!("/names/all{}", cursor.as_ref().map(|c| format!("?cursor={c}")).unwrap_or_default()))?;
                    for n in page["names"].as_array().ok_or_else(|| anyhow!("/names/all: no `names` array"))? {
                        claims.push(Claim::from_indexer(n)?);
                    }
                    match page["next"].as_str() {
                        Some(c) => cursor = Some(c.to_string()),
                        None => break,
                    }
                }
                Ok(claims)
            })
            .await??;
            (indexer.unwrap().to_string(), claims)
        }
        None => {
            let reg = Registry::load(&paths.state())?
                .ok_or_else(|| anyhow!("{} not found: run `scan` first, or pass --indexer", paths.rel(&paths.state())))?;
            ensure!(reg.registry_id == d.registry_id, "state/ is for registry {}, not {}", reg.registry_id, d.registry_id);
            let claims = reg.names.iter().map(|n| Claim { name: n.name(), fields: n.fields.clone() }).collect();
            (paths.rel(&paths.state()), claims)
        }
    };
    let p = prove::probe(&claims, &kit)?;
    let node = Node::connect(cli.node.as_deref(), cli.verbose).await?;
    node.check_network().await?;
    let held = node.utxos(&p.addresses()).await?;
    let url = node.url.clone();
    node.disconnect().await;
    let r = prove::check(&p, held.into_iter().map(|(a, _, e)| (a, e.covenant_id, e.amount)), &kit, d.registry_id)?;
    Ok(serde_json::json!({ "ok": true, "source": source, "names": r.names, "gaps": r.gaps, "node": url }))
}

/// The checked items of a snapshot file: `--snapshot`, else params `migration.snapshot`.
fn load_snapshot_items(paths: &Paths, file: Option<&std::path::Path>) -> Result<Vec<ops::SnapItem>> {
    let path = match file {
        Some(f) => f.to_path_buf(),
        None => {
            let p: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(paths.params())?)?;
            let f = p["migration"]["snapshot"].as_str().ok_or_else(|| anyhow!("no --snapshot and no migration.snapshot in params"))?;
            paths.root.join(f)
        }
    };
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).with_context(|| path.display().to_string())?)?;
    ensure!(v["network"] == net().name, "{} is a {} snapshot, not {}", path.display(), v["network"], net().name);
    ops::snapshot_items(&v)
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
    /// --max-fee in sompi: the most network fee a submitted transaction may leave
    max_fee: Option<u64>,
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
        ensure!(addr.prefix == net().prefix, "deployer address is not {}:", net().prefix);
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
        let d = manifest::load(&mpath, Some(&kit)).with_context(|| {
            format!(
                "{} does not describe the contracts in contracts/ and artifacts/ (the deployed registry was built from other \
                 templates: a new registry version needs a new genesis)",
                self.paths.rel(&mpath)
            )
        })?;
        ensure!(!d.dry_run, "{} is a dry-run manifest", self.paths.rel(&mpath));
        let reg = match Registry::load(&self.paths.state())? {
            Some(r) => {
                ensure!(r.registry_id == d.registry_id, "state file is for another registry");
                r
            }
            None => d.genesis_registry(kit.params.gap_value),
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
        self.finish_then(plan, || Ok(())).await
    }

    /// [`Live::finish`], running `after_submit` as soon as the node took the
    /// transaction, before waiting for its acceptance (the genesis writes its
    /// manifest there, so an interrupted wait cannot lose the registry id).
    async fn finish_then(&self, plan: &Plan, after_submit: impl FnOnce() -> Result<()>) -> Result<bool> {
        println!("{}", summary::render(plan, self.submit));
        if let Some(cap) = self.max_fee
            && plan.network_fee > cap
        {
            bail!("the network fee {} is above --max-fee {}", fmt_kas(plan.network_fee), fmt_kas(cap));
        }
        if !self.submit {
            println!("dry run: nothing was broadcast (add --submit to send it)");
            return Ok(false);
        }
        if !plan.is_valid() {
            bail!("refusing to submit: the transaction does not pass the local checks");
        }
        ensure!(self.point.network == net().name, "node network {}", self.point.network);
        ensure!(!net().mainnet || self.max_fee.is_some(), "mainnet --submit needs --max-fee");
        let id = self.node.submit(&plan.built.tx).await?;
        ensure!(id == plan.txid(), "node returned txid {id}, expected {}", plan.txid());
        println!("SUBMITTED {id} to {}", self.node.url);
        after_submit()?;
        self.wait_accepted(plan).await;
        Ok(true)
    }

    /// Poll (read-only) until output 0 of the transaction is in the UTXO
    /// index, so the next command sees its outputs. Gives up after 60 s.
    async fn wait_accepted(&self, plan: &Plan) {
        let tx = &plan.built.tx;
        let Ok(addr) = spk_address(&tx.outputs[0].script_public_key) else { return };
        let op = TransactionOutpoint::new(tx.id(), 0);
        for _ in 0..60 {
            if let Ok(found) = self.node.utxos(std::slice::from_ref(&addr)).await
                && let Some((_, _, e)) = found.iter().find(|(_, o, _)| *o == op)
            {
                println!("accepted: output 0 is in the UTXO set (DAA {})", e.block_daa_score);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        println!("not accepted within 60 s; check `status` / `balance` before the next command");
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
    if net().mainnet {
        // no discovered node and no uncapped fee for real money
        ensure!(!cli.submit || cli.node.is_some(), "mainnet --submit needs an explicit --node (your own node)");
        ensure!(!cli.submit || cli.max_fee.is_some(), "mainnet --submit needs --max-fee");
        if let Cmd::Register { backdate_minutes, .. } = &cli.cmd {
            ensure!(*backdate_minutes == 0, "--backdate-minutes is a testnet aid; refused on mainnet");
        }
    }
    let max_fee = cli.max_fee.as_deref().map(parse_kas).transpose()?;
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
    let l = Live { templates: Templates::load(&paths.root), paths, node, point, deployer, submit: cli.submit, max_fee, verbose: cli.verbose };
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
            println!("network       {} (required: {})", l.point.network, net().name);
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
                reg = d.genesis_registry(kit.params.gap_value);
            }
            let rep = scan_saving(l, &kit, &mut reg, *min_confirmations, true).await?;
            reg.check_invariants()?;
            reg.save(&l.paths.state())?;
            for w in &rep.warnings {
                println!("warning: {w}");
            }
            println!(
                "scanned {} chain blocks in {} page(s), {} accepted transactions, {} registry events; checkpoint {}{}",
                rep.blocks,
                rep.pages,
                rep.txs,
                rep.events.len(),
                reg.scan_from.map(|h| h.to_string()).unwrap_or_default(),
                if rep.reached_tip { "" } else { " (not at the tip yet)" }
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
        Cmd::Register { name, years, backdate_minutes } => {
            ops::check_name(name)?;
            ensure!(*backdate_minutes >= 0, "--backdate-minutes must be >= 0");
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
            let now = ops::register_now(&env) - backdate_minutes * 60_000;
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
        Cmd::Import { name, snapshot } => {
            let items = load_snapshot_items(&l.paths, snapshot.as_deref())?;
            let item = items.iter().find(|i| i.name == *name).ok_or_else(|| anyhow!("{name} is not in the snapshot"))?;
            let gap = reg
                .gap_for_key(&item.entry.key)
                .cloned()
                .ok_or_else(|| anyhow!("{name} is already in the registry (no gap contains its key)"))?;
            let lives = l.live_utxos(&[(gap.outpoint, gap_spk(&kit, &gap))]).await?;
            let plan = ops::import(&env, &wallet, &gap, &lives[0], item)?;
            if l.finish(&plan).await? {
                l.save_after(&kit, &mut reg, &plan)?;
            }
            return Ok(());
        }
        Cmd::ImportAll { snapshot } => {
            let items = load_snapshot_items(&l.paths, snapshot.as_deref())?;
            let todo: Vec<_> = items.iter().filter(|i| reg.gap_for_key(&i.entry.key).is_some()).collect();
            println!("{} snapshot name(s), {} still to import", items.len(), todo.len());
            // The node's address index can still list a UTXO the previous import spent for a
            // moment after acceptance: leave out everything this loop spent, and if a build still
            // fails the local checks, wait for the index and build again.
            let mut spent = std::collections::HashSet::new();
            for item in todo {
                let gap = reg.gap_for_key(&item.entry.key).cloned().expect("filtered");
                let mut tries = 0;
                let plan = loop {
                    let lives = l.live_utxos(&[(gap.outpoint, gap_spk(&kit, &gap))]).await?;
                    let wallet: Vec<_> = l.wallet().await?.into_iter().filter(|u| !spent.contains(&u.outpoint)).collect();
                    let plan = ops::import(&env, &wallet, &gap, &lives[0], item)?;
                    tries += 1;
                    if plan.validation.is_ok() || tries >= 10 || !l.submit {
                        break plan;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                };
                spent.extend(plan.built.tx.inputs.iter().map(|i| i.previous_outpoint));
                if !l.finish(&plan).await? {
                    println!("dry run: stopping after the first import (each import spends the gap the previous one creates)");
                    return Ok(());
                }
                l.save_after(&kit, &mut reg, &plan)?;
            }
            println!("all snapshot names imported");
            return Ok(());
        }
        Cmd::Extend { name, years } => {
            let n = name_rec(&reg, name)?;
            let u = l.live_utxos(&[(n.outpoint, kit.name.spk(&n.fields.encode()))]).await?;
            ops::extend(&env, &wallet, &n, &u[0], *years)?
        }
        Cmd::Renew { name, years } => {
            let n = name_rec(&reg, name)?;
            let u = l.live_utxos(&[(n.outpoint, kit.name.spk(&n.fields.encode()))]).await?;
            let plan = ops::renew(&env, &wallet, &n, &u[0], *years)?;
            if l.submit && !ops::renew_window_open(&env, &n.fields) {
                println!("{}", summary::render(&plan, false));
                let opens = ops::renew_opens(&kit.params, &n.fields);
                bail!(
                    "refusing to submit: the renewal window of {name} opens {} (expiresAt {} - {}) and the network median time is {}; \
                     a time-locked transaction is only final once the median time passes its lock time. Use `extend {name}` to add periods before then ({} possible now)",
                    fmt_ms(opens),
                    fmt_ms(n.fields.expires_at),
                    fmt_dur(kit.params.renew_window_ms),
                    fmt_ms(l.point.past_median_time as i64),
                    ops::extendable_years(&kit.params, &n.fields)
                );
            }
            plan
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
            let target = name_rec(&reg, name).context("offers are made on registered names (to their owner)")?;
            ops::offer(&env, &wallet, name, parse_kas(amount)?, ra, &target)?
        }
        Cmd::AcceptOffer { name, offer }
        | Cmd::DeclineOffer { name, offer }
        | Cmd::WithdrawOffer { name, offer }
        | Cmd::RefundOffer { name, offer } => {
            let o = pick_offer(&reg, name, offer)?.clone();
            let ou = l.live_utxos(&[(o.outpoint, kit.offer.spk(&o.fields.encode()))]).await?.remove(0);
            match cmd {
                Cmd::AcceptOffer { .. } => {
                    let n = name_rec(&reg, name)?;
                    let u = l.live_utxos(&[(n.outpoint, kit.name.spk(&n.fields.encode()))]).await?;
                    ops::accept_offer(&env, &n, &u[0], &o, &ou)?
                }
                Cmd::DeclineOffer { .. } => ops::decline_offer(&env, &o, &ou)?,
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

/// The deployer's wallet, or one assumed UTXO for a dry run.
async fn genesis_wallet(l: &Live, assume_utxo: Option<&str>) -> Result<Vec<Utxo>> {
    let mut wallet = l.wallet().await?;
    if let Some(a) = assume_utxo {
        ensure!(!l.submit, "--assume-utxo cannot be submitted");
        let v = parse_kas(a)?;
        println!(
            "DRY RUN with an ASSUMED deployer UTXO of {} (synthetic outpoint 5e5e..5e:0; the ids below are hypothetical)",
            fmt_kas(v)
        );
        wallet = vec![Utxo::new(
            TransactionOutpoint::new(TransactionId::from_bytes([0x5e; 32]), 0),
            UtxoEntry::new(v, p2pk_spk(&l.me()), l.point.virtual_daa.saturating_sub(100), false, None),
        )];
    }
    Ok(wallet)
}

/// The registry genesis (registry v4 has no other).
async fn genesis(l: &Live, assume_utxo: Option<&str>) -> Result<()> {
    let paths = &l.paths;
    // A real genesis needs a clean slate; a dry run may preview a new registry next to
    // the deployed one, writing only manifests/dryrun/.
    let params_text = std::fs::read_to_string(paths.params())?;
    let deployed = paths.manifest().exists() || !params_text.contains("\"registryCovenantId\": null");
    if deployed && l.submit {
        bail!(
            "{} exists or params carry a registryCovenantId: a registry is already deployed. A new genesis needs the old \
             manifest (and state/) archived and registryCovenantId set back to null first",
            paths.rel(&paths.manifest())
        );
    }
    if deployed {
        println!(
            "note: a registry is already deployed ({}); this dry run previews a NEW registry from the current contracts",
            paths.rel(&paths.manifest())
        );
    }
    let wallet = genesis_wallet(l, assume_utxo).await?;
    let (plan, kit) = ops::genesis(&l.templates, l.deployer, &wallet, l.block(), now_ms(), l.point.feerate)?;
    let id = plan.registry_id.unwrap();
    let deployer_addr = keys::address_of(&l.deployer);
    // the scanner starts from the sink seen before the genesis
    let scan_from = Some(l.point.sink);
    // Built before the submit, written right after it (before the acceptance wait), so an
    // interrupted run still leaves the manifest, the params id and the state behind.
    let m = manifest::build(paths, &kit, &plan, &deployer_addr, scan_from, false)?;
    let record = || -> Result<()> {
        manifest::write(&paths.manifest(), &m)?;
        manifest::fill_registry_id(paths, id)?;
        let d = manifest::load(&paths.manifest(), Some(&kit))?;
        d.genesis_registry(kit.params.gap_value).save(&paths.state())?;
        println!("manifest  {}", paths.rel(&paths.manifest()));
        println!("params    {} registryCovenantId = {id}", paths.rel(&paths.params()));
        println!("state     {}", paths.rel(&paths.state()));
        Ok(())
    };
    if l.finish_then(&plan, record).await? {
        println!(
            "next: ./scripts/build.sh   (builds artifacts/{}/KachatOffer.json for {id}); commit params, artifacts and the manifest",
            net().params_file
        );
        return Ok(());
    }
    let m = manifest::build(paths, &kit, &plan, &deployer_addr, scan_from, true)?;
    let mp = paths.dryrun_manifest();
    manifest::write(&mp, &m)?;
    println!("would-be manifest written to {} (registry id {id})", paths.rel(&mp));
    let pp = manifest::dryrun_params(paths, id)?;
    println!("would-be params written to {}", paths.rel(&pp));
    demo_build(paths, &kit, &pp)
}

/// The two tables baked into the gap and the name, from params/<network>.json (which
/// the templates in use are compiled from), checked against the deployed manifest's.
fn prices(paths: &Paths) -> Result<()> {
    let p = &Templates::load(&paths.root).params;
    let row = |label: &str, t: &[u64; 5]| println!("  {label:<9} {}", t.iter().map(|x| format!("{:>18}", fmt_kas(*x))).collect::<String>());
    println!("prices per period ({}), baked into KachatGap and KachatName ({}):", fmt_dur(p.period_ms), paths.rel(&paths.params()));
    println!("  {:<9} {}", "", ["1 char", "2 chars", "3 chars", "4 chars", "5+ chars"].iter().map(|h| format!("{h:>18}")).collect::<String>());
    row("register", &p.register_prices);
    row("renew", &p.renew_prices);
    println!(
        "register for N periods = register + renew x (N - 1); extend / renew by N = renew x N (N <= maxYears = {}); \
         the price is left to the miner",
        p.max_years
    );
    if paths.manifest().exists() {
        let m: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(paths.manifest())?)?;
        let ours: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(paths.params())?)?;
        // v5 is v4 plus the migration import: the same two tables
        if !matches!(m["registryVersion"].as_i64(), Some(4 | 5)) {
            println!("note: {} is a registry v{} manifest, not these tables", paths.rel(&paths.manifest()), m["registryVersion"]);
        } else if m["params"]["prices"] != ours["prices"] {
            println!("WARNING: the deployed registry ({}) bakes other prices than params", paths.rel(&paths.manifest()));
        }
    }
    Ok(())
}

/// Dry run: build the name, gap and offer artifacts for the would-be registry id with
/// scripts/build.py into manifests/dryrun/artifacts (when the pinned silverc is
/// available) and check they equal the in-process compiles.
fn demo_build(paths: &Paths, kit: &Kit, params: &std::path::Path) -> Result<()> {
    let ss = std::env::var("SILVERSCRIPT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("silverscript"));
    let silverc = ss.join("target/release/silverc");
    let out = paths.dryrun_dir().join("artifacts");
    let cmd = format!("python3 scripts/build.py $SILVERSCRIPT_DIR/target/release/silverc {} {}", paths.rel(params), paths.rel(&out));
    if !silverc.exists() {
        println!("artifact build (not run, silverc not found): {cmd}");
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
    for (c, t) in [("KachatName", &kit.name), ("KachatGap", &kit.gap), ("KachatOffer", &kit.offer)] {
        let art: silverscript_abi::SilAbiArtifact = serde_json::from_str(&std::fs::read_to_string(out.join(format!("{c}.json")))?)?;
        let built = kachat_names_harness::Template::from_artifact(art);
        ensure!(built.bytecode == t.bytecode, "build.py {c} differs from the in-process compile");
        println!("{c} built by `{cmd}`: {} B, template hash {} (identical to the in-process compile)", built.bytecode.len(), hex(&built.template_hash));
    }
    Ok(())
}

/// `scan` one page at a time, saving the state after each, so a slow or flaky node
/// that fails part way leaves the progress made (the next run continues from it).
async fn scan_saving(l: &Live, kit: &Kit, reg: &mut Registry, min_confirmations: u64, verbose: bool) -> Result<scan::ScanReport> {
    let mut total = scan::ScanReport { blocks: 0, txs: 0, pages: 0, reached_tip: false, events: vec![], warnings: vec![] };
    for _ in 0..10_000 {
        let rep = scan::scan(&l.node, kit, reg, min_confirmations, 1, verbose).await?;
        reg.save(&l.paths.state())?;
        total.blocks += rep.blocks;
        total.txs += rep.txs;
        total.pages += rep.pages;
        total.events.extend(rep.events);
        total.warnings.extend(rep.warnings.into_iter().filter(|w| !w.starts_with("stopped after")));
        if rep.reached_tip {
            total.reached_tip = true;
            break;
        }
        if verbose {
            eprintln!("  page {}: {} chain blocks so far, checkpoint {}", total.pages, total.blocks, reg.scan_from.map(|h| h.to_string()).unwrap_or_default());
        }
    }
    if !total.reached_tip {
        total.warnings.push(format!("stopped after {} page(s) before the confirmed tip; run `scan` again", total.pages));
    }
    Ok(total)
}

async fn status(l: &Live, do_scan: bool) -> Result<()> {
    let (d, kit, mut reg) = l.registry()?;
    if do_scan {
        let rep = scan_saving(l, &kit, &mut reg, 20, l.verbose).await?;
        for w in &rep.warnings {
            println!("warning: {w}");
        }
        println!("scan: {} chain blocks, {} registry events", rep.blocks, rep.events.len());
    }
    reg.check_invariants()?;
    println!("registry {}  (genesis tx {}, funded by {})", d.registry_id, d.genesis_txid, fmt_outpoint(&d.genesis_outpoint));
    println!(
        "prices per period ({}), 1/2/3/4/5+ chars: register {}; renew {}  (baked)",
        fmt_dur(kit.params.period_ms),
        ops::fmt_tiers(&kit.params.register_prices),
        ops::fmt_tiers(&kit.params.renew_prices)
    );
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
        let opens = ops::renew_opens(&kit.params, f);
        let next = if now > opens {
            "renewal window open".to_string()
        } else {
            format!("renewal opens {}, extendable by {} period(s)", fmt_ms(opens), ops::extendable_years(&kit.params, f))
        };
        println!(
            "  {:<20} owner {}  {}  period {} .. expires {} [{phase}; {next}]  {}  {}",
            n.name(),
            p2pk_address(&f.owner),
            if f.price > 0 { format!("listed {}", fmt_kas(f.price as u64)) } else { "unlisted".into() },
            fmt_ms(f.period_start),
            fmt_ms(f.expires_at),
            fmt_outpoint(&n.outpoint),
            live_of(&n.outpoint, true)
        );
    }
    println!("offers ({}):", reg.offers.len());
    for o in &reg.offers {
        println!(
            "  {} on {}  buyer {}  seller {}  refundAfter DAA {}  {}  {}",
            fmt_kas(o.value),
            o.name.clone().unwrap_or_else(|| hex(&o.fields.key)),
            p2pk_address(&o.fields.buyer),
            p2pk_address(&o.fields.seller),
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
    println!("# .kachat names: end-to-end run on {}", net().name);
    println!("# deployer {me}");
    println!("#");
    let t = Templates::load(&paths.root);
    println!(
        "# names: alpha-tn, bravo-tn, lapse-tn (8 characters: the 5+ tier, {} to register for a first period of {}, {} per further period)",
        fmt_kas(t.params.price_for(8)),
        fmt_dur(t.params.period_ms),
        fmt_kas(t.params.renew_price_for(8))
    );
    println!("# simulated with {} (every transaction built and validated locally, each spending the previous outputs):", fmt_kas(b.funding));
    println!("#   {}", plan::fmt_budget(&b));
    println!("#   least funding that completes the plan: {} (re-simulated: ends with {})", fmt_kas(need), fmt_kas(b_min.final_balance));
    println!(
        "#   reclaim: periods are {} with a {} grace, so a name lapses {} after it expires;",
        fmt_dur(t.params.period_ms),
        fmt_dur(t.params.grace_ms),
        fmt_dur(t.params.grace_ms)
    );
    println!(
        "#   lapse-tn is registered with `now` backdated {} minutes: renewed once after lapse (its window is long open), it is still past expiresAt + grace.",
        plan::LAPSE_BACKDATE_MINUTES
    );
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
