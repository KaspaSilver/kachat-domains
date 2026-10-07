//! The two RPC conversions the CLI depends on, on every transaction of the
//! simulated e2e plan: what SubmitTransaction carries must decode on the
//! node side to the identical transaction (id, storage-mass commitment,
//! compute budgets), and the scanner (GetVirtualChainFromBlockV2's
//! RpcOptionalTransaction) must rebuild exactly the state the CLI tracks,
//! offers included (found through their `kchat:1:offer:` payload marker).
//! The scanner itself runs against a simulated node that pages the chain the
//! way rusty-kaspa does (by merged blocks, short of the tip by
//! `min_confirmations`).

use kachat_names_cli::{
    ops::Templates,
    paths::Paths,
    plan::{self, PLANNED_FUNDING},
    registry::Registry,
    scan::{ChainSource, scan, view_of},
};
use kachat_names_harness::{Transaction, scenarios::NOW_MS, YEAR_MS};
use kaspa_hashes::Hash;
use kaspa_rpc_core::{
    GetVirtualChainFromBlockV2Response, RpcChainBlockAcceptedTransactions, RpcOptionalTransaction, RpcOptionalTransactionVerboseData,
    RpcTransaction,
};
use std::{cell::RefCell, sync::Arc};

fn sim() -> plan::Sim {
    let (sim, _) = plan::simulate(Templates::load(&Paths::find(None).unwrap().root), PLANNED_FUNDING, NOW_MS + 10 * YEAR_MS).unwrap();
    sim
}

#[test]
fn submitted_transactions_survive_the_rpc_round_trip() {
    for p in &sim().plans {
        let tx = &p.built.tx;
        let rpc: RpcTransaction = tx.into();
        let back = Transaction::try_from(rpc).unwrap();
        assert_eq!(back.id(), tx.id(), "{}", p.op);
        assert_eq!(back.storage_mass(), tx.storage_mass(), "{}", p.op);
        for (a, b) in back.inputs.iter().zip(&tx.inputs) {
            assert_eq!(a.compute_commit, b.compute_commit, "{}", p.op);
            assert_eq!(a.sequence, b.sequence);
        }
        assert_eq!(back.outputs, tx.outputs);
        assert_eq!(back.lock_time, tx.lock_time);
    }
}

#[test]
fn the_scanner_view_rebuilds_the_tracked_state() {
    let s = sim();
    let kit = s.kit.as_ref().unwrap();
    let id = kit.registry_id;
    let genesis = &s.plans[0].built.tx;
    let mut scanned = Registry::at_genesis(id, genesis.id(), kit.params.gap_value, None);
    for p in &s.plans {
        let v = view_of(&accepted(&p.built.tx)).unwrap();
        assert_eq!(v.payload, p.built.tx.payload);
        scanned.apply(kit, &v).unwrap();
        // no track_offer here: the scanner finds offers by their payload marker
    }
    let tracked = s.reg.as_ref().unwrap();
    assert_eq!(scanned.gaps, tracked.gaps);
    assert_eq!(scanned.names, tracked.names);
    assert_eq!(scanned.offers, tracked.offers);
    scanned.check_invariants().unwrap();
}

/// An accepted transaction as GetVirtualChainFromBlockV2 returns it at High verbosity.
fn accepted(tx: &Transaction) -> RpcOptionalTransaction {
    let mut o = RpcOptionalTransaction::from(tx);
    o.verbose_data = Some(RpcOptionalTransactionVerboseData {
        transaction_id: Some(tx.id()),
        hash: None,
        compute_mass: None,
        block_hash: None,
        block_time: None,
    });
    o
}

/// A selected chain served like rusty-kaspa's GetVirtualChainFromBlockV2:
/// the path after `start` is cut once the merged blocks of the returned chain
/// blocks exceed `merged_limit`, and the last `min_confirmations` blocks
/// (counted from the sink) are held back. Every chain block merges `merged`
/// blocks, so a full page is `merged_limit / merged` chain blocks long.
struct SimChain {
    blocks: RefCell<Vec<(Hash, Vec<RpcOptionalTransaction>)>>,
    merged: usize,
    merged_limit: usize,
    calls: RefCell<usize>,
}

impl SimChain {
    fn new(len: usize, merged: usize, merged_limit: usize) -> Self {
        let c = SimChain { blocks: RefCell::new(vec![]), merged, merged_limit, calls: RefCell::new(0) };
        c.grow(len);
        c
    }
    fn grow(&self, n: usize) {
        let mut b = self.blocks.borrow_mut();
        for _ in 0..n {
            let i = b.len() as u64;
            b.push((Hash::from_u64_word(1_000_000 + i), vec![]));
        }
    }
    fn hash(&self, i: usize) -> Hash {
        self.blocks.borrow()[i].0
    }
    fn put(&self, i: usize, tx: &Transaction) {
        self.blocks.borrow_mut()[i].1.push(accepted(tx));
    }
    fn len(&self) -> usize {
        self.blocks.borrow().len()
    }
}

impl ChainSource for SimChain {
    fn describe(&self) -> &str {
        "sim://chain"
    }
    async fn virtual_chain(&self, start: Hash, min_confirmations: u64) -> anyhow::Result<GetVirtualChainFromBlockV2Response> {
        *self.calls.borrow_mut() += 1;
        let b = self.blocks.borrow();
        let Some(at) = b.iter().position(|(h, _)| *h == start) else {
            anyhow::bail!("RPC Server (remote error) -> Consensus: cannot find header {start}");
        };
        let confirmed = b.len().saturating_sub(min_confirmations as usize);
        let mut added = vec![];
        let mut acc = vec![];
        let mut merged = 0;
        for (h, txs) in b.iter().take(confirmed).skip(at + 1) {
            merged += self.merged;
            if merged > self.merged_limit {
                break;
            }
            added.push(*h);
            acc.push(RpcChainBlockAcceptedTransactions { chain_block_header: Default::default(), accepted_transactions: txs.clone() });
        }
        Ok(GetVirtualChainFromBlockV2Response {
            removed_chain_block_hashes: Arc::new(vec![]),
            added_chain_block_hashes: Arc::new(added),
            chain_block_accepted_transactions: Arc::new(acc),
        })
    }
}

/// Regression (testnet-10, 2026-10-07): pages of ~180 chain blocks (10 merged
/// blocks each, a 1800-merged-block budget) used to be read as "the tip" after
/// the first one, so the scan moved the checkpoint 182 blocks and missed the
/// registrations further on. Every page must be walked until the node returns
/// no new confirmed block, and the checkpoint must land on the last confirmed one.
#[tokio::test]
async fn the_scanner_walks_every_page_to_the_confirmed_tip() {
    let s = sim();
    let kit = s.kit.as_ref().unwrap();
    let genesis = &s.plans[0].built.tx;
    const MIN_CONF: u64 = 20;
    // block 0 is the sink seen before the genesis (the manifest's scanFrom);
    // the plan's transactions are spread over the chain, the first one well past page one
    let chain = SimChain::new(5_000, 10, 1_800);
    let step = 4_000 / s.plans.len();
    for (k, p) in s.plans.iter().enumerate() {
        chain.put(400 + k * step, &p.built.tx);
    }
    let mut reg = Registry::at_genesis(kit.registry_id, genesis.id(), kit.params.gap_value, Some(chain.hash(0)));

    let rep = scan(&chain, kit, &mut reg, MIN_CONF, 10_000, false).await.unwrap();
    let last_confirmed = chain.len() - 1 - MIN_CONF as usize;
    assert!(rep.reached_tip && rep.warnings.is_empty(), "{:?}", rep.warnings);
    assert_eq!(rep.blocks, last_confirmed, "every confirmed chain block after the checkpoint");
    assert_eq!(rep.pages, last_confirmed.div_ceil(180), "pages of 180 chain blocks");
    assert_eq!(rep.txs, s.plans.len());
    assert_eq!(reg.scan_from, Some(chain.hash(last_confirmed)));
    let tracked = s.reg.as_ref().unwrap();
    assert_eq!(reg.gaps, tracked.gaps);
    assert_eq!(reg.names, tracked.names);
    assert_eq!(reg.offers, tracked.offers);
    reg.check_invariants().unwrap();

    // caught up: one call, nothing applied, checkpoint unchanged
    let rep = scan(&chain, kit, &mut reg, MIN_CONF, 10_000, false).await.unwrap();
    assert!(rep.reached_tip);
    assert_eq!((rep.blocks, rep.pages), (0, 0));
    assert_eq!(reg.scan_from, Some(chain.hash(last_confirmed)));

    // the chain grows by more than a page: the next scan walks all of it
    chain.grow(1_000);
    let rep = scan(&chain, kit, &mut reg, MIN_CONF, 10_000, false).await.unwrap();
    assert!(rep.reached_tip);
    assert_eq!(rep.blocks, 1_000);
    assert_eq!(reg.scan_from, Some(chain.hash(chain.len() - 1 - MIN_CONF as usize)));
}

#[tokio::test]
async fn the_scanner_stops_short_only_when_told_to_and_says_so() {
    let s = sim();
    let kit = s.kit.as_ref().unwrap();
    let chain = SimChain::new(2_000, 10, 1_800);
    let mut reg = Registry::at_genesis(kit.registry_id, s.plans[0].built.tx.id(), kit.params.gap_value, Some(chain.hash(0)));
    let rep = scan(&chain, kit, &mut reg, 20, 3, false).await.unwrap();
    assert!(!rep.reached_tip);
    assert_eq!((rep.blocks, rep.pages), (540, 3));
    assert_eq!(reg.scan_from, Some(chain.hash(540)), "the checkpoint is the last block actually applied");
    assert!(rep.warnings.iter().any(|w| w.contains("before the confirmed tip")), "{:?}", rep.warnings);
}

/// A node that does not know the checkpoint (another DNS-seeded node, or one
/// that pruned it) must fail the scan without touching the checkpoint.
#[tokio::test]
async fn an_unknown_checkpoint_fails_loudly_and_moves_nothing() {
    let s = sim();
    let kit = s.kit.as_ref().unwrap();
    let chain = SimChain::new(1_000, 10, 1_800);
    let unknown = Hash::from_u64_word(42);
    let mut reg = Registry::at_genesis(kit.registry_id, s.plans[0].built.tx.id(), kit.params.gap_value, Some(unknown));
    let err = scan(&chain, kit, &mut reg, 20, 10_000, false).await.err().expect("must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains(&unknown.to_string()) && msg.contains("checkpoint was not moved"), "{msg}");
    assert_eq!(reg.scan_from, Some(unknown));
    assert_eq!(*chain.calls.borrow(), 1);
}
