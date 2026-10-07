//! Chain scanner: walk the selected chain with GetVirtualChainFromBlockV2
//! (accepted transactions, High verbosity) from a checkpoint, and feed every
//! accepted transaction to [`Registry::apply`]. Read-only.
//!
//! The node answers in pages: it caps each response by the number of blocks
//! *merged* by the returned chain blocks (`mergeset_size_limit * 10`), so a
//! full page can hold anything from a handful to a few thousand chain blocks
//! (about 180 at 10 bps). The scan therefore keeps asking from the last
//! applied block until the node returns no new chain block, which, with
//! `min_confirmations`, means every block past the checkpoint is still within
//! that many confirmations of the sink. The page length says nothing about
//! the tip.
//!
//! Limits (the indexer replaces this later): the start block must still be
//! inside the node's pruning window, so scan at least daily; if the node does
//! not know it, the scan fails and the checkpoint stays where it was. Reorgs
//! are avoided by asking for `min_confirmations`, and a reported reorg of an
//! already-scanned block is surfaced as a warning (rescan with
//! `scan --from-genesis` if a registry transaction was in it).

use std::future::Future;

use anyhow::{Context, Result, anyhow, bail};
use kachat_names_harness::Kit;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, TransactionOutpoint, TransactionOutput};
use kaspa_hashes::Hash;
use kaspa_rpc_core::{GetVirtualChainFromBlockV2Response, RpcOptionalTransaction};

use crate::{
    node::Node,
    registry::{Registry, TxView},
};

/// Where the scanner reads the selected chain from: a node, or a simulated
/// chain in the tests.
pub trait ChainSource {
    /// for error messages (the node URL)
    fn describe(&self) -> &str;
    /// One page of GetVirtualChainFromBlockV2 from `start` (exclusive).
    fn virtual_chain(&self, start: Hash, min_confirmations: u64) -> impl Future<Output = Result<GetVirtualChainFromBlockV2Response>>;
}

impl ChainSource for Node {
    fn describe(&self) -> &str {
        &self.url
    }
    fn virtual_chain(&self, start: Hash, min_confirmations: u64) -> impl Future<Output = Result<GetVirtualChainFromBlockV2Response>> {
        self.virtual_chain_v2(start, min_confirmations)
    }
}

pub struct ScanReport {
    pub blocks: usize,
    pub txs: usize,
    /// responses that carried at least one new chain block
    pub pages: usize,
    /// false when `max_rounds` ran out before the confirmed tip; scan again
    pub reached_tip: bool,
    pub events: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

pub fn view_of(tx: &RpcOptionalTransaction) -> Result<TxView> {
    let id = tx
        .verbose_data
        .as_ref()
        .and_then(|v| v.transaction_id)
        .ok_or_else(|| anyhow!("accepted transaction without an id (verbosity too low)"))?;
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    for i in &tx.inputs {
        let op = i.previous_outpoint.ok_or_else(|| anyhow!("{id}: input without outpoint"))?;
        let op = TransactionOutpoint::new(
            op.transaction_id.ok_or_else(|| anyhow!("{id}: outpoint without txid"))?,
            op.index.ok_or_else(|| anyhow!("{id}: outpoint without index"))?,
        );
        inputs.push((op, i.signature_script.clone().unwrap_or_default()));
    }
    let mut outputs = Vec::with_capacity(tx.outputs.len());
    for o in &tx.outputs {
        let spk: ScriptPublicKey = o.script_public_key.clone().ok_or_else(|| anyhow!("{id}: output without script"))?;
        let cov: Option<CovenantBinding> = o.covenant.as_ref().and_then(|c| c.0).map(Into::into);
        outputs.push(TransactionOutput::with_covenant(o.value.ok_or_else(|| anyhow!("{id}: output without value"))?, spk, cov));
    }
    Ok(TxView { id, inputs, outputs, payload: tx.payload.clone().unwrap_or_default() })
}

pub async fn scan<C: ChainSource>(
    node: &C,
    kit: &Kit,
    reg: &mut Registry,
    min_confirmations: u64,
    max_rounds: usize,
    verbose: bool,
) -> Result<ScanReport> {
    let mut report = ScanReport { blocks: 0, txs: 0, pages: 0, reached_tip: false, events: vec![], warnings: vec![] };
    for _ in 0..max_rounds {
        let start = reg.scan_from.ok_or_else(|| anyhow!("no scan checkpoint (the manifest's genesis.scanFrom)"))?;
        let resp = node.virtual_chain(start, min_confirmations).await.with_context(|| {
            format!(
                "reading the chain from checkpoint {start} on {}; the checkpoint was not moved (if this node does not know the block \
                 or has pruned it, pass another --node, or run `scan --from-genesis`)",
                node.describe()
            )
        })?;
        if !resp.removed_chain_block_hashes.is_empty() {
            report.warnings.push(format!(
                "{} chain block(s) at or before the checkpoint left the selected chain; if a registry transaction was in them, run `scan --from-genesis`",
                resp.removed_chain_block_hashes.len()
            ));
        }
        if resp.added_chain_block_hashes.len() != resp.chain_block_accepted_transactions.len() {
            bail!("node returned {} chain blocks but {} acceptance sets", resp.added_chain_block_hashes.len(), resp.chain_block_accepted_transactions.len());
        }
        // no new chain block with enough confirmations: the confirmed tip
        if resp.added_chain_block_hashes.is_empty() {
            report.reached_tip = true;
            break;
        }
        if resp.added_chain_block_hashes.contains(&start) {
            bail!("{} returned the checkpoint {start} as a new chain block; refusing to apply it twice", node.describe());
        }
        for (hash, acc) in resp.added_chain_block_hashes.iter().zip(resp.chain_block_accepted_transactions.iter()) {
            for tx in &acc.accepted_transactions {
                report.txs += 1;
                let view = view_of(tx)?;
                let events = reg.apply(kit, &view)?;
                for e in events {
                    if verbose {
                        println!("  {hash}  {}  {e}", view.id);
                    }
                    report.events.push((view.id.to_string(), e));
                }
            }
            report.blocks += 1;
            reg.scan_from = Some(*hash);
        }
        report.pages += 1;
    }
    if !report.reached_tip {
        report.warnings.push(format!(
            "stopped after {} page(s) before the confirmed tip; run `scan` again to continue from {}",
            report.pages,
            reg.scan_from.map(|h| h.to_string()).unwrap_or_default()
        ));
    }
    Ok(report)
}
