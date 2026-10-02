//! Chain scanner: walk the selected chain with GetVirtualChainFromBlockV2
//! (accepted transactions, High verbosity) from a checkpoint, and feed every
//! accepted transaction to [`Registry::apply`]. Read-only.
//!
//! Limits (the indexer replaces this later): the start block must still be
//! inside the node's pruning window, so scan at least daily; reorgs are
//! avoided by asking for `min_confirmations`, and a reported reorg of an
//! already-scanned block is surfaced as a warning (rescan with
//! `scan --from-genesis` if a registry transaction was in it).

use anyhow::{Result, anyhow, bail};
use kachat_names_harness::Kit;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, TransactionOutpoint, TransactionOutput};
use kaspa_rpc_core::RpcOptionalTransaction;

use crate::{
    node::Node,
    registry::{Registry, TxView},
};

pub struct ScanReport {
    pub blocks: usize,
    pub txs: usize,
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
    Ok(TxView { id, inputs, outputs })
}

pub async fn scan(node: &Node, kit: &Kit, reg: &mut Registry, min_confirmations: u64, max_rounds: usize, verbose: bool) -> Result<ScanReport> {
    let mut report = ScanReport { blocks: 0, txs: 0, events: vec![], warnings: vec![] };
    for _ in 0..max_rounds {
        let start = reg.scan_from.ok_or_else(|| anyhow!("no scan checkpoint (the manifest's genesis.scanFrom)"))?;
        let resp = node.virtual_chain_v2(start, min_confirmations).await?;
        if !resp.removed_chain_block_hashes.is_empty() {
            report.warnings.push(format!(
                "{} chain block(s) at or before the checkpoint left the selected chain; if a registry transaction was in them, run `scan --from-genesis`",
                resp.removed_chain_block_hashes.len()
            ));
        }
        if resp.added_chain_block_hashes.is_empty() {
            break;
        }
        if resp.added_chain_block_hashes.len() != resp.chain_block_accepted_transactions.len() {
            bail!("node returned {} chain blocks but {} acceptance sets", resp.added_chain_block_hashes.len(), resp.chain_block_accepted_transactions.len());
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
        // a short batch means we reached the confirmed tip
        if resp.added_chain_block_hashes.len() < 200 {
            break;
        }
    }
    Ok(report)
}
