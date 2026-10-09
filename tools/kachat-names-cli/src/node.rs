//! Read-only node access over gRPC (rusty-kaspa `kaspa-grpc-client`), plus the
//! one write path, [`Node::submit`], which the CLI calls only with `--submit`.
//!
//! Every connection is checked before use: the node must report network
//! the selected network (`--network`), be synced and keep a UTXO index.

use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{Transaction, TransactionOutpoint, UtxoEntry};
use kaspa_grpc_client::GrpcClient;
use kaspa_hashes::Hash;
use kaspa_rpc_core::{
    GetVirtualChainFromBlockV2Response, RpcDataVerbosityLevel, RpcTransaction, api::rpc::RpcApi, notify::mode::NotificationMode,
};

use crate::net::net;

/// What the CLI needs from the virtual state for validation and fees.
#[derive(Clone, Debug)]
pub struct DagPoint {
    pub network: String,
    pub virtual_daa: u64,
    /// past median time of the virtual, unix ms (the lock-time reference)
    pub past_median_time: u64,
    pub sink: Hash,
    pub server_version: String,
    pub is_synced: bool,
    pub has_utxo_index: bool,
    /// normal-priority feerate estimate, sompi/gram
    pub feerate: f64,
}

pub struct Node {
    pub url: String,
    client: GrpcClient,
}

const REQUEST_TIMEOUT_MS: u64 = 20_000;

impl Node {
    async fn connect_url(url: &str) -> Result<Node> {
        let client = tokio::time::timeout(
            Duration::from_secs(10),
            GrpcClient::connect_with_args(
                NotificationMode::Direct,
                url.to_string(),
                None,
                false,
                None,
                false,
                Some(REQUEST_TIMEOUT_MS),
                Default::default(),
            ),
        )
        .await
        .map_err(|_| anyhow!("timed out connecting to {url}"))?
        .map_err(|e| anyhow!("connecting to {url}: {e}"))?;
        Ok(Node { url: url.to_string(), client })
    }

    /// Connect to `--node grpc://host:port`, or discover a node through the
    /// network's DNS seeders: the first that answers on the gRPC port, reports
    /// the network, is synced and has a UTXO index.
    pub async fn connect(explicit: Option<&str>, verbose: bool) -> Result<Node> {
        if let Some(url) = explicit {
            let url = if url.starts_with("grpc://") { url.to_string() } else { format!("grpc://{url}") };
            let node = Self::connect_url(&url).await?;
            node.check_network().await?;
            return Ok(node);
        }
        let candidates = seed_candidates();
        if candidates.is_empty() {
            bail!("no {} DNS seeder resolved; pass --node grpc://host:{}", net().name, net().grpc_port);
        }
        let mut last_err = None;
        for addr in candidates.iter().take(24) {
            let url = format!("grpc://{addr}");
            if verbose {
                eprintln!("  trying {url}");
            }
            // cheap TCP probe first: most seeded peers do not expose gRPC
            if std::net::TcpStream::connect_timeout(addr, Duration::from_secs(3)).is_err() {
                continue;
            }
            match Self::connect_url(&url).await {
                Ok(node) => match node.check_network().await {
                    Ok(_) => return Ok(node),
                    Err(e) => {
                        if verbose {
                            eprintln!("    rejected: {e}");
                        }
                        last_err = Some(e);
                        let _ = node.client.disconnect().await;
                    }
                },
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no seeded {} node answered on gRPC port {}", net().name, net().grpc_port)))
            .with_context(|| format!("node discovery failed; pass --node grpc://host:{}", net().grpc_port))
    }

    /// Refuse anything but a synced, UTXO-indexed node of the selected network.
    pub async fn check_network(&self) -> Result<DagPoint> {
        let point = self.dag_point().await?;
        if point.network != net().name {
            bail!("{} reports network {:?}; this run is on {}", self.url, point.network, net().name);
        }
        if !point.is_synced {
            bail!("{} is not synced", self.url);
        }
        if !point.has_utxo_index {
            bail!("{} has no UTXO index (--utxoindex)", self.url);
        }
        Ok(point)
    }

    pub async fn dag_point(&self) -> Result<DagPoint> {
        let info = self.client.get_server_info().await.context("GetServerInfo")?;
        let dag = self.client.get_block_dag_info().await.context("GetBlockDagInfo")?;
        if info.network_id.to_string() != dag.network.to_string() {
            bail!("node reports two networks: {} / {}", info.network_id, dag.network);
        }
        let feerate = match self.client.get_fee_estimate().await {
            Ok(e) => e.normal_buckets.first().map(|b| b.feerate).unwrap_or(e.priority_bucket.feerate),
            Err(_) => 1.0,
        };
        Ok(DagPoint {
            network: dag.network.to_string(),
            virtual_daa: dag.virtual_daa_score,
            past_median_time: dag.past_median_time,
            sink: dag.sink,
            server_version: info.server_version,
            is_synced: info.is_synced,
            has_utxo_index: info.has_utxo_index,
            feerate,
        })
    }

    /// GetInfo (read-only), for the connectivity report.
    pub async fn info(&self) -> Result<kaspa_rpc_core::GetInfoResponse> {
        self.client.get_info().await.context("GetInfo")
    }

    /// UTXOs of the given addresses: (address, outpoint, entry incl. covenant id).
    pub async fn utxos(&self, addresses: &[Address]) -> Result<Vec<(Address, TransactionOutpoint, UtxoEntry)>> {
        if addresses.is_empty() {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for chunk in addresses.chunks(100) {
            let entries = self.client.get_utxos_by_addresses(chunk.to_vec()).await.context("GetUtxosByAddresses")?;
            for e in entries {
                let addr = e.address.ok_or_else(|| anyhow!("UTXO entry without address"))?;
                let u = e.utxo_entry;
                out.push((
                    addr,
                    TransactionOutpoint::new(e.outpoint.transaction_id, e.outpoint.index),
                    UtxoEntry::new(u.amount, u.script_public_key, u.block_daa_score, u.is_coinbase, u.covenant_id),
                ));
            }
        }
        Ok(out)
    }

    pub async fn virtual_chain_v2(&self, start: Hash, min_confirmations: u64) -> Result<GetVirtualChainFromBlockV2Response> {
        self.client
            .get_virtual_chain_from_block_v2(start, Some(RpcDataVerbosityLevel::High), Some(min_confirmations))
            .await
            .context("GetVirtualChainFromBlockV2")
    }

    /// The only write: broadcast a transaction. Called by the CLI only when
    /// `--submit` is given, after local validation passed and the network
    /// was re-checked.
    pub async fn submit(&self, tx: &Transaction) -> Result<Hash> {
        self.check_network().await?;
        let rpc: RpcTransaction = tx.into();
        self.client.submit_transaction(rpc, false).await.context("SubmitTransaction")
    }

    pub async fn disconnect(self) {
        let _ = self.client.disconnect().await;
    }
}

/// Resolve every seeder of the network (all A records) on the gRPC port, deduplicated.
pub fn seed_candidates() -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for host in net().seeders {
        if let Ok(addrs) = (*host, net().grpc_port).to_socket_addrs() {
            for a in addrs {
                if a.is_ipv4() && !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    }
    // spread the load across seeded nodes
    use rand::seq::SliceRandom;
    out.shuffle(&mut rand::thread_rng());
    out
}
