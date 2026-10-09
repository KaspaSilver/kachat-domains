//! Read-only checks against a real testnet-10 node. Ignored by default (they
//! need the network); run with
//!   cargo test --test live_readonly -- --ignored --nocapture
//! Optional: KACHAT_TN10_NODE=grpc://host:16210. Nothing is ever submitted.

use kachat_names_cli::{
    net::{net, p2pk_address},
    node::Node,
    scan::view_of,
};

fn node_url() -> Option<String> {
    std::env::var("KACHAT_TN10_NODE").ok()
}

#[tokio::test]
#[ignore]
async fn node_is_testnet10_synced_and_indexed() {
    let node = Node::connect(node_url().as_deref(), true).await.expect("connect");
    let p = node.check_network().await.expect("testnet-10 node");
    assert_eq!(p.network, net().name);
    let info = node.info().await.expect("GetInfo");
    println!("{} {} synced={} utxoindex={} daa={}", node.url, info.server_version, info.is_synced, info.is_utxo_indexed, p.virtual_daa);
    // an address nobody uses: empty
    let empty = p2pk_address(blake3::hash(b"kachat-names live_readonly: unused key").as_bytes());
    assert!(node.utxos(&[empty]).await.expect("GetUtxosByAddresses").is_empty());
    node.disconnect().await;
}

#[tokio::test]
#[ignore]
async fn virtual_chain_v2_decodes_accepted_transactions() {
    let node = Node::connect(node_url().as_deref(), true).await.expect("connect");
    let p = node.check_network().await.expect("testnet-10 node");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let r = node.virtual_chain_v2(p.sink, 0).await.expect("GetVirtualChainFromBlockV2");
    assert_eq!(r.added_chain_block_hashes.len(), r.chain_block_accepted_transactions.len());
    let mut txs = 0;
    let mut bound = 0;
    for acc in r.chain_block_accepted_transactions.iter() {
        for tx in &acc.accepted_transactions {
            let v = view_of(tx).expect("decodable at High verbosity");
            txs += 1;
            bound += v.outputs.iter().filter(|o| o.covenant.is_some()).count();
        }
    }
    println!("{} chain blocks, {txs} accepted transactions, {bound} covenant-bound outputs", r.added_chain_block_hashes.len());
    assert!(!r.added_chain_block_hashes.is_empty());
    node.disconnect().await;
}

#[tokio::test]
#[ignore]
async fn scanner_walks_a_minute_of_chain() {
    use kachat_names_cli::{ops::Templates, paths::Paths, registry::Registry, scan::scan};
    use kaspa_hashes::Hash;
    let node = Node::connect(node_url().as_deref(), true).await.expect("connect");
    let p = node.check_network().await.expect("testnet-10 node");
    // a registry nobody has: the walk must decode every accepted transaction and find nothing
    let paths = Paths::find(None).unwrap();
    let id = Hash::from_bytes(*blake3::hash(b"kachat-names: no such registry").as_bytes());
    let kit = Templates::load(&paths.root).kit(id).unwrap();
    let mut reg = Registry::at_genesis(id, kaspa_consensus_core::tx::TransactionId::from_bytes([1; 32]), 100_000_000, Some(p.sink));
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    let t = std::time::Instant::now();
    let rep = scan(&node, &kit, &mut reg, 20, 100, false).await.expect("scan");
    println!("{} chain blocks, {} transactions in {:?}; checkpoint moved: {}", rep.blocks, rep.txs, t.elapsed(), reg.scan_from != Some(p.sink));
    assert!(rep.blocks > 100 && rep.events.is_empty());
    node.disconnect().await;
}
