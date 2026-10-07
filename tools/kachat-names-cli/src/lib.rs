//! Phase 2 tooling for the .kachat name covenants on testnet-10: transaction
//! builders for every entry (validated locally by rusty-kaspa's consensus
//! `TransactionValidator` through the harness kit), registry state tracking
//! without an indexer, the deployment manifest, and a node client.
//!
//! Testnet-10 only. Nothing is broadcast unless the CLI is run with
//! `--submit`.

pub mod commits;
pub mod keys;
pub mod manifest;
pub mod net;
pub mod node;
pub mod ops;
pub mod paths;
pub mod plan;
pub mod prove;
pub mod registry;
pub mod scan;
pub mod summary;
pub mod util;
pub mod verify;
