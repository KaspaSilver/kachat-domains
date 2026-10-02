//! The two RPC conversions the CLI depends on, on every transaction of the
//! simulated e2e plan: what SubmitTransaction carries must decode on the
//! node side to the identical transaction (id, storage-mass commitment,
//! compute budgets), and the scanner (GetVirtualChainFromBlockV2's
//! RpcOptionalTransaction) must rebuild exactly the state the CLI tracks.

use kachat_names_cli::{
    ops::Templates,
    paths::Paths,
    plan::{self, PLANNED_FUNDING},
    registry::Registry,
    scan::view_of,
};
use kachat_names_harness::{Transaction, scenarios::NOW_MS, YEAR_MS};
use kaspa_rpc_core::{RpcOptionalTransaction, RpcOptionalTransactionVerboseData, RpcTransaction};

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
        let mut o = RpcOptionalTransaction::from(&p.built.tx);
        o.verbose_data = Some(RpcOptionalTransactionVerboseData {
            transaction_id: Some(p.built.tx.id()),
            hash: None,
            compute_mass: None,
            block_hash: None,
            block_time: None,
        });
        let v = view_of(&o).unwrap();
        scanned.apply(kit, &v).unwrap();
        // offers are tracked by the CLI that creates them (no covenant id on chain)
        if let Some(of) = &p.new_offer {
            scanned.track_offer(of.clone());
        }
    }
    let tracked = s.reg.as_ref().unwrap();
    assert_eq!(scanned.gaps, tracked.gaps);
    assert_eq!(scanned.names, tracked.names);
    assert_eq!(scanned.offers, tracked.offers);
    scanned.check_invariants().unwrap();
}
