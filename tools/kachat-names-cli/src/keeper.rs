//! `kachat-names refund-expired`: the offer refund keeper (audit DOM-002).
//!
//! `KachatOffer` can't say "not after": an offer stays acceptable by its seller until
//! someone spends it, past its `refundAfter`, past the apps' 7-day cap, and even on a
//! lapsed name (C1: accept, then reclaim; the buyer is left with the bond). `refund()`
//! closes that window and anyone may run it once `refundAfter` has passed: it pays
//! the offer back to its buyer, less a network fee the contract caps at `maxFee`, so
//! the keeper needs no key and no funds. Running this on a schedule protects every
//! buyer, whether or not their own app is open.
//!
//! Candidates come from an indexer (`/names/all`, then `/names/<name>/offers`) or from
//! this CLI's scanned state. Neither is trusted: each offer's state is rebuilt from its
//! fields, and the refund is only built for a UTXO the node holds at the address that
//! state implies (and the transaction is validated locally like any other).

use anyhow::{Result, anyhow, ensure};
use kachat_names_harness::{OfferFields, name_key};
use serde_json::Value;

use crate::{
    net::parse_owner_address,
    registry::OfferRec,
    util::{parse_outpoint, unhex32},
};

/// An offer as the indexer lists it (`/names/<name>/offers`): `outpoint`, `buyer`,
/// `seller` (addresses), `amount` (sompi, string or number), `refundAfter` (DAA).
pub fn offer_from_indexer(v: &Value, name: &str) -> Result<OfferRec> {
    let s = |k: &str| v[k].as_str().ok_or_else(|| anyhow!("{name}: offer without `{k}`: {v}"));
    let op = match &v["outpoint"] {
        Value::String(o) => parse_outpoint(o)?,
        o => {
            let id = o["transactionId"].as_str().or(o["txId"].as_str()).ok_or_else(|| anyhow!("{name}: offer outpoint {o}"))?;
            let index = o["index"].as_u64().ok_or_else(|| anyhow!("{name}: offer outpoint {o}"))?;
            parse_outpoint(&format!("{id}:{index}"))?
        }
    };
    let value = match &v["amount"] {
        Value::String(a) => a.parse::<u64>()?,
        a => a.as_u64().ok_or_else(|| anyhow!("{name}: offer amount {a}"))?,
    };
    let refund_after = v["refundAfter"].as_i64().ok_or_else(|| anyhow!("{name}: offer without refundAfter"))?;
    ensure!(refund_after >= 0, "{name}: negative refundAfter");
    let fields = OfferFields {
        key: name_key(name.as_bytes()),
        buyer: parse_owner_address(s("buyer")?)?,
        seller: parse_owner_address(s("seller")?)?,
        refund_after,
    };
    Ok(OfferRec { outpoint: op, fields, value, name: Some(name.to_string()) })
}

/// The offers `refund()` is valid for at `virtual_daa`: the transaction's lock time is
/// `refundAfter` (DAA domain), final once the DAA has passed it.
pub fn due(offers: &[OfferRec], virtual_daa: u64) -> Vec<OfferRec> {
    let mut d: Vec<OfferRec> = offers.iter().filter(|o| (o.fields.refund_after as u64) < virtual_daa).cloned().collect();
    d.sort_by_key(|o| o.fields.refund_after);
    d.dedup_by_key(|o| o.outpoint);
    d
}

/// A key's hex in a `/names/all` row, for skipping unknown names (key = blake3(name)).
pub fn key_of(v: &Value) -> Option<[u8; 32]> {
    v["key"].as_str().and_then(|k| unhex32(k).ok())
}
