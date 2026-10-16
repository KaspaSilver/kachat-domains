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
//! Candidates come from an indexer (`/offers/refundable`, or else `/names/all` then
//! `/names/<name>/offers`) or from this CLI's scanned state. Neither is trusted: each
//! offer's state is rebuilt from its fields, and the refund is only built for a UTXO the
//! node holds at the address that state implies (and the transaction is validated
//! locally like any other).

use std::{collections::HashSet, time::Instant};

use anyhow::{Result, anyhow, ensure};
use kachat_names_harness::{OfferFields, name_key};
use serde_json::Value;

use crate::{
    net::parse_owner_address,
    prove::{MAX_CLAIMS, collect_pages},
    registry::OfferRec,
    util::{parse_outpoint, unhex32},
};

/// An offer as the indexer lists it (`/offers/refundable`, `/names/<name>/offers`):
/// `outpoint`, `buyer`, `seller` (addresses), `amount` (sompi, string or number),
/// `refundAfter` (DAA), and the wanted name's `key` (hex) and/or its `name`. The key is
/// what the offer's state holds; a name, when given, must hash to it.
pub fn offer_from_indexer(v: &Value, name: Option<&str>) -> Result<OfferRec> {
    let what = name.unwrap_or("an offer");
    let s = |k: &str| v[k].as_str().ok_or_else(|| anyhow!("{what}: offer without `{k}`: {v}"));
    let op = match &v["outpoint"] {
        Value::String(o) => parse_outpoint(o)?,
        o => {
            let id = o["transactionId"].as_str().or(o["txId"].as_str()).ok_or_else(|| anyhow!("{what}: offer outpoint {o}"))?;
            let index = o["index"].as_u64().ok_or_else(|| anyhow!("{what}: offer outpoint {o}"))?;
            parse_outpoint(&format!("{id}:{index}"))?
        }
    };
    let value = match &v["amount"] {
        Value::String(a) => a.parse::<u64>()?,
        a => a.as_u64().ok_or_else(|| anyhow!("{what}: offer amount {a}"))?,
    };
    let refund_after = v["refundAfter"].as_i64().ok_or_else(|| anyhow!("{what}: offer without refundAfter"))?;
    ensure!(refund_after >= 0, "{what}: negative refundAfter");
    let name = name.map(str::to_string).or_else(|| v["name"].as_str().map(str::to_string));
    let key = match (key_of(v), &name) {
        (Some(k), Some(n)) => {
            ensure!(name_key(n.as_bytes()) == k, "{n}: the offer's key is not blake3({n})");
            k
        }
        (Some(k), None) => k,
        (None, Some(n)) => name_key(n.as_bytes()),
        (None, None) => return Err(anyhow!("an offer with neither `key` nor `name`: {v}")),
    };
    let fields = OfferFields { key, buyer: parse_owner_address(s("buyer")?)?, seller: parse_owner_address(s("seller")?)?, refund_after };
    Ok(OfferRec { outpoint: op, fields, value, name })
}

/// The open offers an indexer knows, and what couldn't be read.
pub struct Collected {
    pub offers: Vec<OfferRec>,
    /// what couldn't be used, and why: a name whose `/names/<name>/offers` failed, or an
    /// offer row that doesn't parse (an invalid buyer or seller key, DOM-039)
    pub skipped: Vec<(String, String)>,
    /// `/offers/refundable` (every open offer past refundAfter, in one paged listing) or
    /// `/names/all` + `/names/<name>/offers` (only names registered now: DOM-037)
    pub source: &'static str,
}

/// Collect an indexer's refundable offers (DOM-036, DOM-037). `fetch(path, cursor)`
/// returns a page, `Ok(None)` for HTTP 404, or an error.
/// - `/offers/refundable` first: one paged listing of every open offer past refundAfter,
///   by key, so offers on released or reclaimed names are included.
/// - Without it (404): every name in `/names/all`, then each name's offers. One name's
///   failure (a 429, a timeout) skips that name only; the rest are still refunded.
pub fn collect_offers(mut fetch: impl FnMut(&str, Option<&str>) -> Result<Option<Value>>, deadline: Instant) -> Result<Collected> {
    let mut offers = vec![];
    let mut skipped = vec![];
    let mut cursor: Option<String> = None;
    let mut seen = HashSet::new();
    let mut first = true;
    loop {
        ensure!(Instant::now() < deadline, "/offers/refundable: not done before the deadline ({} offers so far)", offers.len());
        let Some(page) = fetch("/offers/refundable", cursor.as_deref())? else {
            ensure!(first, "/offers/refundable: a later page is missing");
            break;
        };
        first = false;
        for o in page["offers"].as_array().ok_or_else(|| anyhow!("/offers/refundable: no `offers` array"))? {
            // DOM-039: anyone can plant an offer the keeper can't use (a zero or off-curve buyer,
            // about 1 KAS): skip and report it, never let it stop the refunds of everyone else
            match offer_from_indexer(o, None) {
                Ok(rec) => offers.push(rec),
                Err(e) => skipped.push((row_label(o), e.to_string())),
            }
            ensure!(offers.len() + skipped.len() <= MAX_CLAIMS, "/offers/refundable: more than {MAX_CLAIMS} offers");
        }
        match page["next"].as_str() {
            Some(c) => {
                ensure!(seen.insert(c.to_string()), "/offers/refundable: the cursor {c:?} came back a second time");
                cursor = Some(c.to_string());
            }
            None => return Ok(Collected { offers, skipped, source: "/offers/refundable" }),
        }
    }
    // the indexer has no /offers/refundable: by name
    let names = collect_pages(|c| fetch("/names/all", c)?.ok_or_else(|| anyhow!("/names/all: not found")), deadline)?;
    for n in names {
        if Instant::now() >= deadline {
            skipped.push((n.name, "deadline".into()));
            continue;
        }
        match fetch(&format!("/names/{}/offers", n.name), None) {
            Ok(Some(page)) => {
                for o in page["offers"].as_array().into_iter().flatten() {
                    match offer_from_indexer(o, Some(&n.name)) {
                        Ok(rec) => offers.push(rec),
                        Err(e) => skipped.push((n.name.clone(), e.to_string())),
                    }
                }
            }
            Ok(None) => skipped.push((n.name, "not found".into())),
            Err(e) => skipped.push((n.name, e.to_string())),
        }
    }
    Ok(Collected { offers, skipped, source: "/names/all + /names/<name>/offers (registered names only)" })
}

/// How a row is named in a skip report: its outpoint, else its name, else the row.
fn row_label(o: &Value) -> String {
    let op = &o["outpoint"];
    match (op["txId"].as_str().or(op["transactionId"].as_str()).or(op.as_str()), op["index"].as_u64()) {
        (Some(id), Some(i)) => format!("offer {id}:{i}"),
        (Some(id), None) => format!("offer {id}"),
        _ => o["name"].as_str().map(|n| format!("an offer on {n}")).unwrap_or_else(|| format!("offer {o}")),
    }
}

/// A node or relay answer that means "this offer was already spent", by another keeper
/// or by its buyer or seller: a race, not a failure.
pub fn already_spent(err: &str) -> bool {
    let e = err.to_lowercase();
    ["double spend", "already spent", "spent by", "missing outpoint", "orphan", "not in the utxo set"].iter().any(|m| e.contains(m))
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
