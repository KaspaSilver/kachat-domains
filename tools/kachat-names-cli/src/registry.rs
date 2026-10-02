//! Registry state without an indexer.
//!
//! The registry is the set of UTXOs carrying the registry covenant id: gaps
//! and names. A P2SH address commits to the whole redeem script, and the
//! redeem script embeds the state, so a (state -> address) pair can be checked
//! against the node with GetUtxosByAddresses: a UTXO at that address with the
//! registry covenant id *is* that state, live. This module keeps the decoded
//! states, starting from the genesis gap in the manifest, and moves them
//! forward one transaction at a time with [`Registry::apply`], which decodes a
//! transaction's registry spends from their signature scripts (entry tag +
//! arguments + revealed redeem) and predicts every registry output it must
//! create. Every registry output must be predicted exactly, or the
//! transaction is refused and the state is left untouched.
//!
//! Two feeds use the same `apply`: the transactions this CLI submits, and the
//! chain scanner (`scan`, GetVirtualChainFromBlockV2 with accepted
//! transactions) for everyone else's.
//!
//! Offers carry no covenant id; the CLI tracks the ones it creates.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use kachat_names_harness::{
    FF32, Kit, NameFields, OfferFields, Template, TransactionOutput, YEAR_MS, ZERO32, gap_state, name_key, pad_name,
    scenarios::name_len,
};
use kaspa_consensus_core::tx::{Transaction, TransactionId, TransactionOutpoint};
use kaspa_hashes::Hash;
use serde_json::{Value, json};

use crate::{
    net::{p2pk_address, spk_address},
    util::{fmt_ms, fmt_outpoint, hex, num8_decode, parse_outpoint, parse_pushes, script_num, unhex32},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GapRec {
    pub outpoint: TransactionOutpoint,
    pub lo: [u8; 32],
    pub hi: [u8; 32],
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameRec {
    pub outpoint: TransactionOutpoint,
    pub fields: NameFields,
    pub value: u64,
}

impl NameRec {
    pub fn name(&self) -> String {
        name_str(&self.fields.name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferRec {
    pub outpoint: TransactionOutpoint,
    pub fields: OfferFields,
    pub value: u64,
    /// the wanted name, when known (the state holds only its key)
    pub name: Option<String>,
}

pub fn name_str(padded: &[u8; 32]) -> String {
    String::from_utf8_lossy(&padded[..name_len(padded)]).into_owned()
}

#[derive(Clone, Debug)]
pub struct Registry {
    pub registry_id: Hash,
    pub gaps: Vec<GapRec>,
    pub names: Vec<NameRec>,
    pub offers: Vec<OfferRec>,
    /// chain block the scanner continues from
    pub scan_from: Option<Hash>,
    /// transactions already applied (most recent last, bounded)
    pub applied: Vec<TransactionId>,
}

const APPLIED_KEEP: usize = 4096;

/// A transaction as the decoder sees it.
#[derive(Clone, Debug)]
pub struct TxView {
    pub id: TransactionId,
    pub inputs: Vec<(TransactionOutpoint, Vec<u8>)>,
    pub outputs: Vec<TransactionOutput>,
    pub payload: Vec<u8>,
}

impl From<&Transaction> for TxView {
    fn from(tx: &Transaction) -> Self {
        TxView {
            id: tx.id(),
            inputs: tx.inputs.iter().map(|i| (i.previous_outpoint, i.signature_script.clone())).collect(),
            outputs: tx.outputs.clone(),
            payload: tx.payload.clone(),
        }
    }
}

/// An offer announced by the `kchat:1:offer:<keyHex>:<buyerXonlyHex>:<refundAfterDaa>`
/// payload marker, if one of the outputs really is that offer
/// (P2SH(offer prefix || state || suffix)). Returns (output index, fields).
pub fn offer_from_marker(kit: &Kit, tx: &TxView) -> Option<(usize, OfferFields)> {
    let text = std::str::from_utf8(&tx.payload).ok()?;
    let rest = text.strip_prefix("kchat:1:offer:")?;
    let mut parts = rest.split(':');
    let key = unhex32(parts.next()?).ok()?;
    let buyer = unhex32(parts.next()?).ok()?;
    let refund_after: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || refund_after < 0 {
        return None;
    }
    let fields = OfferFields { key, buyer, refund_after };
    let spk = kit.offer.spk(&fields.encode());
    let idx = tx.outputs.iter().position(|o| o.script_public_key == spk && o.covenant.is_none())?;
    Some((idx, fields))
}

/// One decoded P2SH spend: `<args> <tag> <redeem>`.
struct Spend {
    args: Vec<Vec<u8>>,
    entry: String,
    redeem: Vec<u8>,
}

fn decode_spend(tpl: &Template, sig_script: &[u8]) -> Result<Spend> {
    let mut pushes = parse_pushes(sig_script)?;
    let redeem = pushes.pop().ok_or_else(|| anyhow!("empty signature script"))?;
    let tag = pushes.pop().ok_or_else(|| anyhow!("no dispatch tag"))?;
    let tag_hex = hex(&tag);
    let entry = tpl.abi.contracts[&tpl.contract]
        .entries
        .iter()
        .find(|(_, e)| e.dispatch_tag.to_hex() == tag_hex)
        .map(|(n, _)| n.clone())
        .ok_or_else(|| anyhow!("unknown {} dispatch tag {tag_hex}", tpl.contract))?;
    Ok(Spend { args: pushes, entry, redeem })
}

fn arg32(args: &[Vec<u8>], i: usize) -> Result<[u8; 32]> {
    args.get(i).and_then(|a| <[u8; 32]>::try_from(a.as_slice()).ok()).ok_or_else(|| anyhow!("argument {i} is not 32 bytes"))
}

fn arg_int(args: &[Vec<u8>], i: usize) -> Result<i64> {
    script_num(args.get(i).ok_or_else(|| anyhow!("missing argument {i}"))?)
}

/// What a registry spend predicts for the outputs.
enum Predicted {
    Gap { lo: [u8; 32], hi: [u8; 32] },
    Name(NameFields),
}

impl Registry {
    /// The registry right after genesis: the lone genesis gap.
    pub fn at_genesis(registry_id: Hash, genesis_txid: TransactionId, gap_value: u64, scan_from: Option<Hash>) -> Self {
        Registry {
            registry_id,
            gaps: vec![GapRec { outpoint: TransactionOutpoint::new(genesis_txid, 0), lo: ZERO32, hi: FF32, value: gap_value }],
            names: vec![],
            offers: vec![],
            scan_from,
            applied: vec![genesis_txid],
        }
    }

    pub fn gap_for_key(&self, key: &[u8; 32]) -> Option<&GapRec> {
        self.gaps.iter().find(|g| g.lo < *key && *key < g.hi)
    }

    pub fn name(&self, name: &str) -> Option<&NameRec> {
        let key = name_key(name.as_bytes());
        self.names.iter().find(|n| n.fields.key == key)
    }

    /// The gaps on either side of a registered key: (lo, key) and (key, hi).
    pub fn neighbours(&self, key: &[u8; 32]) -> Option<(&GapRec, &GapRec)> {
        let below = self.gaps.iter().find(|g| g.hi == *key)?;
        let above = self.gaps.iter().find(|g| g.lo == *key)?;
        Some((below, above))
    }

    pub fn offers_for(&self, key: &[u8; 32]) -> Vec<&OfferRec> {
        self.offers.iter().filter(|o| o.fields.key == *key).collect()
    }

    /// Sanity: the gaps and names tile the key space exactly.
    pub fn check_invariants(&self) -> Result<()> {
        let mut gaps = self.gaps.clone();
        gaps.sort_by_key(|g| g.lo);
        let mut keys: Vec<[u8; 32]> = self.names.iter().map(|n| n.fields.key).collect();
        keys.sort();
        if gaps.len() != keys.len() + 1 {
            bail!("{} gaps for {} names", gaps.len(), keys.len());
        }
        let mut cur = ZERO32;
        for (i, g) in gaps.iter().enumerate() {
            if g.lo != cur {
                bail!("gap {i} starts at {} instead of {}", hex(&g.lo), hex(&cur));
            }
            if g.lo >= g.hi {
                bail!("gap {i} is empty");
            }
            if i < keys.len() {
                if keys[i] != g.hi {
                    bail!("gap {i} ends at {} but the next name is {}", hex(&g.hi), hex(&keys[i]));
                }
                cur = keys[i];
            } else if g.hi != FF32 {
                bail!("the last gap ends at {}", hex(&g.hi));
            }
        }
        Ok(())
    }

    /// Apply one transaction. Returns human-readable events; an irrelevant
    /// transaction returns none. On error nothing changes.
    pub fn apply(&mut self, kit: &Kit, tx: &TxView) -> Result<Vec<String>> {
        if self.applied.contains(&tx.id) {
            return Ok(vec![]);
        }
        let reg_outs: Vec<usize> = tx
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, o)| o.covenant.is_some_and(|c| c.covenant_id == self.registry_id))
            .map(|(i, _)| i)
            .collect();
        let gap_ins: Vec<(usize, GapRec)> = tx
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(i, (op, _))| self.gaps.iter().find(|g| g.outpoint == *op).map(|g| (i, g.clone())))
            .collect();
        let name_ins: Vec<(usize, NameRec)> = tx
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(i, (op, _))| self.names.iter().find(|n| n.outpoint == *op).map(|n| (i, n.clone())))
            .collect();
        let offer_ins: Vec<(usize, OfferRec)> = tx
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(i, (op, _))| self.offers.iter().find(|o| o.outpoint == *op).map(|o| (i, o.clone())))
            .collect();
        let new_offer = offer_from_marker(kit, tx);
        if reg_outs.is_empty() && gap_ins.is_empty() && name_ins.is_empty() && offer_ins.is_empty() && new_offer.is_none() {
            return Ok(vec![]);
        }
        let id = tx.id;
        let mut events = Vec::new();
        // (authorizing input, output state)
        let mut predicted: Vec<(u16, Predicted)> = Vec::new();

        for (i, g) in &gap_ins {
            let sp = decode_spend(&kit.gap, &tx.inputs[*i].1).with_context(|| format!("{id}: gap input {i}"))?;
            if sp.redeem != kit.gap.redeem(&gap_state(&g.lo, &g.hi)) {
                bail!("{id}: gap input {i} reveals a redeem script that is not the tracked gap state");
            }
            match sp.entry.as_str() {
                "register" => {
                    let name = sp.args.first().ok_or_else(|| anyhow!("register without a name"))?.clone();
                    let owner = arg32(&sp.args, 1)?;
                    let now = arg_int(&sp.args, 3)?;
                    let years = arg_int(&sp.args, 4)?;
                    let key = name_key(&name);
                    let f = NameFields::new(&name, &owner, 0, now + years * YEAR_MS);
                    predicted.push((*i as u16, Predicted::Gap { lo: g.lo, hi: key }));
                    predicted.push((*i as u16, Predicted::Gap { lo: key, hi: g.hi }));
                    events.push(format!(
                        "register {} for {} until {} ({} y, now = {})",
                        String::from_utf8_lossy(&name),
                        p2pk_address(&owner),
                        fmt_ms(f.expires_at),
                        years,
                        fmt_ms(now)
                    ));
                    predicted.push((*i as u16, Predicted::Name(f)));
                }
                "merge" => {
                    let succ = gap_ins
                        .iter()
                        .find(|(j, s)| *j == 2 && s.lo == g.hi)
                        .map(|(_, s)| s.clone())
                        .ok_or_else(|| anyhow!("{id}: merge without the tracked successor gap at input 2"))?;
                    predicted.push((*i as u16, Predicted::Gap { lo: g.lo, hi: succ.hi }));
                }
                "absorbed" => {}
                e => bail!("{id}: unexpected gap entry {e}"),
            }
        }

        for (i, n) in &name_ins {
            let sp = decode_spend(&kit.name, &tx.inputs[*i].1).with_context(|| format!("{id}: name input {i}"))?;
            if sp.redeem != kit.name.redeem(&n.fields.encode()) {
                bail!("{id}: name input {i} reveals a redeem script that is not the tracked name state");
            }
            let f = &n.fields;
            let nm = n.name();
            match sp.entry.as_str() {
                "transfer" => {
                    let to = arg32(&sp.args, 0)?;
                    events.push(format!("transfer {nm} to {}", p2pk_address(&to)));
                    predicted.push((*i as u16, Predicted::Name(f.with_owner(&to))));
                }
                "list" => {
                    let price = arg_int(&sp.args, 0)?;
                    events.push(if price == 0 {
                        format!("delist {nm}")
                    } else {
                        format!("list {nm} at {}", crate::util::fmt_kas(price as u64))
                    });
                    predicted.push((*i as u16, Predicted::Name(f.with_price(price))));
                }
                "buy" => {
                    let to = arg32(&sp.args, 0)?;
                    events.push(format!("buy {nm} for {} by {}", crate::util::fmt_kas(f.price as u64), p2pk_address(&to)));
                    predicted.push((*i as u16, Predicted::Name(f.with_owner(&to))));
                }
                "renew" => {
                    let years = arg_int(&sp.args, 0)?;
                    let nf = f.with_expiry(f.expires_at + years * YEAR_MS);
                    events.push(format!("renew {nm} by {years} y, until {}", fmt_ms(nf.expires_at)));
                    predicted.push((*i as u16, Predicted::Name(nf)));
                }
                "release" => events.push(format!("release {nm}")),
                "reclaim" => events.push(format!("reclaim {nm} (bond back to {})", p2pk_address(&f.owner))),
                e => bail!("{id}: unexpected name entry {e}"),
            }
        }

        for (i, o) in &offer_ins {
            let sp = decode_spend(&kit.offer, &tx.inputs[*i].1).with_context(|| format!("{id}: offer input {i}"))?;
            let what = o.name.clone().unwrap_or_else(|| hex(&o.fields.key[..8]));
            events.push(format!("offer {} on {what}: {}", crate::util::fmt_kas(o.value), sp.entry));
        }

        // Match predictions to the registry outputs, one to one.
        let mut matched: BTreeMap<usize, Predicted> = BTreeMap::new();
        for (auth, p) in predicted {
            let spk = match &p {
                Predicted::Gap { lo, hi } => kit.gap.spk(&gap_state(lo, hi)),
                Predicted::Name(f) => kit.name.spk(&f.encode()),
            };
            let idx = reg_outs
                .iter()
                .copied()
                .find(|j| {
                    !matched.contains_key(j)
                        && tx.outputs[*j].script_public_key == spk
                        && tx.outputs[*j].covenant.is_some_and(|c| c.authorizing_input == auth)
                })
                .ok_or_else(|| anyhow!("{id}: predicted registry output not found (authorized by input {auth})"))?;
            matched.insert(idx, p);
        }
        if let Some(extra) = reg_outs.iter().find(|j| !matched.contains_key(j)) {
            bail!(
                "{id}: registry output {extra} is not explained by any tracked registry input; the local state is stale (run `scan`)"
            );
        }

        // Commit the change.
        let spent: Vec<TransactionOutpoint> = tx.inputs.iter().map(|(op, _)| *op).collect();
        self.gaps.retain(|g| !spent.contains(&g.outpoint));
        self.names.retain(|n| !spent.contains(&n.outpoint));
        self.offers.retain(|o| !spent.contains(&o.outpoint));
        for (idx, p) in matched {
            let op = TransactionOutpoint::new(id, idx as u32);
            let value = tx.outputs[idx].value;
            match p {
                Predicted::Gap { lo, hi } => self.gaps.push(GapRec { outpoint: op, lo, hi, value }),
                Predicted::Name(fields) => self.names.push(NameRec { outpoint: op, fields, value }),
            }
        }
        if let Some((idx, fields)) = new_offer {
            let op = TransactionOutpoint::new(id, idx as u32);
            let known = self.names.iter().find(|n| n.fields.key == fields.key).map(|n| n.name());
            events.push(format!(
                "offer {} on {} by {} (refundAfter DAA {})",
                crate::util::fmt_kas(tx.outputs[idx].value),
                known.clone().unwrap_or_else(|| hex(&fields.key[..8])),
                p2pk_address(&fields.buyer),
                fields.refund_after
            ));
            self.offers.retain(|o| o.outpoint != op);
            self.offers.push(OfferRec { outpoint: op, fields, value: tx.outputs[idx].value, name: known });
        }
        self.applied.push(id);
        if self.applied.len() > APPLIED_KEEP {
            let n = self.applied.len() - APPLIED_KEEP;
            self.applied.drain(..n);
        }
        Ok(events)
    }

    pub fn track_offer(&mut self, rec: OfferRec) {
        self.offers.retain(|o| o.outpoint != rec.outpoint);
        self.offers.push(rec);
    }

    // -- persistence ---------------------------------------------------------

    pub fn to_json(&self) -> Value {
        json!({
            "registryCovenantId": self.registry_id.to_string(),
            "scanFrom": self.scan_from.map(|h| h.to_string()),
            "gaps": self.gaps.iter().map(|g| json!({
                "outpoint": fmt_outpoint(&g.outpoint), "lo": hex(&g.lo), "hi": hex(&g.hi), "value": g.value,
            })).collect::<Vec<_>>(),
            "names": self.names.iter().map(|n| json!({
                "outpoint": fmt_outpoint(&n.outpoint), "name": n.name(), "key": hex(&n.fields.key),
                "owner": hex(&n.fields.owner), "price": n.fields.price, "expiresAt": n.fields.expires_at, "value": n.value,
            })).collect::<Vec<_>>(),
            "offers": self.offers.iter().map(|o| json!({
                "outpoint": fmt_outpoint(&o.outpoint), "key": hex(&o.fields.key), "name": o.name,
                "buyer": hex(&o.fields.buyer), "refundAfter": o.fields.refund_after, "value": o.value,
            })).collect::<Vec<_>>(),
            "applied": self.applied.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        let s = |v: &Value, k: &str| -> Result<String> { v[k].as_str().map(str::to_string).ok_or_else(|| anyhow!("missing {k}")) };
        let u = |v: &Value, k: &str| -> Result<u64> { v[k].as_u64().ok_or_else(|| anyhow!("missing {k}")) };
        let i = |v: &Value, k: &str| -> Result<i64> { v[k].as_i64().ok_or_else(|| anyhow!("missing {k}")) };
        let arr = |k: &str| v[k].as_array().cloned().unwrap_or_default();
        let mut gaps = vec![];
        for g in arr("gaps") {
            gaps.push(GapRec {
                outpoint: parse_outpoint(&s(&g, "outpoint")?)?,
                lo: unhex32(&s(&g, "lo")?)?,
                hi: unhex32(&s(&g, "hi")?)?,
                value: u(&g, "value")?,
            });
        }
        let mut names = vec![];
        for n in arr("names") {
            let name = s(&n, "name")?;
            let fields = NameFields {
                key: unhex32(&s(&n, "key")?)?,
                name: pad_name(name.as_bytes()),
                owner: unhex32(&s(&n, "owner")?)?,
                price: i(&n, "price")?,
                expires_at: i(&n, "expiresAt")?,
            };
            if fields.key != name_key(name.as_bytes()) {
                bail!("state: key of {name} does not match");
            }
            names.push(NameRec { outpoint: parse_outpoint(&s(&n, "outpoint")?)?, fields, value: u(&n, "value")? });
        }
        let mut offers = vec![];
        for o in arr("offers") {
            offers.push(OfferRec {
                outpoint: parse_outpoint(&s(&o, "outpoint")?)?,
                fields: OfferFields {
                    key: unhex32(&s(&o, "key")?)?,
                    buyer: unhex32(&s(&o, "buyer")?)?,
                    refund_after: i(&o, "refundAfter")?,
                },
                value: u(&o, "value")?,
                name: o["name"].as_str().map(str::to_string),
            });
        }
        let applied = arr("applied")
            .iter()
            .filter_map(|t| t.as_str())
            .map(|t| unhex32(t).map(TransactionId::from_bytes))
            .collect::<Result<Vec<_>>>()?;
        Ok(Registry {
            registry_id: Hash::from_bytes(unhex32(&s(v, "registryCovenantId")?)?),
            gaps,
            names,
            offers,
            scan_from: v["scanFrom"].as_str().map(|h| unhex32(h).map(Hash::from_bytes)).transpose()?,
            applied,
        })
    }

    pub fn load(path: &std::path::Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        Ok(Some(Self::from_json(&v)?))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&self.to_json())? + "\n")?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    /// Every tracked UTXO with its P2SH address (for GetUtxosByAddresses).
    pub fn tracked(&self, kit: &Kit) -> Result<Vec<Tracked>> {
        let mut out = vec![];
        for g in &self.gaps {
            let spk = kit.gap.spk(&gap_state(&g.lo, &g.hi));
            out.push(Tracked { kind: "gap", label: format!("gap ({}.., {}..)", hex(&g.lo[..4]), hex(&g.hi[..4])), outpoint: g.outpoint, address: spk_address(&spk)?, value: g.value, registry: true });
        }
        for n in &self.names {
            let spk = kit.name.spk(&n.fields.encode());
            out.push(Tracked { kind: "name", label: n.name(), outpoint: n.outpoint, address: spk_address(&spk)?, value: n.value, registry: true });
        }
        for o in &self.offers {
            let spk = kit.offer.spk(&o.fields.encode());
            let label = format!("offer on {}", o.name.clone().unwrap_or_else(|| hex(&o.fields.key[..8])));
            out.push(Tracked { kind: "offer", label, outpoint: o.outpoint, address: spk_address(&spk)?, value: o.value, registry: false });
        }
        Ok(out)
    }
}

#[derive(Clone, Debug)]
pub struct Tracked {
    pub kind: &'static str,
    pub label: String,
    pub outpoint: TransactionOutpoint,
    pub address: kaspa_addresses::Address,
    pub value: u64,
    /// carries the registry covenant id
    pub registry: bool,
}

/// Decode a name state from its 117 bytes (for display / checks).
pub fn decode_name_state(state: &[u8]) -> Result<NameFields> {
    if state.len() != 117 || state[0] != 0x20 || state[33] != 0x20 || state[66] != 0x20 || state[99] != 0x08 || state[108] != 0x08 {
        bail!("not a name state");
    }
    Ok(NameFields {
        key: state[1..33].try_into().unwrap(),
        name: state[34..66].try_into().unwrap(),
        owner: state[67..99].try_into().unwrap(),
        price: num8_decode(&state[100..108])?,
        expires_at: num8_decode(&state[109..117])?,
    })
}
