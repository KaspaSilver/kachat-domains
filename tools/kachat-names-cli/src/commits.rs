//! Salted commits, kept in `.secrets/commits.json` (mode 600): the salt is
//! what keeps a pending name private until it is registered.

use anyhow::{Result, anyhow};
use kaspa_consensus_core::tx::TransactionOutpoint;
use serde_json::{Value, json};

use crate::{
    keys::write_secret_json,
    paths::Paths,
    util::{fmt_outpoint, hex, parse_outpoint, unhex32},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitRec {
    pub name: String,
    pub owner: [u8; 32],
    pub salt: [u8; 32],
    pub value: u64,
    /// set once the commit transaction is submitted (output 0 of it)
    pub outpoint: Option<TransactionOutpoint>,
    /// set when a registration spent it
    pub used_by: Option<String>,
    pub created_ms: i64,
}

impl CommitRec {
    fn to_json(&self) -> Value {
        json!({
            "name": self.name, "owner": hex(&self.owner), "salt": hex(&self.salt), "value": self.value,
            "outpoint": self.outpoint.map(|o| fmt_outpoint(&o)), "usedBy": self.used_by, "createdMs": self.created_ms,
        })
    }

    fn from_json(v: &Value) -> Result<Self> {
        let s = |k: &str| v[k].as_str().ok_or_else(|| anyhow!("commit: missing {k}"));
        Ok(CommitRec {
            name: s("name")?.to_string(),
            owner: unhex32(s("owner")?)?,
            salt: unhex32(s("salt")?)?,
            value: v["value"].as_u64().ok_or_else(|| anyhow!("commit: missing value"))?,
            outpoint: v["outpoint"].as_str().map(parse_outpoint).transpose()?,
            used_by: v["usedBy"].as_str().map(str::to_string),
            created_ms: v["createdMs"].as_i64().unwrap_or(0),
        })
    }
}

pub fn load(paths: &Paths) -> Result<Vec<CommitRec>> {
    let p = paths.commits();
    if !p.exists() {
        return Ok(vec![]);
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p)?)?;
    v["commits"].as_array().cloned().unwrap_or_default().iter().map(CommitRec::from_json).collect()
}

pub fn save(paths: &Paths, commits: &[CommitRec]) -> Result<()> {
    write_secret_json(paths, &paths.commits(), &json!({ "commits": commits.iter().map(CommitRec::to_json).collect::<Vec<_>>() }))
}

/// The newest unused, submitted commit for `name` by `owner`.
pub fn find_open<'a>(commits: &'a [CommitRec], name: &str, owner: &[u8; 32]) -> Option<&'a CommitRec> {
    commits.iter().rev().find(|c| c.name == name && c.owner == *owner && c.outpoint.is_some() && c.used_by.is_none())
}
