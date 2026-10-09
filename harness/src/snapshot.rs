//! The migration snapshot (registry v5): a fixed-depth Merkle tree over the
//! names of a predecessor registry, exactly as `contracts/v5/KachatGap.sil`
//! `import` checks it.
//!
//! - Leaf: `blake3("kachat-snapshot-leaf:v1" || key || owner || num8(periodStart) || num8(expiresAt))`.
//!   `num8` is what the contract's `as byte[8]` (OpNum2Bin 8) produces.
//! - Leaves in key order from index 0; the rest of the 2^20 slots are empty
//!   (32 zero bytes, which no leaf hash can be).
//! - Node: `blake3(left || right)`.
//! - Proof: the sibling at each level, leaf level first; bit i of the index
//!   says whether the path is the right child at level i.
//!
//! Anyone can rebuild the root from the predecessor registry's state at the
//! snapshot block, so a deployer cannot slip in or leave out a name unseen.

use crate::{NameFields, num8};

/// Depth of every snapshot tree (`SNAPSHOT_DEPTH` in the contract).
pub const DEPTH: usize = 20;
/// Most names one snapshot holds.
pub const CAPACITY: usize = 1 << DEPTH;
const LEAF_TAG: &[u8] = b"kachat-snapshot-leaf:v1";

/// One name as the snapshot records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: [u8; 32],
    pub owner: [u8; 32],
    pub period_start: i64,
    pub expires_at: i64,
}

impl Entry {
    pub fn of(f: &NameFields) -> Entry {
        Entry { key: f.key, owner: f.owner, period_start: f.period_start, expires_at: f.expires_at }
    }

    pub fn leaf(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(LEAF_TAG);
        h.update(&self.key);
        h.update(&self.owner);
        h.update(&num8(self.period_start));
        h.update(&num8(self.expires_at));
        *h.finalize().as_bytes()
    }
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// The tree over a set of entries (sorted by key here; keys must be distinct).
pub struct Snapshot {
    pub entries: Vec<Entry>,
    /// levels[0] = the leaves present, levels[d] = the nodes at height d that
    /// cover at least one leaf (the rest are `empty[d]`).
    levels: Vec<Vec<[u8; 32]>>,
    empty: Vec<[u8; 32]>,
}

impl Snapshot {
    pub fn new(mut entries: Vec<Entry>) -> Snapshot {
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        assert!(entries.windows(2).all(|w| w[0].key < w[1].key), "duplicate key in a snapshot");
        assert!(entries.len() <= CAPACITY, "more than 2^{DEPTH} names");
        let mut empty = vec![[0u8; 32]];
        for d in 0..DEPTH {
            empty.push(node(&empty[d], &empty[d]));
        }
        let mut levels = vec![entries.iter().map(Entry::leaf).collect::<Vec<_>>()];
        for d in 0..DEPTH {
            let below = &levels[d];
            let up = (0..below.len().div_ceil(2))
                .map(|i| node(&below[2 * i], below.get(2 * i + 1).unwrap_or(&empty[d])))
                .collect();
            levels.push(up);
        }
        Snapshot { entries, levels, empty }
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels[DEPTH].first().copied().unwrap_or(self.empty[DEPTH])
    }

    /// Index of `key` in the snapshot.
    pub fn index_of(&self, key: &[u8; 32]) -> Option<usize> {
        self.entries.binary_search_by(|e| e.key.cmp(key)).ok()
    }

    /// The 640-byte proof for the leaf at `index`.
    pub fn proof(&self, index: usize) -> Vec<u8> {
        assert!(index < self.entries.len());
        let mut out = Vec::with_capacity(32 * DEPTH);
        let mut i = index;
        for d in 0..DEPTH {
            let sibling = self.levels[d].get(i ^ 1).copied().unwrap_or(self.empty[d]);
            out.extend_from_slice(&sibling);
            i /= 2;
        }
        out
    }

    /// Recompute a root from a leaf, an index and a proof (what the contract does).
    pub fn root_from(leaf: [u8; 32], index: usize, proof: &[u8]) -> [u8; 32] {
        let mut h = leaf;
        let mut i = index;
        for d in 0..DEPTH {
            let s: [u8; 32] = proof[32 * d..32 * d + 32].try_into().unwrap();
            h = if i % 2 == 0 { node(&h, &s) } else { node(&s, &h) };
            i /= 2;
        }
        h
    }
}
