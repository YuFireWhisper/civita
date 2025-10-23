use std::collections::{HashMap, HashSet};

use multihash_derive::MultihashDigest;
use rocksdb::{ColumnFamily, WriteBatch, DB};

use crate::crypto::{hasher::Hasher, Multihash};

#[derive(Clone)]
#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct MmrProof {
    pub idx: u64,
    pub hashes: Vec<Multihash>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(PartialEq, Eq)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct State(u64, Vec<Multihash>);

#[derive(Default)]
pub struct Mmr {
    entries: HashMap<u64, Multihash>,
    next: u64,
    vleaves: u64,
    staged_create: Vec<Multihash>,
    staged_delete: Vec<u64>,

    peaks: Vec<u64>,
    peak_hashes: Vec<Multihash>,
}

impl MmrProof {
    pub fn new(hashes: Vec<Multihash>, idx: u64) -> Self {
        Self { hashes, idx }
    }
}

impl Mmr {
    pub fn new(state: State) -> Option<Self> {
        if state.0 == 0 {
            return Some(Mmr::default());
        }

        let peak_indices = peak_indices(state.0 - 1);

        if peak_indices.len() != state.1.len() {
            return None;
        }

        let entries = HashMap::from_iter(peak_indices.iter().copied().zip(state.1.iter().copied()));

        Some(Mmr {
            entries,
            next: state.0,
            vleaves: leaves_from_size(state.0),
            staged_create: vec![],
            staged_delete: vec![],
            peaks: peak_indices,
            peak_hashes: state.1,
        })
    }

    /// Returns index of appended leaf (not next index)
    pub fn append(&mut self, hash: Multihash) -> u64 {
        let idx = 2 * self.vleaves - self.vleaves.count_ones() as u64;
        self.vleaves += 1;
        self.staged_create.push(hash);
        idx
    }

    pub fn delete(&mut self, hash: Multihash, proof: &MmrProof) -> bool {
        let Some(fs) = self.resolve(hash, proof) else {
            return false;
        };

        self.entries.extend(fs);
        self.staged_delete.push(proof.idx);

        true
    }

    fn resolve(&self, hash: Multihash, proof: &MmrProof) -> Option<HashMap<u64, Multihash>> {
        let peak = peak_of(&self.peaks, &proof.idx)?;

        if proof.idx == peak {
            return proof.hashes.is_empty().then(HashMap::new);
        }

        let mut idx = proof.idx;
        let mut acc = hash;
        let mut g = index_height(idx);
        let mut fills: HashMap<u64, Multihash> = HashMap::new();

        for hash in &proof.hashes {
            fills.insert(idx, acc);

            let offset = 2u64 << g;
            if index_height(idx + 1) > g {
                idx += 1;
                fills.insert(idx - offset, *hash);
                acc = hash_pospair(idx + 1, hash, &acc);
            } else {
                idx += offset;
                fills.insert(idx - 1, *hash);
                acc = hash_pospair(idx + 1, &acc, hash);
            }

            g += 1;
        }

        if idx != peak || acc != self.entries[&peak] {
            return None;
        }

        Some(fills)
    }

    pub fn commit(&mut self) {
        let created = std::mem::take(&mut self.staged_create);
        let deleted = std::mem::take(&mut self.staged_delete);

        deleted.into_iter().for_each(|idx| {
            self.entries.insert(idx, Multihash::default());
            self.recalculate_parents(idx);
        });

        created.into_iter().for_each(|h| {
            let mut g = 0usize;
            let mut i = self.insert(h);

            while index_height(i) > g {
                let il = i - (2u64 << g);
                let ir = i - 1;
                i = self.insert(hash_pospair(i + 1, &self.entries[&il], &self.entries[&ir]));
                g += 1;
            }
        });

        self.peaks = peak_indices(self.next - 1);
        self.peak_hashes = self.peaks.iter().map(|i| self.entries[i]).collect();
    }

    fn recalculate_parents(&mut self, mut idx: u64) {
        let mut g = index_height(idx);
        let mut c = Multihash::default();
        let peak = peak_of(&self.peaks, &idx).unwrap();

        while idx != peak {
            let offset = 2u64 << g;

            if index_height(idx + 1) > g {
                idx += 1;
                let h = hash_pospair(idx + 1, &self.entries[&(idx - offset)], &c);
                self.entries.insert(idx, h);
            } else {
                idx += offset;
                let h = hash_pospair(idx + 1, &c, &self.entries[&(idx - 1)]);
                self.entries.insert(idx, h);
            }

            g += 1;
            c = self.entries[&idx];
        }
    }

    /// Returns next index
    fn insert(&mut self, hash: Multihash) -> u64 {
        self.entries.insert(self.next, hash);
        self.next += 1;
        self.next
    }

    pub fn prove(&self, idx: u64) -> Option<MmrProof> {
        self.prove_inner(idx, |_| None)
    }

    fn prove_inner<F>(&self, mut idx: u64, mut f: F) -> Option<MmrProof>
    where
        F: FnMut(u64) -> Option<Multihash>,
    {
        let peak = peak_of(&self.peaks, &idx)?;
        let mut proof = MmrProof::new(vec![], idx);

        if idx == peak {
            return Some(proof);
        }

        let mut g = index_height(idx);

        loop {
            let offset = 2u64 << g;

            let is = if index_height(idx + 1) > g {
                idx += 1;
                idx - offset
            } else {
                idx += offset;
                idx - 1
            };

            if is > peak {
                return Some(proof);
            }

            let h = self.entries.get(&is).copied().or_else(|| f(is))?;
            proof.hashes.push(h);
            g += 1;
        }
    }

    pub fn prove_with_db(&self, idx: u64, db: &DB) -> Option<MmrProof> {
        self.prove_inner(idx, |i| {
            db.get(i.to_le_bytes())
                .ok()
                .flatten()
                .and_then(|v| Multihash::from_bytes(&v).ok())
        })
    }

    pub fn prove_with_cf(&self, idx: u64, db: &DB, cf: &ColumnFamily) -> Option<MmrProof> {
        self.prove_inner(idx, |i| {
            db.get_cf(cf, i.to_le_bytes())
                .ok()
                .flatten()
                .and_then(|v| Multihash::from_bytes(&v).ok())
        })
    }

    pub fn state(&self) -> State {
        State(self.next, self.peak_hashes.clone())
    }

    pub fn verify(&self, hash: Multihash, proof: &MmrProof) -> bool {
        self.resolve(hash, proof).is_some()
    }

    pub fn prune(&mut self, indices: &[u64]) -> bool {
        let indices = pruned_indices(self.next - 1, indices);
        let mut entries = HashMap::with_capacity(indices.len());

        for i in indices {
            if let Some(h) = self.entries.get(&i) {
                entries.insert(i, *h);
            } else {
                return false;
            }
        }

        self.entries = entries;
        true
    }

    pub fn resolve_and_fill(&mut self, hash: Multihash, proof: &MmrProof) -> bool {
        let Some(fs) = self.resolve(hash, proof) else {
            return false;
        };
        self.entries.extend(fs);
        true
    }

    pub fn write_cf(&mut self, cf: &ColumnFamily, batch: &mut WriteBatch) {
        let entries = HashMap::from_iter(self.peaks.iter().map(|p| (*p, self.entries[p])));
        self.entries
            .drain()
            .for_each(|(k, v)| batch.put_cf(cf, k.to_le_bytes(), v.to_bytes()));
        self.entries = entries;
    }
}

fn index_height(i: u64) -> usize {
    let mut pos = i + 1;

    while !(pos + 1).is_power_of_two() {
        pos = pos - (1 << (u64::BITS - pos.leading_zeros() - 1)) + 1;
    }

    (u64::BITS - pos.leading_zeros()).saturating_sub(1) as usize
}

fn hash_pospair(idx: u64, l: &Multihash, r: &Multihash) -> Multihash {
    use bincode::{config, serde::encode_into_std_write};

    let mut buf = Vec::new();
    encode_into_std_write(idx, &mut buf, config::standard()).unwrap();
    encode_into_std_write(l, &mut buf, config::standard()).unwrap();
    encode_into_std_write(r, &mut buf, config::standard()).unwrap();
    Hasher::default().digest(&buf)
}

fn peak_indices(s: u64) -> Vec<u64> {
    let mut peak = 0;
    let mut peaks = Vec::new();
    let mut s = s + 1;

    while s != 0 {
        let size = (1 << (u64::BITS - (s + 1).leading_zeros() - 1)) - 1;
        peak += size;
        peaks.push(peak - 1);
        s -= size;
    }

    peaks
}

fn leaves_from_size(size: u64) -> u64 {
    if size == 0 {
        return 0;
    }
    let mut lo = 0u64;
    let mut hi = size;
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let msize = 2 * mid - mid.count_ones() as u64;
        if msize <= size {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

fn peak_of(peaks: &[u64], idx: &u64) -> Option<u64> {
    peaks.last().filter(|p| p >= &idx)?;
    let pos = peaks.partition_point(|p| p < idx);
    Some(*peaks.get(pos).unwrap_or_else(|| &peaks[pos - 1]))
}

fn pruned_indices(size: u64, leaves: &[u64]) -> HashSet<u64> {
    let peaks = HashSet::<u64>::from_iter(peak_indices(size));
    let mut indices = peaks.clone();

    for l in leaves {
        let mut cur = *l;
        let mut g = index_height(cur);

        while !peaks.contains(&cur) {
            indices.insert(cur);

            let offset = 2u64 << g;
            let is = if index_height(cur + 1) > g {
                cur += 1;
                cur - offset
            } else {
                cur += offset;
                cur - 1
            };

            indices.insert(is);

            g += 1;
        }
    }

    indices
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "State({}, [", self.0)?;
        for (i, h) in self.1.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", hex::encode(h.to_bytes()))?;
        }
        write!(f, "])")
    }
}

impl Clone for Mmr {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            next: self.next,
            vleaves: self.vleaves,
            staged_create: Vec::new(),
            staged_delete: Vec::new(),
            peaks: self.peaks.clone(),
            peak_hashes: self.peak_hashes.clone(),
        }
    }
}
