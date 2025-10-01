use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use derivative::Derivative;
use multihash_derive::MultihashDigest;

use crate::crypto::{hasher::Hasher, Multihash};

#[derive(Clone)]
#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct MmrProof {
    pub idx: u64,
    pub hashes: Vec<Multihash>,
}

#[derive(Clone)]
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
#[derivative(PartialEq(bound = "T: PartialEq"), Eq)]
pub struct Mmr<T> {
    entries: HashMap<u64, (Multihash, Option<T>)>,
    next: u64,
    vleaves: u64,
    staged_create: Vec<(Multihash, T)>,
    staged_delete: Vec<u64>,
    peaks: OnceLock<Vec<u64>>,
}

impl MmrProof {
    pub fn new(hashes: Vec<Multihash>, idx: u64) -> Self {
        Self { hashes, idx }
    }
}

impl<T> Mmr<T> {
    pub fn with_peaks(peaks: Vec<(Multihash, u64)>) -> Self {
        let mut entries = HashMap::with_capacity(peaks.len());
        let mut next = 0u64;

        for (h, idx) in peaks {
            entries.insert(idx, (h, None));
            next = next.max(idx + 1);
        }

        Mmr {
            entries,
            next,
            vleaves: leaves_from_size(next),
            ..Default::default()
        }
    }

    /// Returns index of appended leaf (not next index)
    pub fn append(&mut self, hash: Multihash, value: T) -> u64 {
        let idx = 2 * self.vleaves - self.vleaves.count_ones() as u64;
        self.vleaves += 1;
        self.staged_create.push((hash, value));
        idx
    }

    pub fn delete(&mut self, hash: Multihash, proof: &MmrProof) -> bool {
        let Some(fs) = self.resolve(hash, proof) else {
            return false;
        };

        fs.into_iter().for_each(|(idx, h)| {
            self.entries.entry(idx).and_modify(|e| e.0 = h);
        });

        self.staged_delete.push(proof.idx);

        true
    }

    fn resolve(&self, hash: Multihash, proof: &MmrProof) -> Option<HashMap<u64, Multihash>> {
        let exp = peak_range(self.peaks(), &proof.idx).0;
        let exp_len = index_height(exp);

        if proof.hashes.len() != exp_len {
            return None;
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

        if idx != exp || acc != self.entries[&exp].0 {
            return None;
        }

        Some(fills)
    }

    pub fn commit(&mut self) {
        let created = std::mem::take(&mut self.staged_create);
        let deleted = std::mem::take(&mut self.staged_delete);

        deleted.into_iter().for_each(|idx| {
            self.entries.insert(idx, (Multihash::default(), None));
            self.recalculate_parents(idx);
        });

        created.into_iter().for_each(|(h, v)| {
            let mut g = 0usize;
            let mut i = self.insert(h, Some(v));

            while index_height(i) > g {
                let il = i - (2u64 << g);
                let ir = i - 1;
                let h = hash_pospair(i + 1, &self.entries[&il].0, &self.entries[&ir].0);
                i = self.insert(h, None);
                g += 1;
            }
        });

        self.peaks = OnceLock::new();
    }

    fn recalculate_parents(&mut self, mut idx: u64) {
        let mut g = index_height(idx);
        let mut c = Multihash::default();
        let peak = peak_range(self.peaks(), &idx).0;

        while idx != peak {
            let offset = 2u64 << g;

            if index_height(idx + 1) > g {
                idx += 1;
                let s = &self.entries[&(idx - offset)].0;
                *self.entries.get_mut(&idx).unwrap() = (hash_pospair(idx + 1, s, &c), None);
            } else {
                idx += offset;
                let s = &self.entries[&(idx - 1)].0;
                *self.entries.get_mut(&idx).unwrap() = (hash_pospair(idx + 1, &c, s), None);
            }

            g += 1;
            c = self.entries[&idx].0;
        }
    }

    /// Returns next index
    fn insert(&mut self, hash: Multihash, value: Option<T>) -> u64 {
        self.entries.insert(self.next, (hash, value));
        self.next += 1;
        self.next
    }

    pub fn get(&self, idx: u64) -> Option<&(Multihash, Option<T>)> {
        self.entries.get(&idx)
    }

    pub fn prove(&self, idx: u64) -> Option<MmrProof> {
        let peak = peak_range(self.peaks(), &idx).0;
        let mut proof = MmrProof::new(vec![], idx);

        if peak == idx {
            return Some(proof);
        }

        let mut g = index_height(idx);
        let mut idx = idx;

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

            proof.hashes.push(self.entries.get(&is)?.0);
            g += 1;
        }
    }

    fn peaks(&self) -> &Vec<u64> {
        self.peaks.get_or_init(|| {
            if self.next == 0 {
                vec![]
            } else {
                peak_indices(self.next - 1)
            }
        })
    }

    pub fn peak_hashes(&self) -> Vec<Multihash> {
        self.peaks().iter().map(|p| self.entries[p].0).collect()
    }

    pub fn verify(&self, hash: Multihash, proof: &MmrProof) -> bool {
        self.resolve(hash, proof).is_some()
    }

    pub fn prune(&mut self, indices: &[u64]) -> bool {
        let indices = pruned_indices(self.next - 1, indices);
        let mut entries = HashMap::with_capacity(indices.len());

        for i in indices {
            if let Some(e) = self.entries.remove(&i) {
                entries.insert(i, e);
            } else {
                return false;
            }
        }

        self.entries = entries;
        true
    }
}

impl<T: Clone> Mmr<T> {
    pub fn to_pruned(&self, indices: &[u64]) -> Option<Mmr<T>> {
        let indices = pruned_indices(self.next, indices);
        let mut entries = HashMap::with_capacity(indices.len());

        for i in indices {
            entries.insert(i, self.entries.get(&i)?.clone());
        }

        Some(Mmr {
            entries,
            next: self.next,
            vleaves: leaves_from_size(self.next),
            ..Default::default()
        })
    }
}

pub fn index_height(i: u64) -> usize {
    let mut pos = i + 1;

    while !(pos + 1).is_power_of_two() {
        pos = pos - (1 << (u64::BITS - pos.leading_zeros() - 1)) + 1;
    }

    (u64::BITS - pos.leading_zeros()).saturating_sub(1) as usize
}

pub fn hash_pospair(idx: u64, l: &Multihash, r: &Multihash) -> Multihash {
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

fn peak_range(peaks: &[u64], idx: &u64) -> (u64, u64) {
    let pos = peaks.partition_point(|p| p < idx);
    if pos == 0 {
        return (peaks[0], peaks[0]);
    }
    let peak = peaks.get(pos).unwrap_or(&peaks[pos - 1]);
    let next_peak = peaks.get(pos + 1).unwrap_or(peak);
    (*peak, *next_peak)
}

pub fn serialize_indices(size: u64, leaves: &[u64]) -> Vec<u64> {
    let peaks = HashSet::<u64>::from_iter(peak_indices(size - 1));
    let mut indices = HashMap::<u64, bool>::from_iter(peaks.iter().map(|p| (*p, true)));

    leaves.iter().for_each(|l| {
        let mut cur = *l;
        let mut path = Vec::new();
        let mut g = index_height(cur);

        while !indices.contains_key(&cur) {
            path.push((cur, true));

            let offset = 2u64 << g;
            let is = if index_height(cur + 1) > g {
                cur += 1;
                cur - offset
            } else {
                cur += offset;
                cur - 1
            };

            path.push((is, true));
            path.push((cur, false));

            g += 1;
        }

        path.into_iter().for_each(|(i, v)| {
            indices.entry(i).and_modify(|e| *e &= v).or_insert(v);
        });
    });

    indices
        .into_iter()
        .filter_map(|(k, v)| v.then_some(k))
        .collect()
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

impl<T: serde::Serialize> serde::Serialize for Mmr<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (self.next, &self.entries).serialize(serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Mmr<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (next, entries): (u64, HashMap<u64, (Multihash, Option<T>)>) =
            serde::Deserialize::deserialize(deserializer)?;

        Ok(Mmr {
            entries,
            next,
            vleaves: leaves_from_size(next),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use multihash_derive::MultihashDigest;

    use crate::{
        crypto::{hasher::Hasher, Multihash},
        utils::mmr::{Mmr, MmrProof},
    };

    #[derive(Default)]
    struct Context {
        mmr: Mmr<u32>,
        hash_to_idx: HashMap<Multihash, u64>,
        proof_cache: HashMap<u64, (Multihash, MmrProof)>,
        deleted: Vec<u64>,
    }

    impl Context {
        pub fn append(&mut self, start: u64, end: u64) {
            for i in start..end {
                let h = Hasher::default().digest(&i.to_le_bytes());
                let idx = self.mmr.append(h, i as u32);
                self.hash_to_idx.insert(h, idx);
            }
            self.mmr.commit();
        }

        pub fn delete(&mut self, start: u64, end: u64) {
            for i in start..end {
                let h = Hasher::default().digest(&i.to_le_bytes());
                let idx = self.hash_to_idx[&h];
                let p = self.mmr.prove(idx).unwrap();
                assert!(self.mmr.delete(h, &p));
                self.deleted.push(idx);
            }
            self.mmr.commit();
        }

        pub fn verify(&self, start: u64, end: u64) {
            for i in start..end {
                let h = Hasher::default().digest(&i.to_le_bytes());
                let idx = self.hash_to_idx[&h];
                let p = self.mmr.prove(idx).unwrap();
                assert!(self.mmr.verify(h, &p));
            }
        }

        pub fn verify_deleted(&self) {
            for idx in &self.deleted {
                let p = self.mmr.prove(*idx).unwrap();
                assert!(self.mmr.verify(Multihash::default(), &p));
            }
        }

        pub fn prove_and_cache(&mut self, start: u64, end: u64) {
            for i in start..end {
                let h = Hasher::default().digest(&i.to_le_bytes());
                let idx = self.hash_to_idx[&h];
                let p = self.mmr.prove(idx).unwrap();
                self.proof_cache.insert(idx, (h, p));
            }
        }

        pub fn prune(&mut self, indices: &[u64]) {
            let hs: Vec<Multihash> = indices
                .iter()
                .map(|i| Hasher::default().digest(&i.to_le_bytes()))
                .collect();
            let idxs: Vec<u64> = hs.iter().map(|h| self.hash_to_idx[h]).collect();
            assert!(self.mmr.prune(&idxs));
        }

        pub fn verify_cached(&self) {
            for (idx, (h, p)) in &self.proof_cache {
                assert!(self.mmr.verify(*h, p), "failed to verify idx {}", idx);
            }
        }
    }

    #[test]
    fn append_and_verify() {
        let mut ctx = Context::default();
        ctx.append(0, 1000);
        ctx.verify(0, 1000);
    }

    #[test]
    fn delete_and_verify() {
        let mut ctx = Context::default();
        ctx.append(0, 1000);
        ctx.delete(200, 800);
        ctx.verify(0, 200);
        ctx.verify(800, 1000);
        ctx.verify_deleted();
    }

    #[test]
    fn prune_keeps_necessary_nodes() {
        let mut ctx = Context::default();
        ctx.append(0, 12);
        ctx.prove_and_cache(0, 12);
        ctx.prune(&[1, 2, 3]);
        ctx.verify_cached();
    }

    #[test]
    fn serialize_deserialize() {
        use bincode::{config, serde::decode_from_slice, serde::encode_to_vec};

        let mut ctx = Context::default();
        ctx.append(0, 1000);
        ctx.delete(200, 800);

        let encoded = encode_to_vec(&ctx.mmr, config::standard()).unwrap();
        let decoded = decode_from_slice::<Mmr<u32>, _>(&encoded, config::standard())
            .unwrap()
            .0;

        assert!(ctx.mmr == decoded);
    }
}
