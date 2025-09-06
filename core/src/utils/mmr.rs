use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;

use crate::crypto::{hasher::Hasher, Multihash};

#[derive(Clone)]
#[derive(Default)]
#[derive(Serialize)]
pub struct MmrProof(Vec<Multihash>);

#[derive(Default)]
struct Staged {
    appends: Vec<Multihash>,
    fills: HashMap<u32, Multihash>,
    deletes: Vec<u32>,
    vnext: u32,
    vleaves: u32,
}

#[derive(Default)]
pub struct Mmr {
    hashes: HashMap<u32, Multihash>,
    next: u32,
    staged: Staged,
    leaves: u32,
    peaks: OnceLock<Vec<u32>>,
}

impl Mmr {
    pub fn append(&mut self, hash: Multihash) -> u32 {
        self.ensure_virtual_state();

        let idx = self.staged.vnext;

        let l = self.leaves + self.staged.vleaves;
        let merges = l.trailing_ones();

        self.staged.vnext += 1 + merges;
        self.staged.vleaves += 1;

        self.staged.appends.push(hash);

        idx
    }

    fn ensure_virtual_state(&mut self) {
        if self.staged.appends.is_empty() && self.staged.vleaves == 0 {
            self.staged.vnext = self.next;
        }
    }

    pub fn delete(&mut self, idx: u32, hash: Multihash, proof: &MmrProof) -> bool {
        if idx >= self.next {
            return false;
        }

        let (peak, last) = peak_ranges(self.peaks(), idx);
        let mut cur_idx = idx;
        let mut g = index_height(cur_idx);
        let mut acc = hash;
        let mut local_fills = HashMap::new();

        for (i, h) in proof.0.iter().enumerate() {
            let offset = 2 << g;
            let sibling_idx;

            if index_height(cur_idx + 1) > g {
                sibling_idx = cur_idx + 1 - offset;
                cur_idx += 1;
                acc = hash_pospair(cur_idx + 1, h, &acc);
            } else {
                sibling_idx = cur_idx + offset - 1;
                cur_idx += offset;
                acc = hash_pospair(cur_idx + 1, &acc, h);
            }

            if sibling_idx <= last {
                local_fills.entry(sibling_idx).or_insert(*h);
            }

            g += 1;

            if cur_idx == peak {
                if i + 1 != proof.0.len() {
                    return false;
                }
                break;
            }
        }

        let valid = self
            .peaks()
            .iter()
            .any(|p| self.hashes.get(p).unwrap() == &acc);

        if !valid {
            return false;
        }

        self.staged.fills.insert(idx, hash);
        self.staged.fills.extend(local_fills);
        self.staged.deletes.push(idx);

        true
    }

    pub fn delete_with_idx(&mut self, idx: u32) -> bool {
        if !self.hashes.contains_key(&idx) {
            return false;
        }
        self.staged.deletes.push(idx);
        true
    }

    pub fn commmit(&mut self) {
        let mut staged = std::mem::take(&mut self.staged);

        self.hashes.extend(staged.fills.drain());

        staged.deletes.into_iter().for_each(|idx| {
            self.hashes.insert(idx, Multihash::default());
            self.recalculate_parents(idx);
        });

        let mut stack: Vec<_> = self.peaks().iter().map(|&p| (p, index_height(p))).collect();

        for h in staged.appends.into_iter() {
            let leaf_idx = self.insert(h);
            stack.push((leaf_idx, 0));

            while stack.len() >= 2 {
                let (r_idx, r_h) = *stack.last().unwrap();
                let (l_idx, l_h) = stack[stack.len() - 2];

                if r_h != l_h {
                    break;
                }

                let l_hash = *self
                    .hashes
                    .get(&l_idx)
                    .expect("Left child missing, corrupted MMR");
                let r_hash = *self
                    .hashes
                    .get(&r_idx)
                    .expect("Right child missing, corrupted MMR");

                let pidx = self.next;
                let parent_hash = hash_pospair(pidx + 1, &l_hash, &r_hash);

                let inserted_pidx = self.insert(parent_hash);
                debug_assert_eq!(inserted_pidx, pidx);

                stack.pop();
                stack.pop();
                stack.push((pidx, r_h + 1));
            }

            self.leaves += 1;
        }

        self.peaks = OnceLock::new();
        self.staged = Staged::default();
    }

    fn recalculate_parents(&mut self, mut idx: u32) {
        let mut g = index_height(idx);

        loop {
            let offset = 2 << g;
            let pidx;
            let sibling_idx;

            if index_height(idx + 1) > g {
                sibling_idx = idx + 1 - offset;
                pidx = idx + 1;
            } else {
                sibling_idx = idx + offset - 1;
                pidx = idx + offset;
            }

            if !self.hashes.contains_key(&pidx) {
                break;
            }

            let sibling_hash = self
                .hashes
                .get(&sibling_idx)
                .expect("Sibling node missing, data structure corrupted");
            let cur_hash = self
                .hashes
                .get(&idx)
                .expect("Current node missing, data structure corrupted");

            let new_parent_hash = if index_height(idx + 1) > g {
                hash_pospair(pidx + 1, sibling_hash, cur_hash)
            } else {
                hash_pospair(pidx + 1, cur_hash, sibling_hash)
            };

            self.hashes.insert(pidx, new_parent_hash);

            idx = pidx;
            g += 1;
        }
    }

    fn insert(&mut self, hash: Multihash) -> u32 {
        let idx = self.next;
        self.hashes.insert(idx, hash);
        self.next += 1;
        idx
    }

    pub fn prove(&self, mut idx: u32) -> Option<MmrProof> {
        if self
            .hashes
            .get(&idx)
            .is_none_or(|h| h == &Multihash::default())
        {
            return None;
        }

        let (peak, last) = peak_ranges(self.peaks(), idx);
        if peak == idx {
            return Some(MmrProof(Vec::new()));
        }

        let mut proof = Vec::new();
        let mut g = index_height(idx);

        loop {
            let offset = 2 << g;
            let isibling;

            // idx is a right child
            if index_height(idx + 1) > g {
                isibling = idx + 1 - offset;
                idx += 1;
            } else {
                isibling = idx + offset - 1;
                idx += offset;
            }

            if isibling > last {
                return Some(MmrProof(proof));
            }

            proof.push(*self.hashes.get(&isibling)?);
            g += 1;

            if idx == peak {
                return Some(MmrProof(proof));
            }
        }
    }

    fn peaks(&self) -> &Vec<u32> {
        self.peaks.get_or_init(|| peak_indices(self.next))
    }

    pub fn verify(&self, mut idx: u32, hash: Multihash, proof: &MmrProof) -> bool {
        let mut root = hash;
        let mut g = index_height(idx);

        proof.0.iter().rev().for_each(|h| {
            if index_height(idx + 1) > g {
                idx += 1;
                root = hash_pospair(idx + 1, h, &root);
            } else {
                idx += 2 << g;
                root = hash_pospair(idx + 1, &root, h);
            }
            g += 1;
        });

        self.peaks().iter().any(|p| self.hashes[p] == root)
    }

    pub fn prune<I>(&mut self, indices: I) -> bool
    where
        I: IntoIterator<Item = u32>,
    {
        let mut keep: HashSet<u32> = HashSet::from_iter(self.peaks().iter().copied());

        for idx in indices {
            if !self.hashes.contains_key(&idx) {
                return false;
            }

            if !keep.insert(idx) {
                continue;
            }

            let (peak, last) = peak_ranges(self.peaks(), idx);
            if peak == idx {
                continue;
            }

            let mut cur_idx = idx;
            let mut g = index_height(cur_idx);

            loop {
                let offset = 2 << g;
                let sibling_idx;

                if index_height(cur_idx + 1) > g {
                    sibling_idx = cur_idx + 1 - offset;
                    cur_idx += 1;
                } else {
                    sibling_idx = cur_idx + offset - 1;
                    cur_idx += offset;
                }

                keep.insert(cur_idx);

                if sibling_idx <= last && self.hashes.contains_key(&sibling_idx) {
                    keep.insert(sibling_idx);
                }

                g += 1;

                if cur_idx == peak {
                    break;
                }
            }
        }

        self.hashes.retain(|k, _| keep.contains(k));

        true
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.hashes.to_writer(&mut buf);
        self.next.to_writer(&mut buf);
        self.peaks().to_writer(&mut buf);
        buf
    }

    pub fn from_vec(mut data: &[u8]) -> Result<Self, civita_serialize::Error> {
        let hashes: HashMap<u32, Multihash> = HashMap::from_reader(&mut data)?;
        let next: u32 = u32::from_reader(&mut data)?;
        let peaks: Vec<u32> = Vec::from_reader(&mut data)?;
        let exp_peaks = peak_indices(next);

        if peaks != exp_peaks {
            return Err(civita_serialize::Error("Invalid peaks".to_string()));
        }

        let lock = OnceLock::new();
        lock.set(peaks.clone()).unwrap();

        let leaves = peaks.iter().map(|&p| 1u32 << index_height(p)).sum();

        Ok(Self {
            hashes,
            next,
            peaks: lock,
            staged: Staged::default(),
            leaves,
        })
    }
}

fn index_height(i: u32) -> u32 {
    let mut pos = i + 1;
    while (pos & (pos + 1)) != 0 {
        pos = pos - (1 << (31 - pos.leading_zeros())) + 1;
    }
    31 - pos.leading_zeros()
}

fn hash_pospair(idx: u32, l: &Multihash, r: &Multihash) -> Multihash {
    let mut buf = Vec::new();
    idx.to_writer(&mut buf);
    l.to_writer(&mut buf);
    r.to_writer(&mut buf);
    Hasher::digest(&buf)
}

fn peak_indices(mut s: u32) -> Vec<u32> {
    let mut peak = 0;
    let mut peaks = Vec::new();
    while s != 0 {
        let highest = (1 << (s + 1).ilog2()) - 1;
        peak += highest;
        peaks.push(peak - 1);
        s -= highest;
    }
    peaks
}

fn peak_ranges(peaks: &[u32], idx: u32) -> (u32, u32) {
    let pos = peaks.partition_point(|p| *p < idx);
    let peak = peaks[pos];
    (peak, peaks.get(pos + 1).copied().unwrap_or(peak))
}

#[cfg(test)]
mod test {
    use crate::{
        crypto::hasher::Hasher,
        utils::mmr::{Mmr, MmrProof},
    };

    #[test]
    fn append_and_prove() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");
        let h3 = Hasher::digest(b"3");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1);
        let i2 = mmr.append(h2);
        let i3 = mmr.append(h3);

        assert_eq!(i1, 0);
        assert_eq!(i2, 1);
        assert_eq!(i3, 3);

        mmr.commmit();

        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();
        let p3 = mmr.prove(i3).unwrap();

        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
        assert!(mmr.verify(i3, h3, &p3));
    }

    #[test]
    fn delete_and_verify() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");
        let h3 = Hasher::digest(b"3");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1);
        let i2 = mmr.append(h2);
        let i3 = mmr.append(h3);

        mmr.commmit();

        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();
        let p3 = mmr.prove(i3).unwrap();

        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
        assert!(mmr.verify(i3, h3, &p3));

        let _ok = mmr.delete(i3, h3, &p3);
        mmr.commmit();

        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();
        let p3 = mmr.prove(i3).unwrap_or_else(|| MmrProof(Vec::new()));

        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
        assert!(!mmr.verify(i3, h3, &p3));
    }

    #[test]
    fn prune_keeps_necessary_nodes() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1);
        let i2 = mmr.append(h2);

        mmr.commmit();

        let valid = mmr.prune(vec![i1, i2]);
        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();

        assert!(valid);
        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
    }

    #[test]
    fn serialize_deserialize() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");
        let h3 = Hasher::digest(b"3");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1);
        let i2 = mmr.append(h2);
        let i3 = mmr.append(h3);

        mmr.commmit();

        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();
        let p3 = mmr.prove(i3).unwrap();

        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
        assert!(mmr.verify(i3, h3, &p3));

        let data = mmr.to_vec();
        let mmr2 = Mmr::from_vec(&data).unwrap();

        let p1 = mmr2.prove(i1).unwrap();
        let p2 = mmr2.prove(i2).unwrap();
        let p3 = mmr2.prove(i3).unwrap();

        assert!(mmr2.verify(i1, h1, &p1));
        assert!(mmr2.verify(i2, h2, &p2));
        assert!(mmr2.verify(i3, h3, &p3));
    }
}
