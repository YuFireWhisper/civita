use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize::Serialize;

use crate::crypto::{hasher::Hasher, Multihash};

pub struct MmrProof(Vec<Multihash>);

#[derive(Default)]
pub struct Mmr {
    hashes: HashMap<u32, Multihash>,
    next: u32,
    peaks: OnceLock<Vec<u32>>,
}

impl Mmr {
    pub fn append(&mut self, hash: Multihash) -> Option<u32> {
        let mut g = 0;
        let mut idx = self.insert(hash);
        let tmp = idx - 1;

        while index_height(idx) > g {
            let il = idx - (2 << g);
            let ir = idx - 1;

            let l = self.hashes.get(&il)?;
            let r = self.hashes.get(&ir)?;

            idx = self.insert(self.hash_pospair(idx + 1, l, r));
            g += 1;
        }

        self.peaks = OnceLock::new();
        Some(tmp)
    }

    fn insert(&mut self, hash: Multihash) -> u32 {
        self.hashes.insert(self.next, hash);
        self.next += 1;
        self.next
    }

    fn hash_pospair(&self, idx: u32, l: &Multihash, r: &Multihash) -> Multihash {
        let mut buf = Vec::new();
        idx.to_writer(&mut buf);
        l.to_writer(&mut buf);
        r.to_writer(&mut buf);
        Hasher::digest(&buf)
    }

    pub fn delete(&mut self, idx: u32) -> bool {
        if !self.hashes.contains_key(&idx) {
            return false;
        }

        self.hashes.insert(idx, Multihash::default());
        self.recalculate_parents(idx);
        self.peaks = OnceLock::new();

        true
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

            // Already reached the peak
            if !self.hashes.contains_key(&pidx) {
                break;
            }

            let sibling_hash = match self.hashes.get(&sibling_idx) {
                Some(hash) => hash,
                None => panic!("Sibling node missing, data structure corrupted"),
            };

            let cur_hash = match self.hashes.get(&idx) {
                Some(hash) => hash,
                None => panic!("Current node missing, data structure corrupted"),
            };

            let new_parent_hash = if index_height(idx + 1) > g {
                self.hash_pospair(pidx + 1, sibling_hash, cur_hash)
            } else {
                self.hash_pospair(pidx + 1, cur_hash, sibling_hash)
            };

            self.hashes.insert(pidx, new_parent_hash);

            idx = pidx;
            g += 1;
        }
    }

    pub fn prove(&self, mut idx: u32) -> Option<MmrProof> {
        if idx >= self.next {
            return None;
        }

        let peaks = self.peaks();

        let (peak, last) = {
            let pos = peaks.partition_point(|p| *p < idx);
            let peak = peaks[pos];

            if peak == idx {
                return Some(MmrProof(Vec::new()));
            }

            let last = if pos + 1 < peaks.len() {
                peaks[pos + 1]
            } else {
                peak
            };

            (peak, last)
        };

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
                root = self.hash_pospair(idx + 1, h, &root);
            } else {
                idx += 2 << g;
                root = self.hash_pospair(idx + 1, &root, h);
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
            if idx >= self.next || !self.hashes.contains_key(&idx) {
                return false;
            }

            keep.insert(idx);

            let mut cur_idx = idx;
            let peaks = self.peaks();

            let (peak, last) = {
                let pos = peaks.partition_point(|p| *p < idx);
                let peak = peaks[pos];

                if peak == idx {
                    continue;
                }

                let last = if pos + 1 < peaks.len() {
                    peaks[pos + 1]
                } else {
                    peak
                };

                (peak, last)
            };

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
        lock.set(peaks).unwrap();

        Ok(Self {
            hashes,
            next,
            peaks: lock,
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

#[cfg(test)]
mod test {
    use crate::{
        crypto::hasher::Hasher,
        utils::mmr::{Mmr, MmrProof},
    };

    #[test]
    fn some_when_not_missing() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");
        let h3 = Hasher::digest(b"3");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1);
        let i2 = mmr.append(h2);
        let i3 = mmr.append(h3);

        assert!(i1.is_some());
        assert!(i2.is_some());
        assert!(i3.is_some());
    }

    #[test]
    fn prove_and_verify() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");
        let h3 = Hasher::digest(b"3");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1).unwrap();
        let i2 = mmr.append(h2).unwrap();
        let i3 = mmr.append(h3).unwrap();

        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();
        let p3 = mmr.prove(i3).unwrap();
        let ip = MmrProof(vec![]);

        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
        assert!(mmr.verify(i3, h3, &p3));
        assert!(!mmr.verify(i1, h1, &ip));
    }

    #[test]
    fn delete_and_verify() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");
        let h3 = Hasher::digest(b"3");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1).unwrap();
        let i2 = mmr.append(h2).unwrap();
        let i3 = mmr.append(h3).unwrap();

        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();
        let p3 = mmr.prove(i3).unwrap();

        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
        assert!(mmr.verify(i3, h3, &p3));

        assert!(mmr.delete(i3));

        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();
        let p3 = mmr.prove(i3).unwrap();

        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
        assert!(!mmr.verify(i3, h3, &p3));
    }

    #[test]
    fn prune_keeps_necessary_nodes() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1).unwrap();
        let i2 = mmr.append(h2).unwrap();

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

        let i1 = mmr.append(h1).unwrap();
        let i2 = mmr.append(h2).unwrap();
        let i3 = mmr.append(h3).unwrap();

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
