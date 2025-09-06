use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;

use crate::crypto::{hasher::Hasher, Multihash};

#[derive(Clone)]
#[derive(Debug)]
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

        let (peak, _) = peak_range(self.peaks(), idx);
        let mut cur_idx = idx;
        let mut g = index_height(cur_idx);
        let mut local_fills = HashMap::new();

        let acc = proof.0.iter().fold(hash, |acc, h| {
            let offset = 2 << g;
            let sibling_idx;

            if index_height(cur_idx + 1) > g {
                sibling_idx = cur_idx + 1 - offset;
                cur_idx += 1;
                g += 1;
                local_fills.entry(sibling_idx).or_insert(*h);
                hash_pospair(cur_idx + 1, h, &acc)
            } else {
                sibling_idx = cur_idx + offset - 1;
                cur_idx += offset;
                g += 1;
                local_fills.entry(sibling_idx).or_insert(*h);
                hash_pospair(cur_idx + 1, &acc, h)
            }
        });

        if acc != self.hashes[&peak] {
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
        let staged = std::mem::take(&mut self.staged);

        self.hashes.extend(staged.fills);

        staged.deletes.into_iter().for_each(|idx| {
            self.hashes.insert(idx, Multihash::default());
            self.recalculate_parents(idx);
        });

        staged.appends.into_iter().for_each(|h| {
            let mut g = 0;
            let mut i = self.insert(h);

            while index_height(i) > g {
                let il = i - (2 << g);
                let ir = i - 1;
                i = self.insert(hash_pospair(i + 1, &self.hashes[&il], &self.hashes[&ir]));
                g += 1;
            }

            self.leaves += 1;
        });

        self.peaks = OnceLock::new();
        self.staged = Staged::default();
    }

    fn recalculate_parents(&mut self, mut idx: u32) {
        let mut g = index_height(idx);
        let peak = peak_range(self.peaks(), idx).0;

        while idx != peak {
            let offset = 2 << g;
            let c = &self.hashes[&idx];

            if index_height(idx + 1) > g {
                let s = &self.hashes[&(idx + 1 - offset)];
                let p = idx + 1;
                self.hashes.insert(p, hash_pospair(p + 1, s, c));
                idx = p;
            } else {
                if idx == peak {
                    break;
                }

                let s = &self.hashes[&(idx + offset - 1)];
                let p = idx + offset;
                self.hashes.insert(p, hash_pospair(p + 1, c, s));
                idx = p;
            }

            g += 1;
        }
    }

    fn insert(&mut self, hash: Multihash) -> u32 {
        self.hashes.insert(self.next, hash);
        self.next += 1;
        self.next
    }

    pub fn prove(&self, mut idx: u32) -> Option<MmrProof> {
        if self
            .hashes
            .get(&idx)
            .is_none_or(|h| h == &Multihash::default())
        {
            return None;
        }

        let (peak, last) = peak_range(self.peaks(), idx);
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

        proof.0.iter().for_each(|h| {
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

            let (peak, last) = peak_range(self.peaks(), idx);
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

fn peak_range(peaks: &[u32], idx: u32) -> (u32, u32) {
    let pos = peaks.partition_point(|p| *p < idx);
    let peak = peaks[pos];
    (peak, peaks.get(pos + 1).copied().unwrap_or(peak))
}

#[cfg(test)]
mod test {
    use crate::{crypto::hasher::Hasher, utils::mmr::Mmr};

    #[test]
    fn append_and_prove() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");
        let h3 = Hasher::digest(b"3");
        let h4 = Hasher::digest(b"4");
        let h5 = Hasher::digest(b"5");
        let h6 = Hasher::digest(b"6");
        let h7 = Hasher::digest(b"7");
        let h8 = Hasher::digest(b"8");
        let h9 = Hasher::digest(b"9");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1);
        let i2 = mmr.append(h2);
        let i3 = mmr.append(h3);
        let i4 = mmr.append(h4);
        let i5 = mmr.append(h5);
        let i6 = mmr.append(h6);
        let i7 = mmr.append(h7);
        let i8 = mmr.append(h8);
        let i9 = mmr.append(h9);

        mmr.commmit();

        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();
        let p3 = mmr.prove(i3).unwrap();
        let p4 = mmr.prove(i4).unwrap();
        let p5 = mmr.prove(i5).unwrap();
        let p6 = mmr.prove(i6).unwrap();
        let p7 = mmr.prove(i7).unwrap();
        let p8 = mmr.prove(i8).unwrap();
        let p9 = mmr.prove(i9).unwrap();

        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
        assert!(mmr.verify(i3, h3, &p3));
        assert!(mmr.verify(i4, h4, &p4));
        assert!(mmr.verify(i5, h5, &p5));
        assert!(mmr.verify(i6, h6, &p6));
        assert!(mmr.verify(i7, h7, &p7));
        assert!(mmr.verify(i8, h8, &p8));
        assert!(mmr.verify(i9, h9, &p9));
    }

    #[test]
    fn delete_and_verify() {
        let h1 = Hasher::digest(b"1");
        let h2 = Hasher::digest(b"2");
        let h3 = Hasher::digest(b"3");
        let h4 = Hasher::digest(b"4");
        let h5 = Hasher::digest(b"5");
        let h6 = Hasher::digest(b"6");
        let h7 = Hasher::digest(b"7");
        let h8 = Hasher::digest(b"8");
        let h9 = Hasher::digest(b"9");

        let mut mmr = Mmr::default();

        let i1 = mmr.append(h1);
        let i2 = mmr.append(h2);
        let i3 = mmr.append(h3);
        let i4 = mmr.append(h4);
        let i5 = mmr.append(h5);
        let i6 = mmr.append(h6);
        let i7 = mmr.append(h7);
        let i8 = mmr.append(h8);
        let i9 = mmr.append(h9);

        mmr.commmit();

        mmr.delete(i3, h3, &mmr.prove(i3).unwrap());
        mmr.delete(i6, h6, &mmr.prove(i6).unwrap());
        mmr.delete(i9, h9, &mmr.prove(i9).unwrap());

        mmr.commmit();

        let p1 = mmr.prove(i1).unwrap();
        let p2 = mmr.prove(i2).unwrap();
        let p4 = mmr.prove(i4).unwrap();
        let p5 = mmr.prove(i5).unwrap();
        let p7 = mmr.prove(i7).unwrap();
        let p8 = mmr.prove(i8).unwrap();

        assert!(mmr.verify(i1, h1, &p1));
        assert!(mmr.verify(i2, h2, &p2));
        assert!(mmr.verify(i4, h4, &p4));
        assert!(mmr.verify(i5, h5, &p5));
        assert!(mmr.verify(i7, h7, &p7));
        assert!(mmr.verify(i8, h8, &p8));
        assert!(mmr.prove(i3).is_none());
        assert!(mmr.prove(i6).is_none());
        assert!(mmr.prove(i9).is_none());
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
