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
    pub siblings: Vec<Multihash>,
    pub idx: u64,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Staged<T> {
    appends: Vec<(Multihash, T)>,
    deletes: HashSet<Multihash>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Mmr<T> {
    hashes: HashMap<u64, Multihash>,
    indices: HashMap<Multihash, u64>,
    leaves: HashMap<Multihash, T>,
    next: u64,
    staged: Staged<T>,
    peaks: OnceLock<Vec<u64>>,
}

impl MmrProof {
    pub fn new(siblings: Vec<Multihash>, idx: u64) -> Self {
        Self { siblings, idx }
    }
}

impl<T> Mmr<T> {
    pub fn append(&mut self, hash: Multihash, value: T) {
        self.staged.appends.push((hash, value));
    }

    pub fn delete(&mut self, hash: Multihash, proof: &MmrProof) -> bool {
        let Some(fills) = self.resolve(&hash, proof) else {
            return false;
        };

        self.hashes.extend(fills.clone());
        self.indices.extend(fills.into_iter().map(|(k, v)| (v, k)));
        self.staged.deletes.insert(hash);

        true
    }

    fn resolve(&self, hash: &Multihash, proof: &MmrProof) -> Option<HashMap<u64, Multihash>> {
        if hash == &Multihash::default() || self.staged.deletes.contains(hash) {
            return None;
        }

        let exp = peak_range(self.peaks(), &proof.idx).0;
        let exp_len = index_height(exp);

        if proof.siblings.len() != exp_len {
            return None;
        }

        let mut idx = proof.idx;
        let mut acc = *hash;
        let mut g = index_height(idx);
        let mut fills: HashMap<u64, Multihash> = HashMap::new();

        for hash in &proof.siblings {
            fills.insert(idx, acc);

            let offset = 2u64 << g;

            if index_height(idx + 1) > g {
                idx += 1;
                let is = idx - offset;
                fills.insert(is, *hash);
                acc = hash_pospair(idx + 1, hash, &acc);
            } else {
                idx += offset;
                let is = idx - 1;
                fills.insert(is, *hash);
                acc = hash_pospair(idx + 1, &acc, hash);
            }

            g += 1;

            if self.hashes.get(&idx).is_some_and(|h| h != &acc) {
                return None;
            }
        }

        Some(fills)
    }

    pub fn commit(&mut self) {
        let staged = std::mem::take(&mut self.staged);

        staged.deletes.into_iter().for_each(|hash| {
            let idx = self.indices.remove(&hash).unwrap();
            self.hashes.insert(idx, Multihash::default());
            self.leaves.remove(&hash);
            self.recalculate_parents(idx);
        });

        staged.appends.into_iter().for_each(|(h, v)| {
            let mut g = 0usize;
            let mut i = self.insert(h);

            while index_height(i) > g {
                let il = i - (2u64 << g);
                let ir = i - 1;
                i = self.insert(hash_pospair(i + 1, &self.hashes[&il], &self.hashes[&ir]));
                g += 1;
            }

            self.leaves.insert(h, v);
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
                let is = idx - offset;
                let s = self.hashes[&is];
                let h = hash_pospair(idx + 1, &s, &c);
                self.hashes.insert(idx, h);
                self.indices.insert(h, idx);
            } else {
                idx += offset;
                let is = idx - 1;
                let s = self.hashes[&is];
                let h = hash_pospair(idx + 1, &c, &s);
                self.hashes.insert(idx, h);
                self.indices.insert(h, idx);
            }

            g += 1;
            c = self.hashes[&idx];
        }
    }

    fn insert(&mut self, hash: Multihash) -> u64 {
        self.hashes.insert(self.next, hash);
        self.indices.insert(hash, self.next);
        self.next += 1;
        self.next
    }

    pub fn get(&self, hash: &Multihash) -> Option<&T> {
        self.leaves.get(hash)
    }

    pub fn prove(&self, hash: Multihash) -> Option<MmrProof> {
        let mut idx = self.indices.get(&hash).cloned()?;
        let tmp = idx;

        let (peak, last) = peak_range(self.peaks(), &idx);
        if peak == idx {
            return Some(MmrProof::new(vec![], idx));
        }

        let mut proof = Vec::new();
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

            if is > last {
                return Some(MmrProof::new(proof, tmp));
            }

            proof.push(self.hashes.get(&is).copied().unwrap_or_default());
            g += 1;
        }
    }

    fn peaks(&self) -> &Vec<u64> {
        self.peaks.get_or_init(|| peak_indices(self.next - 1))
    }

    pub fn verify(&self, hash: Multihash, proof: &MmrProof) -> bool {
        self.resolve(&hash, proof).is_some()
    }

    pub fn prune<I>(&mut self, iter: I) -> bool
    where
        I: IntoIterator<Item = Multihash>,
    {
        let mut hashes = HashMap::new();
        let mut indices = HashMap::new();
        let mut leaves = HashMap::new();

        self.peaks().clone().into_iter().for_each(|p| {
            let h = self.hashes[&p];
            hashes.insert(p, h);
            indices.insert(h, p);
            if let Some(v) = self.leaves.remove(&h) {
                leaves.insert(h, v);
            }
        });

        for hash in iter {
            if indices.contains_key(&hash) {
                continue;
            }

            let mut idx = if let Some(idx) = self.indices.get(&hash) {
                *idx
            } else {
                return false;
            };
            let mut g = index_height(idx);

            loop {
                if hashes.contains_key(&idx) {
                    break;
                }

                let hash = self.hashes.remove(&idx).unwrap();
                self.indices.remove(&hash);
                hashes.insert(idx, hash);
                indices.insert(hash, idx);

                if let Some(v) = self.leaves.remove(&hash) {
                    leaves.insert(hash, v);
                }

                let offset = 2u64 << g;
                let is = if index_height(idx + 1) > g {
                    idx += 1;
                    idx - offset
                } else {
                    idx += offset;
                    &idx - 1
                };

                let hash = self.hashes.remove(&is).unwrap();
                self.indices.remove(&hash);
                hashes.insert(is, hash);
                indices.insert(hash, is);

                if let Some(v) = self.leaves.remove(&hash) {
                    leaves.insert(hash, v);
                }

                g += 1;
            }
        }

        self.hashes = hashes;
        self.indices = indices;
        self.leaves = leaves;

        true
    }

    pub fn leaves(&self) -> impl Iterator<Item = (&Multihash, &T)> {
        self.leaves.iter()
    }
}

impl<T: Clone> Mmr<T> {
    pub fn to_pruned<I>(&self, iter: I) -> Option<Mmr<T>>
    where
        I: IntoIterator<Item = Multihash>,
    {
        let mut hashes: HashMap<u64, Multihash> = HashMap::new();
        let mut indices: HashMap<Multihash, u64> = HashMap::new();
        let mut leaves: HashMap<Multihash, T> = HashMap::new();

        self.peaks().iter().copied().for_each(|p| {
            let h = self.hashes[&p];
            hashes.insert(p, h);
            indices.insert(h, p);
        });

        for hash in iter {
            if indices.contains_key(&hash) {
                continue;
            }

            let mut idx = self.indices.get(&hash).cloned()?;
            let mut g = index_height(idx);

            loop {
                if hashes.insert(idx, hash).is_some() {
                    break;
                }

                indices.insert(hash, idx);

                if let Some(v) = self.leaves.get(&hash) {
                    leaves.insert(hash, v.clone());
                }

                let offset = 2u64 << g;
                let is = if index_height(idx + 1) > g {
                    idx += 1;
                    idx - offset
                } else {
                    idx += offset;
                    idx - 1
                };

                let Some(sh) = self.hashes.get(&is).copied() else {
                    break;
                };

                hashes.insert(is, sh);
                indices.insert(sh, is);

                if let Some(v) = self.leaves.get(&sh) {
                    leaves.insert(sh, v.clone());
                }

                g += 1;
            }
        }

        Some(Mmr {
            hashes,
            indices,
            leaves,
            next: self.next,
            staged: Staged::default(),
            peaks: self.peaks.clone(),
        })
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

fn peak_range(peaks: &[u64], idx: &u64) -> (u64, u64) {
    let pos = peaks.partition_point(|p| p < idx);
    let peak = &peaks[pos];
    let next_peak = peaks.get(pos + 1).unwrap_or(peak);
    (*peak, *next_peak)
}

impl<T: Clone> Clone for Mmr<T> {
    fn clone(&self) -> Self {
        Self {
            hashes: self.hashes.clone(),
            indices: self.indices.clone(),
            leaves: self.leaves.clone(),
            next: self.next,
            peaks: self.peaks.clone(),
            ..Default::default()
        }
    }
}

impl<T: serde::Serialize> serde::Serialize for Mmr<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let map: HashMap<&Multihash, (&u64, Option<&T>)> = self
            .indices
            .iter()
            .map(|(k, idx)| (k, (idx, self.leaves.get(k))))
            .collect();
        (map, self.peaks()).serialize(serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Mmr<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        type Tup<T> = (HashMap<Multihash, (u64, Option<T>)>, Vec<u64>);

        let (map, peaks) = Tup::<T>::deserialize(deserializer)?;

        let mut hashes: HashMap<u64, Multihash> = HashMap::new();
        let mut indices: HashMap<Multihash, u64> = HashMap::new();
        let mut leaves: HashMap<Multihash, T> = HashMap::new();
        let next = peaks.last().map(|p| p + 1).unwrap_or_default();

        for (h, (idx, v)) in map {
            hashes.insert(idx, h);
            indices.insert(h, idx);
            if let Some(v) = v {
                leaves.insert(h, v);
            }
        }

        Ok(Mmr {
            hashes,
            indices,
            leaves,
            next,
            staged: Staged::default(),
            peaks: {
                let lock = OnceLock::new();
                lock.set(peaks).unwrap();
                lock
            },
        })
    }
}

#[cfg(test)]
mod test {
    use multihash_derive::MultihashDigest;

    use crate::{crypto::hasher::Hasher, utils::mmr::Mmr};

    #[test]
    fn append_and_verify() {
        let h1 = Hasher::default().digest(b"1");
        let h2 = Hasher::default().digest(b"2");
        let h3 = Hasher::default().digest(b"3");
        let h4 = Hasher::default().digest(b"4");
        let h5 = Hasher::default().digest(b"5");
        let h6 = Hasher::default().digest(b"6");
        let h7 = Hasher::default().digest(b"7");
        let h8 = Hasher::default().digest(b"8");
        let h9 = Hasher::default().digest(b"9");

        let mut mmr = Mmr::default();

        mmr.append(h1, 1);
        mmr.append(h2, 2);
        mmr.append(h3, 3);
        mmr.append(h4, 4);
        mmr.append(h5, 5);
        mmr.append(h6, 6);
        mmr.append(h7, 7);
        mmr.append(h8, 8);
        mmr.append(h9, 9);
        mmr.commit();

        let p1 = mmr.prove(h1).unwrap();
        let p2 = mmr.prove(h2).unwrap();
        let p3 = mmr.prove(h3).unwrap();
        let p4 = mmr.prove(h4).unwrap();
        let p5 = mmr.prove(h5).unwrap();
        let p6 = mmr.prove(h6).unwrap();
        let p7 = mmr.prove(h7).unwrap();
        let p8 = mmr.prove(h8).unwrap();
        let p9 = mmr.prove(h9).unwrap();

        assert!(mmr.verify(h1, &p1));
        assert!(mmr.verify(h2, &p2));
        assert!(mmr.verify(h3, &p3));
        assert!(mmr.verify(h4, &p4));
        assert!(mmr.verify(h5, &p5));
        assert!(mmr.verify(h6, &p6));
        assert!(mmr.verify(h7, &p7));
        assert!(mmr.verify(h8, &p8));
        assert!(mmr.verify(h9, &p9));
    }

    #[test]
    fn delete_and_verify() {
        let h1 = Hasher::default().digest(b"1");
        let h2 = Hasher::default().digest(b"2");
        let h3 = Hasher::default().digest(b"3");
        let h4 = Hasher::default().digest(b"4");
        let h5 = Hasher::default().digest(b"5");
        let h6 = Hasher::default().digest(b"6");
        let h7 = Hasher::default().digest(b"7");
        let h8 = Hasher::default().digest(b"8");
        let h9 = Hasher::default().digest(b"9");

        let mut mmr = Mmr::default();

        mmr.append(h1, 1);
        mmr.append(h2, 2);
        mmr.append(h3, 3);
        mmr.append(h4, 4);
        mmr.append(h5, 5);
        mmr.append(h6, 6);
        mmr.append(h7, 7);
        mmr.append(h8, 8);
        mmr.append(h9, 9);
        mmr.commit();

        mmr.delete(h3, &mmr.prove(h3).unwrap());
        mmr.delete(h6, &mmr.prove(h6).unwrap());
        mmr.delete(h9, &mmr.prove(h9).unwrap());
        mmr.commit();

        let p1 = mmr.prove(h1).unwrap();
        let p2 = mmr.prove(h2).unwrap();
        let p4 = mmr.prove(h4).unwrap();
        let p5 = mmr.prove(h5).unwrap();
        let p7 = mmr.prove(h7).unwrap();
        let p8 = mmr.prove(h8).unwrap();

        assert!(mmr.verify(h1, &p1));
        assert!(mmr.verify(h2, &p2));
        assert!(mmr.verify(h4, &p4));
        assert!(mmr.verify(h5, &p5));
        assert!(mmr.verify(h7, &p7));
        assert!(mmr.verify(h8, &p8));
        assert!(mmr.prove(h3).is_none());
        assert!(mmr.prove(h6).is_none());
        assert!(mmr.prove(h9).is_none());
    }

    #[test]
    fn prune_keeps_necessary_nodes() {
        let h1 = Hasher::default().digest(b"1");
        let h2 = Hasher::default().digest(b"2");
        let h3 = Hasher::default().digest(b"3");
        let h4 = Hasher::default().digest(b"4");
        let h5 = Hasher::default().digest(b"5");
        let h6 = Hasher::default().digest(b"6");
        let h7 = Hasher::default().digest(b"7");
        let h8 = Hasher::default().digest(b"8");
        let h9 = Hasher::default().digest(b"9");

        let mut mmr = Mmr::default();

        mmr.append(h1, 1);
        mmr.append(h2, 2);
        mmr.append(h3, 3);
        mmr.append(h4, 4);
        mmr.append(h5, 5);
        mmr.append(h6, 6);
        mmr.append(h7, 7);
        mmr.append(h8, 8);
        mmr.append(h9, 9);
        mmr.commit();

        let p1 = mmr.prove(h1).unwrap();
        let p2 = mmr.prove(h2).unwrap();
        let p3 = mmr.prove(h3).unwrap();
        let p4 = mmr.prove(h4).unwrap();
        let p5 = mmr.prove(h5).unwrap();
        let p6 = mmr.prove(h6).unwrap();
        let p7 = mmr.prove(h7).unwrap();
        let p8 = mmr.prove(h8).unwrap();
        let p9 = mmr.prove(h9).unwrap();

        assert!(mmr.prune(vec![h1, h2, h3]));
        assert!(mmr.verify(h1, &p1));
        assert!(mmr.verify(h2, &p2));
        assert!(mmr.verify(h3, &p3));
        assert!(mmr.verify(h4, &p4));
        assert!(mmr.verify(h5, &p5));
        assert!(mmr.verify(h6, &p6));
        assert!(mmr.verify(h7, &p7));
        assert!(mmr.verify(h8, &p8));
        assert!(mmr.verify(h9, &p9));

        assert!(mmr.get(&h1).is_some());
        assert!(mmr.get(&h2).is_some());
        assert!(mmr.get(&h3).is_some());
        assert!(mmr.get(&h4).is_some()); // sibling of h3
        assert!(mmr.get(&h5).is_none());
        assert!(mmr.get(&h6).is_none());
        assert!(mmr.get(&h7).is_none());
        assert!(mmr.get(&h8).is_none());
        assert!(mmr.get(&h9).is_some()); // peak

        assert!(mmr.verify(h1, &mmr.prove(h1).unwrap()));
        assert!(mmr.verify(h2, &mmr.prove(h2).unwrap()));
        assert!(mmr.verify(h3, &mmr.prove(h3).unwrap()));
        assert!(mmr.verify(h4, &mmr.prove(h4).unwrap()));
        assert!(mmr.verify(h9, &mmr.prove(h9).unwrap()));
        assert!(mmr.prove(h5).is_none());
        assert!(mmr.prove(h6).is_none());
        assert!(mmr.prove(h7).is_none());
        assert!(mmr.prove(h8).is_none());
    }

    #[test]
    fn serialize_deserialize() {
        use bincode::{config, serde::decode_from_slice, serde::encode_to_vec};

        let h1 = Hasher::default().digest(b"1");
        let h2 = Hasher::default().digest(b"2");
        let h3 = Hasher::default().digest(b"3");
        let h4 = Hasher::default().digest(b"4");
        let h5 = Hasher::default().digest(b"5");
        let h6 = Hasher::default().digest(b"6");
        let h7 = Hasher::default().digest(b"7");
        let h8 = Hasher::default().digest(b"8");
        let h9 = Hasher::default().digest(b"9");

        let mut mmr = Mmr::default();

        mmr.append(h1, 1);
        mmr.append(h2, 2);
        mmr.append(h3, 3);
        mmr.append(h4, 4);
        mmr.append(h5, 5);
        mmr.append(h6, 6);
        mmr.append(h7, 7);
        mmr.append(h8, 8);
        mmr.append(h9, 9);
        mmr.commit();

        let vec = encode_to_vec(&mmr, config::standard()).unwrap();
        let (mmr2, _) = decode_from_slice::<Mmr<i32>, _>(&vec, config::standard()).unwrap();

        assert!(mmr.hashes == mmr2.hashes);
        assert!(mmr.indices == mmr2.indices);
        assert!(mmr.leaves == mmr2.leaves);
        assert!(mmr.next == mmr2.next);
        assert!(mmr.peaks() == mmr2.peaks());
    }
}
