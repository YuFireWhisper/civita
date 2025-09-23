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
pub struct Mmr<T> {
    idx_to_hash: HashMap<u64, Multihash>,
    hash_to_idx: HashMap<Multihash, u64>,
    leaves: HashMap<Multihash, T>,
    next: u64,
    staged: Vec<(Multihash, Option<T>)>,
    peaks: OnceLock<Vec<u64>>,
}

impl MmrProof {
    pub fn new(siblings: Vec<Multihash>, idx: u64) -> Self {
        Self { siblings, idx }
    }
}

impl<T> Mmr<T> {
    pub fn append(&mut self, hash: Multihash, value: T) {
        self.staged.push((hash, Some(value)));
    }

    pub fn delete(&mut self, hash: Multihash, proof: &MmrProof) -> bool {
        let Some(fs) = self.resolve(&hash, proof) else {
            return false;
        };

        self.idx_to_hash.extend(fs.clone());
        self.hash_to_idx.extend(fs.into_iter().map(|(k, v)| (v, k)));
        self.staged.push((hash, None));

        true
    }

    fn resolve(&self, hash: &Multihash, proof: &MmrProof) -> Option<HashMap<u64, Multihash>> {
        if hash == &Multihash::default() {
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

            if self.idx_to_hash.get(&idx).is_some_and(|h| h != &acc) {
                return None;
            }
        }

        Some(fills)
    }

    pub fn commit(&mut self) {
        let staged = std::mem::take(&mut self.staged);

        staged.into_iter().for_each(|(h, v)| {
            if let Some(v) = v {
                // Insertion
                let mut g = 0usize;
                let mut i = self.insert(h);

                while index_height(i) > g {
                    let il = i - (2u64 << g);
                    let ir = i - 1;
                    i = self.insert(hash_pospair(
                        i + 1,
                        &self.idx_to_hash[&il],
                        &self.idx_to_hash[&ir],
                    ));
                    g += 1;
                }

                self.leaves.insert(h, v);
            } else {
                // Deletion
                let idx = self.hash_to_idx.remove(&h).unwrap();
                self.idx_to_hash.insert(idx, Multihash::default());
                self.leaves.remove(&h);
                self.recalculate_parents(idx);
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
                let is = idx - offset;
                let s = self.idx_to_hash[&is];
                let h = hash_pospair(idx + 1, &s, &c);
                self.idx_to_hash.insert(idx, h);
                self.hash_to_idx.insert(h, idx);
            } else {
                idx += offset;
                let is = idx - 1;
                let s = self.idx_to_hash[&is];
                let h = hash_pospair(idx + 1, &c, &s);
                self.idx_to_hash.insert(idx, h);
                self.hash_to_idx.insert(h, idx);
            }

            g += 1;
            c = self.idx_to_hash[&idx];
        }
    }

    fn insert(&mut self, hash: Multihash) -> u64 {
        self.idx_to_hash.insert(self.next, hash);
        self.hash_to_idx.insert(hash, self.next);
        self.next += 1;
        self.next
    }

    pub fn get(&self, hash: &Multihash) -> Option<&T> {
        self.leaves.get(hash)
    }

    pub fn prove(&self, hash: Multihash) -> Option<MmrProof> {
        let mut idx = self.hash_to_idx.get(&hash).cloned()?;
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

            proof.push(self.idx_to_hash.get(&is).copied().unwrap_or_default());
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
            let h = self.idx_to_hash[&p];
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

            let mut idx = if let Some(idx) = self.hash_to_idx.get(&hash) {
                *idx
            } else {
                return false;
            };
            let mut g = index_height(idx);

            loop {
                if hashes.contains_key(&idx) {
                    break;
                }

                let hash = self.idx_to_hash.remove(&idx).unwrap();
                self.hash_to_idx.remove(&hash);
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

                let hash = self.idx_to_hash.remove(&is).unwrap();
                self.hash_to_idx.remove(&hash);
                hashes.insert(is, hash);
                indices.insert(hash, is);

                if let Some(v) = self.leaves.remove(&hash) {
                    leaves.insert(hash, v);
                }

                g += 1;
            }
        }

        self.idx_to_hash = hashes;
        self.hash_to_idx = indices;
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
            let h = self.idx_to_hash[&p];
            hashes.insert(p, h);
            indices.insert(h, p);
            if let Some(v) = self.leaves.get(&h) {
                leaves.insert(h, v.clone());
            }
        });

        for hash in iter {
            if indices.contains_key(&hash) {
                continue;
            }

            let mut idx = self.hash_to_idx.get(&hash).cloned()?;
            let mut g = index_height(idx);

            loop {
                if hashes.contains_key(&idx) {
                    break;
                }

                let hash = *self.idx_to_hash.get(&idx).unwrap();
                hashes.insert(idx, hash);
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

                let hash = *self.idx_to_hash.get(&is).unwrap();
                hashes.insert(is, hash);
                indices.insert(hash, is);

                if let Some(v) = self.leaves.get(&hash) {
                    leaves.insert(hash, v.clone());
                }

                g += 1;
            }
        }

        Some(Mmr {
            idx_to_hash: hashes,
            hash_to_idx: indices,
            leaves,
            next: self.next,
            staged: Vec::new(),
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

pub fn prune_indices(size: u64, leaves: &[u64]) -> Vec<u64> {
    let peaks = HashSet::<u64>::from_iter(peak_indices(size - 1));
    let mut indices = HashMap::<u64, bool>::new();

    leaves.iter().filter(|l| !peaks.contains(l)).for_each(|l| {
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

            if peaks.contains(&cur) {
                break;
            }

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

impl<T: Clone> Clone for Mmr<T> {
    fn clone(&self) -> Self {
        Self {
            idx_to_hash: self.idx_to_hash.clone(),
            hash_to_idx: self.hash_to_idx.clone(),
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
            .hash_to_idx
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
            idx_to_hash: hashes,
            hash_to_idx: indices,
            leaves,
            next,
            staged: Vec::new(),
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

        assert!(mmr.idx_to_hash == mmr2.idx_to_hash);
        assert!(mmr.hash_to_idx == mmr2.hash_to_idx);
        assert!(mmr.leaves == mmr2.leaves);
        assert!(mmr.next == mmr2.next);
        assert!(mmr.peaks() == mmr2.peaks());
    }
}
