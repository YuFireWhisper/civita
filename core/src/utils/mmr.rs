use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use derivative::Derivative;
use multihash_derive::MultihashDigest;
use primitive_types::U256;

use crate::crypto::{hasher::Hasher, Multihash};

type Index = U256;

#[derive(Clone)]
#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct MmrProof {
    pub siblings: Vec<Multihash>,
    pub idx: Index,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
#[derivative(PartialEq(bound = "T: Eq"), Eq(bound = "T: Eq"))]
struct Staged<T> {
    appends: HashMap<Multihash, T>,
    deletes: HashSet<Multihash>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
#[derivative(PartialEq(bound = "T: Eq"), Eq(bound = "T: Eq"))]
pub struct Mmr<T> {
    hashes: HashMap<Index, Multihash>,
    indices: HashMap<Multihash, Index>,
    deletes: HashSet<Multihash>,
    leaves: HashMap<Multihash, T>,
    next: Index,
    staged: Staged<T>,
    peaks: OnceLock<Vec<Index>>,
}

impl MmrProof {
    pub fn new(siblings: Vec<Multihash>, idx: Index) -> Self {
        Self { siblings, idx }
    }
}

impl<T> Mmr<T> {
    pub fn append(&mut self, hash: Multihash, value: T) {
        self.staged.appends.insert(hash, value);
    }

    pub fn delete(&mut self, hash: Multihash, proof: &MmrProof) -> bool {
        if hash == Multihash::default()
            || self.deletes.contains(&hash)
            || self.staged.deletes.contains(&hash)
        {
            return false;
        }

        let exp = peak_range(self.peaks(), &proof.idx).0;
        let exp_len = index_height(&exp);

        if proof.siblings.len() != exp_len {
            return false;
        }

        let mut idx = proof.idx;
        let mut acc = hash;
        let mut g = index_height(&idx);
        let mut fills: HashMap<Index, Multihash> = HashMap::from_iter([(idx, hash)]);

        for hash in &proof.siblings {
            let offset = 2usize << g;

            if index_height(&(&idx + 1u8)) > g {
                idx += 1u8.into();
                let sidx = idx - offset;
                fills.insert(sidx, *hash);
                acc = hash_pospair(&(&idx + 1u8), hash, &acc);
                g += 1;
            } else {
                idx += offset.into();
                let sidx = &idx - 1u8;
                fills.insert(sidx, *hash);
                acc = hash_pospair(&(&idx + 1u8), &acc, hash);
                g += 1;
            }

            if self.hashes.get(&idx).is_some_and(|h| h != &acc) {
                return false;
            }
        }

        self.hashes.extend(fills.clone());
        self.indices.extend(fills.into_iter().map(|(k, v)| (v, k)));
        self.staged.deletes.insert(hash);

        true
    }

    pub fn commit(&mut self) {
        let staged = std::mem::take(&mut self.staged);

        staged.deletes.into_iter().for_each(|hash| {
            let idx = self.indices.remove(&hash).unwrap();
            self.hashes.remove(&idx);
            self.deletes.insert(hash);
            self.leaves.remove(&hash);
            self.recalculate_parents(idx);
        });

        staged.appends.into_iter().for_each(|(h, v)| {
            let mut g = 0;
            let mut i = self.insert(h);

            while index_height(&i) > g {
                dbg!();
                let il = i - (2u64 << g);
                let ir = &i - 1u8;
                i = self.insert(hash_pospair(
                    &(&i + 1u8),
                    &self.hashes[&il],
                    &self.hashes[&ir],
                ));
                g += 1;
            }

            self.leaves.insert(h, v);
        });

        self.peaks = OnceLock::new();
    }

    fn recalculate_parents(&mut self, mut idx: Index) {
        let mut g = index_height(&idx);
        let peak = peak_range(self.peaks(), &idx).0;
        let mut c = &Multihash::default();

        while idx != peak {
            let offset = 2usize << g;

            if index_height(&(&idx + 1u8)) > g {
                idx += 1u8.into();
                let is = idx - offset;
                let s = self.hashes.get(&is).copied().unwrap_or_default();
                let h = hash_pospair(&(&idx + 1u8), &s, c);
                self.hashes.insert(idx, h);
                self.indices.insert(h, idx);
            } else {
                idx += offset.into();
                let is = &idx - 1u8;
                let s = self.hashes.get(&is).copied().unwrap_or_default();
                let h = hash_pospair(&(&idx + 1u8), c, &s);
                self.hashes.insert(idx, h);
                self.indices.insert(h, idx);
            }

            g += 1;
            c = &self.hashes[&idx];
        }
    }

    fn insert(&mut self, hash: Multihash) -> Index {
        self.hashes.insert(self.next, hash);
        self.next += 1u8.into();
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
        let mut g = index_height(&idx);

        loop {
            let offset = 2usize << g;

            let isibling = if index_height(&(&idx + 1u8)) > g {
                idx += 1u8.into();
                idx - offset
            } else {
                idx += offset.into();
                &idx - 1u8
            };

            if isibling > last {
                return Some(MmrProof::new(proof, tmp));
            }

            proof.push(*self.hashes.get(&isibling)?);
            g += 1;
        }
    }

    fn peaks(&self) -> &Vec<Index> {
        self.peaks.get_or_init(|| peak_indices(&self.next))
    }

    pub fn verify(&self, hash: Multihash, proof: &MmrProof) -> bool {
        if hash == Multihash::default()
            || self.deletes.contains(&hash)
            || self.staged.deletes.contains(&hash)
        {
            return false;
        }

        let exp = peak_range(self.peaks(), &proof.idx).0;
        let exp_len = index_height(&exp);

        if proof.siblings.len() != exp_len {
            return false;
        }

        let mut root = hash;
        let mut idx = proof.idx;
        let mut g = index_height(&idx);

        proof.siblings.iter().for_each(|h| {
            if index_height(&(&idx + 1u8)) > g {
                idx += 1u8.into();
                root = hash_pospair(&(&idx + 1u8), h, &root);
            } else {
                idx += (2usize << g).into();
                root = hash_pospair(&(&idx + 1u8), &root, h);
            }
            g += 1;
        });

        self.peaks().iter().any(|p| self.hashes[p] == root)
    }

    pub fn prune<I>(&mut self, hashes: I) -> bool
    where
        I: IntoIterator<Item = Multihash>,
    {
        let mut keep: HashSet<_> = HashSet::from_iter(self.peaks().iter().map(|p| self.hashes[p]));

        for hash in hashes {
            let Some(mut idx) = self.indices.get(&hash).cloned() else {
                return false;
            };

            if !keep.insert(hash) {
                continue;
            }

            let peak = peak_range(self.peaks(), &idx).0;
            if peak == idx {
                continue;
            }

            let mut g = index_height(&idx);
            loop {
                let offset = 2u64 << g;
                let sibling_idx = if index_height(&(&idx + 1u8)) > g {
                    idx += 1u8.into();
                    idx - offset
                } else {
                    idx += offset.into();
                    &idx - 1u8
                };

                keep.insert(self.hashes[&idx]);

                if idx == peak {
                    break;
                }

                if self.hashes.contains_key(&sibling_idx) {
                    keep.insert(self.hashes[&sibling_idx]);
                }

                g += 1;
            }
        }

        self.hashes
            .extract_if(|_, v| !keep.contains(v))
            .for_each(|(_, h)| {
                self.indices.remove(&h);
                self.leaves.remove(&h);
            });
        self.deletes.clear();

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
        let mut hashes: HashMap<Index, Multihash> = HashMap::new();
        let mut indices: HashMap<Multihash, Index> = HashMap::new();
        let mut deletes: HashSet<Multihash> = HashSet::new();
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
            let mut g = index_height(&idx);

            loop {
                if hashes.insert(idx, hash).is_some() {
                    break;
                }

                indices.insert(hash, idx);

                if let Some(v) = self.leaves.get(&hash) {
                    leaves.insert(hash, v.clone());
                }

                let offset = 2usize << g;
                let sidx = if index_height(&(&idx + 1u8)) > g {
                    idx += 1u8.into();
                    idx - offset
                } else {
                    idx += offset.into();
                    &idx - 1u8
                };

                if let Some(hash) = self.deletes.get(&hash) {
                    deletes.insert(*hash);
                    continue;
                }

                let Some(hash) = self.hashes.get(&sidx).copied() else {
                    break;
                };

                hashes.insert(sidx, hash);
                indices.insert(hash, sidx);

                if let Some(v) = self.leaves.get(&hash) {
                    leaves.insert(hash, v.clone());
                }

                g += 1;
            }
        }

        Some(Mmr {
            hashes,
            indices,
            deletes,
            leaves,
            next: self.next,
            staged: Staged::default(),
            peaks: self.peaks.clone(),
        })
    }
}

fn is_all_ones(n: &Index) -> bool {
    let msb = (1usize << (n.bits() - 1)) - 1;
    let mask = (1usize << (msb + 1)) - 1;
    n == &Index::from(mask)
}

fn index_height(i: &Index) -> usize {
    let mut pos = i + 1u8;

    while !is_all_ones(&pos) {
        pos = pos - (1u64 << (pos.bits() - 1)) + 1u8;
    }

    pos.bits().saturating_sub(1)
}

fn hash_pospair(idx: &Index, l: &Multihash, r: &Multihash) -> Multihash {
    use bincode::{config, serde::encode_into_std_write};

    let mut buf = Vec::new();
    encode_into_std_write(idx, &mut buf, config::standard()).unwrap();
    encode_into_std_write(l, &mut buf, config::standard()).unwrap();
    encode_into_std_write(r, &mut buf, config::standard()).unwrap();
    Hasher::default().digest(&buf)
}

fn peak_indices(s: &Index) -> Vec<Index> {
    let mut s = *s + 1u8;
    let mut peak = Index::zero();
    let mut peaks = Vec::new();

    while !s.is_zero() {
        let size = (Index::zero() << ((&s + 1u8).bits() - 1)) - 1u8;
        peak += size;
        peaks.push(&peak - 1u8);
        s -= size;
    }

    peaks
}

fn peak_range(peaks: &[Index], idx: &Index) -> (Index, Index) {
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
            deletes: self.deletes.clone(),
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
        let map: HashMap<&Multihash, Option<(&Index, Option<&T>)>> = self
            .indices
            .iter()
            .map(|(k, idx)| (k, Some((idx, self.leaves.get(k)))))
            .chain(self.deletes.iter().map(|k| (k, None)))
            .collect();
        (map, self.peaks()).serialize(serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Mmr<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        type Tup<T> = (HashMap<Multihash, Option<(Index, Option<T>)>>, Vec<Index>);

        let (map, peaks) = Tup::<T>::deserialize(deserializer)?;

        let mut hashes: HashMap<Index, Multihash> = HashMap::new();
        let mut indices: HashMap<Multihash, Index> = HashMap::new();
        let mut leaves: HashMap<Multihash, T> = HashMap::new();
        let mut deletes: HashSet<Multihash> = HashSet::new();
        let next = peaks.last().map(|p| p + 1u8).unwrap_or_default();

        for (h, opt) in map {
            let Some((idx, v)) = opt else {
                deletes.insert(h);
                continue;
            };

            hashes.insert(idx, h);
            indices.insert(h, idx);

            if let Some(v) = v {
                leaves.insert(h, v);
            }
        }

        Ok(Mmr {
            hashes,
            indices,
            deletes,
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

        let p1 = mmr.prove(h1).unwrap();
        let p2 = mmr.prove(h2).unwrap();
        let p3 = mmr.prove(h3).unwrap();
        let p4 = mmr.prove(h4).unwrap();
        let p5 = mmr.prove(h5).unwrap();
        let p6 = mmr.prove(h6).unwrap();
        let p7 = mmr.prove(h7).unwrap();
        let p8 = mmr.prove(h8).unwrap();
        let p9 = mmr.prove(h9).unwrap();

        mmr.delete(h3, &mmr.prove(h3).unwrap());
        mmr.delete(h6, &mmr.prove(h6).unwrap());
        mmr.delete(h9, &mmr.prove(h9).unwrap());
        mmr.commit();

        assert!(mmr.verify(h1, &p1));
        assert!(mmr.verify(h2, &p2));
        assert!(mmr.verify(h4, &p4));
        assert!(mmr.verify(h5, &p5));
        assert!(mmr.verify(h7, &p7));
        assert!(mmr.verify(h8, &p8));
        assert!(!mmr.verify(h3, &p3));
        assert!(!mmr.verify(h6, &p6));
        assert!(!mmr.verify(h9, &p9));
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
        assert!(mmr.get(&h9).is_none());

        assert!(mmr.prove(h1).is_some());
        assert!(mmr.prove(h2).is_some());
        assert!(mmr.prove(h3).is_some());
        assert!(mmr.prove(h4).is_some());
        assert!(mmr.prove(h5).is_none());
        assert!(mmr.prove(h6).is_none());
        assert!(mmr.prove(h7).is_none());
        assert!(mmr.prove(h8).is_none());
        assert!(mmr.prove(h9).is_none());
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

        assert!(mmr == mmr2);
    }
}
