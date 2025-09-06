use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

use crate::crypto::{hasher::Hasher, Multihash};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Serialize)]
pub struct MmrProof(Vec<Multihash>);

#[derive(Default)]
struct Staged {
    appends: Vec<Multihash>,
    fills: HashMap<BigUint, Multihash>,
    deletes: Vec<BigUint>,
    vnext: BigUint,
    vleaves: BigUint,
}

#[derive(Default)]
pub struct Mmr {
    hashes: HashMap<BigUint, Multihash>,
    next: BigUint,
    leaves: BigUint,
    leaves_indices: HashSet<BigUint>,
    staged: Staged,
    peaks: OnceLock<Vec<BigUint>>,
}

impl Staged {
    pub fn new(vnext: BigUint, vleaves: BigUint) -> Self {
        Self {
            vnext,
            vleaves,
            ..Default::default()
        }
    }
}

impl Mmr {
    pub fn append(&mut self, hash: Multihash) -> BigUint {
        let idx = self.staged.vnext.clone();

        self.staged.vnext += 1 + self.staged.vleaves.trailing_ones();
        self.staged.vleaves.inc();
        self.staged.appends.push(hash);

        idx
    }

    pub fn delete(&mut self, idx: BigUint, hash: Multihash, proof: &MmrProof) -> bool {
        if idx >= self.next {
            return false;
        }

        if let Some(h) = self.hashes.get(&idx) {
            if h == &Multihash::default() || h != &hash {
                return false;
            }
            self.staged.deletes.push(idx);
            return true;
        }

        let (peak, _) = peak_range(self.peaks(), &idx);
        let mut cur_idx = idx.clone();
        let mut g = index_height(&cur_idx);
        let mut local_fills = HashMap::new();

        let acc = proof.0.iter().fold(hash, |acc, h| {
            let offset = BigUint::from(2u32) << g;
            let sidx;

            if index_height(&(&cur_idx + 1u8)) > g {
                cur_idx += 1u8;
                sidx = &cur_idx - &offset;
                g += 1;
                local_fills.entry(sidx).or_insert(*h);
                hash_pospair(&(&cur_idx + 1u8), h, &acc)
            } else {
                cur_idx += offset;
                sidx = &cur_idx - 1u8;
                g += 1;
                local_fills.entry(sidx).or_insert(*h);
                hash_pospair(&(&cur_idx + 1u8), &acc, h)
            }
        });

        if acc != self.hashes[&peak] {
            return false;
        }

        self.staged.fills.insert(idx.clone(), hash);
        self.staged.fills.extend(local_fills);
        self.staged.deletes.push(idx);

        true
    }

    pub fn delete_with_idx(&mut self, idx: BigUint) -> bool {
        if !self.hashes.contains_key(&idx) {
            return false;
        }
        self.staged.deletes.push(idx);
        true
    }

    pub fn commit(&mut self) {
        let staged = std::mem::take(&mut self.staged);

        self.hashes.extend(staged.fills);

        staged.deletes.into_iter().for_each(|idx| {
            self.hashes.insert(idx.clone(), Multihash::default());
            self.leaves_indices.remove(&idx);
            self.recalculate_parents(idx);
        });

        staged.appends.into_iter().for_each(|h| {
            let mut g = 0;
            let mut i = self.insert(h);
            let tmp = &i - 1u8;

            while index_height(&i) > g {
                let il = &i - (2u64 << g);
                let ir = &i - 1u8;
                i = self.insert(hash_pospair(
                    &(&i + 1u8),
                    &self.hashes[&il],
                    &self.hashes[&ir],
                ));
                g += 1;
            }

            self.leaves.inc();
            self.leaves_indices.insert(tmp);
        });

        self.staged = Staged::new(self.next.clone(), self.leaves.clone());
        self.peaks = OnceLock::new();
    }

    fn recalculate_parents(&mut self, mut idx: BigUint) {
        let mut g = index_height(&idx);
        let peak = peak_range(self.peaks(), &idx).0;

        while idx != peak {
            let offset = 2u64 << g;
            let c = &self.hashes[&idx];

            if index_height(&(&idx + 1u8)) > g {
                idx.inc();
                let s = &self.hashes[&(&idx - offset)];
                self.hashes
                    .insert(idx.clone(), hash_pospair(&(&idx + 1u8), s, c));
            } else {
                idx += offset;
                let s = &self.hashes[&(&idx - 1u8)];
                self.hashes
                    .insert(idx.clone(), hash_pospair(&(&idx + 1u8), c, s));
            }

            g += 1;
        }
    }

    fn insert(&mut self, hash: Multihash) -> BigUint {
        self.hashes.insert(self.next.clone(), hash);
        self.next.inc();
        self.next.clone()
    }

    pub fn prove(&self, mut idx: BigUint) -> Option<MmrProof> {
        if self
            .hashes
            .get(&idx)
            .is_none_or(|h| h == &Multihash::default())
        {
            return None;
        }

        let (peak, last) = peak_range(self.peaks(), &idx);
        if peak == idx {
            return Some(MmrProof(Vec::new()));
        }

        let mut proof = Vec::new();
        let mut g = index_height(&idx);

        loop {
            let offset = 2u64 << g;

            let isibling = if index_height(&(&idx + 1u8)) > g {
                idx.inc();
                &idx - offset
            } else {
                idx += offset;
                &idx - 1u8
            };

            if isibling > last {
                return Some(MmrProof(proof));
            }

            proof.push(*self.hashes.get(&isibling)?);
            g += 1;
        }
    }

    fn peaks(&self) -> &Vec<BigUint> {
        self.peaks.get_or_init(|| peak_indices(&self.next))
    }

    pub fn verify(&self, mut idx: BigUint, hash: Multihash, proof: &MmrProof) -> bool {
        let mut root = hash;
        let mut g = index_height(&idx);

        proof.0.iter().for_each(|h| {
            if index_height(&(&idx + 1u8)) > g {
                idx.inc();
                root = hash_pospair(&(&idx + 1u8), h, &root);
            } else {
                idx += 2u64 << g;
                root = hash_pospair(&(&idx + 1u8), &root, h);
            }
            g += 1;
        });

        self.peaks().iter().any(|p| self.hashes[p] == root)
    }

    pub fn prune<I>(&mut self, indices: I) -> bool
    where
        I: IntoIterator<Item = BigUint>,
    {
        let mut keep: HashSet<_> = HashSet::from_iter(self.peaks().iter().cloned());

        for mut idx in indices {
            if !self.hashes.contains_key(&idx) {
                return false;
            }

            if !keep.insert(idx.clone()) {
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
                    idx.inc();
                    &idx - offset
                } else {
                    idx += offset;
                    &idx - 1u8
                };

                keep.insert(idx.clone());

                if idx == peak {
                    break;
                }

                if self.hashes.contains_key(&sibling_idx) {
                    keep.insert(sibling_idx);
                }

                g += 1;
            }
        }

        self.hashes.retain(|k, _| keep.contains(k));
        self.leaves_indices.retain(|k| keep.contains(k));

        true
    }
}

fn index_height(i: &BigUint) -> u64 {
    let mut pos = i + 1u8;

    while pos.bits() != pos.count_ones() {
        pos = &pos - (1u64 << (pos.bits() - 1)) + 1u8;
    }

    pos.bits().saturating_sub(1)
}

fn hash_pospair(idx: &BigUint, l: &Multihash, r: &Multihash) -> Multihash {
    let mut buf = Vec::new();
    buf.extend(idx.to_bytes_be());
    l.to_writer(&mut buf);
    r.to_writer(&mut buf);
    Hasher::digest(&buf)
}

fn peak_indices(s: &BigUint) -> Vec<BigUint> {
    let mut s = s.clone() + 1u8;
    let mut peak = BigUint::zero();
    let mut peaks = Vec::new();

    while !s.is_zero() {
        let size = (BigUint::one() << ((&s + 1u8).bits() - 1)) - 1u8;
        peak += &size;
        peaks.push(&peak - 1u8);
        s -= size;
    }

    peaks
}

fn peak_range(peaks: &[BigUint], idx: &BigUint) -> (BigUint, BigUint) {
    let pos = peaks.partition_point(|p| p < idx);
    let peak = peaks[pos].clone();
    let next_peak = peaks.get(pos + 1).cloned().unwrap_or_else(|| peak.clone());
    (peak, next_peak)
}

impl Clone for Mmr {
    fn clone(&self) -> Self {
        Self {
            hashes: self.hashes.clone(),
            next: self.next.clone(),
            leaves: self.leaves.clone(),
            leaves_indices: self.leaves_indices.clone(),
            staged: Staged::new(self.staged.vnext.clone(), self.staged.vleaves.clone()),
            peaks: self.peaks.clone(),
        }
    }
}

impl Serialize for Mmr {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, civita_serialize::Error> {
        Ok(Self {
            hashes: HashMap::from_reader(reader)?,
            next: BigUint::from_reader(reader)?,
            leaves: BigUint::from_reader(reader)?,
            leaves_indices: HashSet::from_reader(reader)?,
            staged: Staged::default(),
            peaks: {
                let peaks = Vec::from_reader(reader)?;
                let lock = OnceLock::new();
                lock.set(peaks).unwrap();
                lock
            },
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.hashes.to_writer(writer);
        self.next.to_writer(writer);
        self.leaves.to_writer(writer);
        self.leaves_indices.to_writer(writer);
        self.peaks().to_writer(writer);
    }
}

#[cfg(test)]
mod test {
    use civita_serialize::Serialize;

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

        mmr.commit();

        let p1 = mmr.prove(i1.clone()).unwrap();
        let p2 = mmr.prove(i2.clone()).unwrap();
        let p3 = mmr.prove(i3.clone()).unwrap();
        let p4 = mmr.prove(i4.clone()).unwrap();
        let p5 = mmr.prove(i5.clone()).unwrap();
        let p6 = mmr.prove(i6.clone()).unwrap();
        let p7 = mmr.prove(i7.clone()).unwrap();
        let p8 = mmr.prove(i8.clone()).unwrap();
        let p9 = mmr.prove(i9.clone()).unwrap();

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

        mmr.commit();

        mmr.delete(i3.clone(), h3, &mmr.prove(i3.clone()).unwrap());
        mmr.delete(i6.clone(), h6, &mmr.prove(i6.clone()).unwrap());
        mmr.delete(i9.clone(), h9, &mmr.prove(i9.clone()).unwrap());

        mmr.commit();

        let p1 = mmr.prove(i1.clone()).unwrap();
        let p2 = mmr.prove(i2.clone()).unwrap();
        let p4 = mmr.prove(i4.clone()).unwrap();
        let p5 = mmr.prove(i5.clone()).unwrap();
        let p7 = mmr.prove(i7.clone()).unwrap();
        let p8 = mmr.prove(i8.clone()).unwrap();

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

        mmr.commit();

        let valid = mmr.prune(vec![i1.clone(), i2.clone()]);
        let p1 = mmr.prove(i1.clone()).unwrap();
        let p2 = mmr.prove(i2.clone()).unwrap();

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

        mmr.commit();

        let p1 = mmr.prove(i1.clone()).unwrap();
        let p2 = mmr.prove(i2.clone()).unwrap();
        let p3 = mmr.prove(i3.clone()).unwrap();

        assert!(mmr.verify(i1.clone(), h1, &p1));
        assert!(mmr.verify(i2.clone(), h2, &p2));
        assert!(mmr.verify(i3.clone(), h3, &p3));

        let data = mmr.to_vec();
        let mmr2 = Mmr::from_slice(&data).unwrap();

        let p1 = mmr2.prove(i1.clone()).unwrap();
        let p2 = mmr2.prove(i2.clone()).unwrap();
        let p3 = mmr2.prove(i3.clone()).unwrap();

        assert!(mmr2.verify(i1, h1, &p1));
        assert!(mmr2.verify(i2, h2, &p2));
        assert!(mmr2.verify(i3, h3, &p3));
    }
}
