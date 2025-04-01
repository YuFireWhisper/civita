use std::any::TypeId;

use bincode::{Decode, Encode};
use curv::elliptic::curves::{
    Bls12_381_1, Bls12_381_2, Curve, Ed25519, Ristretto, Secp256k1, Secp256r1,
};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
#[derive(Encode, Decode)]
pub enum CurveType {
    Unknown,
    Bls12_381_1,
    Bls12_381_2,
    Ed25519,
    Ristretto,
    Secp256k1,
    Secp256r1,
}

impl CurveType {
    pub fn from_type<T: Curve>() -> Self {
        let type_id = TypeId::of::<T>();

        match type_id {
            id if id == TypeId::of::<Bls12_381_1>() => CurveType::Bls12_381_1,
            id if id == TypeId::of::<Bls12_381_2>() => CurveType::Bls12_381_2,
            id if id == TypeId::of::<Ed25519>() => CurveType::Ed25519,
            id if id == TypeId::of::<Ristretto>() => CurveType::Ristretto,
            id if id == TypeId::of::<Secp256k1>() => CurveType::Secp256k1,
            id if id == TypeId::of::<Secp256r1>() => CurveType::Secp256r1,
            _ => CurveType::Unknown,
        }
    }
}
