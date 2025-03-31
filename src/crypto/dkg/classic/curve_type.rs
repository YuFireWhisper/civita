use std::any::type_name;

use bincode::{Decode, Encode};
use curv::elliptic::curves::Curve;
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
        let type_name = type_name::<T>();

        match type_name {
            "curv::elliptic::curves::Bls12_381_1" => CurveType::Bls12_381_1,
            "curv::elliptic::curves::Bls12_381_2" => CurveType::Bls12_381_2,
            "curv::elliptic::curves::Ed25519" => CurveType::Ed25519,
            "curv::elliptic::curves::Ristretto" => CurveType::Ristretto,
            "curv::elliptic::curves::Secp256k1" => CurveType::Secp256k1,
            "curv::elliptic::curves::Secp256r1" => CurveType::Secp256r1,
            _ => CurveType::Unknown,
        }
    }
}
