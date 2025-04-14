// use curv::elliptic::curves::{Curve, Scalar};
//
// use crate::crypto::primitives::algebra::element::{Element, Secret};
//
// impl<E: Curve> Element for Scalar<E> {
//     fn random() -> Self {
//         Scalar::random()
//     }
// }
//
// impl<E: Curve> Secret for Scalar<E> {
//     type PublicKey = Scalar<E>;
//
//     fn to_public(&self) -> Self::PublicKey {
//         self.clone()
//     }
//
//     fn to_vec(&self) -> Vec<u8> {
//         self.to_bytes().to_vec()
//     }
//
//     fn from_bytes(bytes: &[u8]) -> Self {
//         Scalar::from_bytes(bytes)
//     }
// }
