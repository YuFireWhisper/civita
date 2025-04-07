use serde::{Deserialize, Serialize};

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
pub struct Proof<E: curv::elliptic::curves::Curve> {
    pub gamma: curv::elliptic::curves::Point<E>,
    pub c: curv::elliptic::curves::Scalar<E>,
    pub s: curv::elliptic::curves::Scalar<E>,
}

pub struct Output<E: curv::elliptic::curves::Curve> {
    pub value: Vec<u8>,
    pub proof: Proof<E>,
}

impl<E: curv::elliptic::curves::Curve> Proof<E> {
    pub fn new(
        gamma: curv::elliptic::curves::Point<E>,
        c: curv::elliptic::curves::Scalar<E>,
        s: curv::elliptic::curves::Scalar<E>,
    ) -> Self {
        Self { gamma, c, s }
    }
}

impl<E: curv::elliptic::curves::Curve> Output<E> {
    pub fn new(value: Vec<u8>, proof: Proof<E>) -> Self {
        Self { value, proof }
    }
}
