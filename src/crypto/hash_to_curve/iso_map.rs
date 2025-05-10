pub mod secp256k1;

pub trait IsoMap {
    fn iso_map(self) -> Self;
}
