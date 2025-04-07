use curv::{arithmetic::Converter, elliptic::curves::Scalar};
use p256::ecdsa::signature::digest::Digest;

use crate::crypto::{vrf::proof::Proof, Keypair};

pub mod proof;

pub use proof::Output;

pub struct Vrf<E: curv::elliptic::curves::Curve> {
    keypair: Keypair<E>,
}

impl<E: curv::elliptic::curves::Curve> Default for Vrf<E> {
    fn default() -> Self {
        Self {
            keypair: Keypair::random(),
        }
    }
}

impl<E: curv::elliptic::curves::Curve> Vrf<E> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn proof<D: Digest>(&self, alpha: &[u8]) -> Output<E> {
        use curv::elliptic::curves::{Point, Scalar};

        let h_point = Self::hash_to_curve::<D>(alpha);
        let gamma = &h_point * self.keypair.private_key();

        let k = Scalar::random();
        let k_base = Point::generator() * &k;
        let k_hash = &h_point * &k;

        let c = Self::hash_to_challenge::<D>(
            &Point::generator(),
            &h_point,
            self.keypair.public_key(),
            &gamma,
            &k_base,
            &k_hash,
        );

        let cx = &c * self.keypair.private_key();
        let s = &k - &cx;

        let value = Self::gamma_to_hash::<D>(&gamma);
        Output::new(value, Proof::new(gamma, c, s))
    }

    fn hash_to_curve<D: Digest>(alpha: &[u8]) -> curv::elliptic::curves::Point<E> {
        use curv::elliptic::curves::{Point, Scalar};

        let mut counter = 0u8;
        loop {
            let mut hasher = D::new();
            hasher.update(alpha);
            hasher.update([counter]);
            let digest = hasher.finalize();

            if let Ok(point) = Point::<E>::from_bytes(&digest) {
                return point;
            }

            counter += 1;
            if counter == 0 {
                let mut hasher = D::new();
                hasher.update(alpha);
                hasher.update(b"final_attempt");
                let digest = hasher.finalize();
                let scalar =
                    Scalar::<E>::from_bytes(&digest).unwrap_or_else(|_| Scalar::<E>::random());
                return Point::<E>::generator() * &scalar;
            }
        }
    }

    fn hash_to_challenge<D: Digest>(
        g: &curv::elliptic::curves::Generator<E>,
        h: &curv::elliptic::curves::Point<E>,
        y: &curv::elliptic::curves::Point<E>,
        gamma: &curv::elliptic::curves::Point<E>,
        u: &curv::elliptic::curves::Point<E>,
        v: &curv::elliptic::curves::Point<E>,
    ) -> Scalar<E> {
        let mut hasher = D::new();

        hasher.update(g.to_bytes(true));
        hasher.update(h.to_bytes(true));
        hasher.update(y.to_bytes(true));
        hasher.update(gamma.to_bytes(true));
        hasher.update(u.to_bytes(true));
        hasher.update(v.to_bytes(true));

        let digest = hasher.finalize();

        Scalar::<E>::from_bytes(&digest).unwrap_or_else(|_| {
            let big_int = curv::BigInt::from_bytes(&digest);
            let order = Scalar::<E>::group_order();
            let reduced = big_int % order;
            Scalar::<E>::from(&reduced)
        })
    }

    fn gamma_to_hash<D: Digest>(gamma: &curv::elliptic::curves::Point<E>) -> Vec<u8> {
        const VRF_OUTPUT: &[u8] = b"VRF_OUTPUT";

        let mut hasher = D::new();
        hasher.update(VRF_OUTPUT);
        hasher.update(gamma.to_bytes(true));
        hasher.finalize().to_vec()
    }
}
