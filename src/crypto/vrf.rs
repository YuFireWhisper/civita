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

    pub fn proof<D: sha2::Digest>(&self, alpha: &[u8]) -> Output<E> {
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

    fn hash_to_curve<D: sha2::Digest>(alpha: &[u8]) -> curv::elliptic::curves::Point<E> {
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

            counter = counter.wrapping_add(1);
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

    fn hash_to_challenge<D: sha2::Digest>(
        g: &curv::elliptic::curves::Generator<E>,
        h: &curv::elliptic::curves::Point<E>,
        y: &curv::elliptic::curves::Point<E>,
        gamma: &curv::elliptic::curves::Point<E>,
        u: &curv::elliptic::curves::Point<E>,
        v: &curv::elliptic::curves::Point<E>,
    ) -> curv::elliptic::curves::Scalar<E> {
        use curv::{
            arithmetic::Converter,
            elliptic::curves::{Point, Scalar},
        };

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

    fn gamma_to_hash<D: sha2::Digest>(gamma: &curv::elliptic::curves::Point<E>) -> Vec<u8> {
        const VRF_OUTPUT: &[u8] = b"VRF_OUTPUT";

        let mut hasher = D::new();
        hasher.update(VRF_OUTPUT);
        hasher.update(gamma.to_bytes(true));
        hasher.finalize().to_vec()
    }

    pub fn verify<D: sha2::Digest>(
        &self,
        public_key: &curv::elliptic::curves::Point<E>,
        alpha: &[u8],
        proof: &Proof<E>,
    ) -> bool {
        use curv::elliptic::curves::{Point, Scalar};

        let h_point = Self::hash_to_curve::<D>(alpha);

        let g_to_s = Point::generator() * &proof.s;
        let y_to_c = public_key * &proof.c;
        let u = g_to_s + y_to_c;

        let h_to_s = &h_point * &proof.s;
        let gamma_to_c = &proof.gamma * &proof.c;
        let v = h_to_s + gamma_to_c;

        let c_prime = Self::hash_to_challenge::<D>(
            &Point::generator(),
            &h_point,
            &public_key,
            &proof.gamma,
            &u,
            &v,
        );

        proof.c == c_prime
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::elliptic::curves::secp256_k1::Secp256k1;
    use sha2::Sha256;

    const TEST_MESSAGE: &[u8] = b"test message for VRF";
    const DIFFERENT_MESSAGE: &[u8] = b"different message";

    #[test]
    fn proof_verifies_when_generated_correctly() {
        let vrf = Vrf::<Secp256k1>::new();
        let alpha = TEST_MESSAGE;

        let output = vrf.proof::<Sha256>(alpha);
        let public_key = vrf.keypair.public_key();
        let verification_result = vrf.verify::<Sha256>(public_key, alpha, &output.proof);

        assert!(verification_result);
    }

    #[test]
    fn verification_fails_when_message_differs() {
        let vrf = Vrf::<Secp256k1>::new();
        let alpha = TEST_MESSAGE;
        let different_alpha = DIFFERENT_MESSAGE;

        let output = vrf.proof::<Sha256>(alpha);
        let public_key = vrf.keypair.public_key();
        let verification_result = vrf.verify::<Sha256>(public_key, different_alpha, &output.proof);

        assert!(!verification_result);
    }

    #[test]
    fn verification_fails_when_using_different_public_key() {
        let vrf1 = Vrf::<Secp256k1>::new();
        let vrf2 = Vrf::<Secp256k1>::new();
        let alpha = TEST_MESSAGE;

        let output = vrf1.proof::<Sha256>(alpha);
        let wrong_public_key = vrf2.keypair.public_key();
        let verification_result = vrf1.verify::<Sha256>(wrong_public_key, alpha, &output.proof);

        assert!(!verification_result);
    }

    #[test]
    fn outputs_differ_for_same_message_with_different_keys() {
        let vrf1 = Vrf::<Secp256k1>::new();
        let vrf2 = Vrf::<Secp256k1>::new();
        let alpha = TEST_MESSAGE;

        let output1 = vrf1.proof::<Sha256>(alpha);
        let output2 = vrf2.proof::<Sha256>(alpha);

        assert_ne!(output1.value, output2.value);
    }

    #[test]
    fn outputs_are_deterministic_for_same_key_and_message() {
        let vrf = Vrf::<Secp256k1>::new();
        let alpha = TEST_MESSAGE;

        let output1 = vrf.proof::<Sha256>(alpha);
        let output2 = vrf.proof::<Sha256>(alpha);

        assert_eq!(output1.value, output2.value);
    }

    #[test]
    fn outputs_differ_for_different_messages_with_same_key() {
        let vrf = Vrf::<Secp256k1>::new();
        let alpha1 = TEST_MESSAGE;
        let alpha2 = DIFFERENT_MESSAGE;

        let output1 = vrf.proof::<Sha256>(alpha1);
        let output2 = vrf.proof::<Sha256>(alpha2);

        assert_ne!(output1.value, output2.value);
    }

    #[test]
    fn default_and_new_create_equivalent_instances() {
        let vrf1 = Vrf::<Secp256k1>::default();
        let vrf2 = Vrf::<Secp256k1>::new();

        let alpha = TEST_MESSAGE;
        let output1 = vrf1.proof::<Sha256>(alpha);
        let output2 = vrf2.proof::<Sha256>(alpha);

        let verify1 = vrf1.verify::<Sha256>(vrf1.keypair.public_key(), alpha, &output1.proof);
        let verify2 = vrf2.verify::<Sha256>(vrf2.keypair.public_key(), alpha, &output2.proof);

        assert!(verify1);
        assert!(verify2);
    }
}
