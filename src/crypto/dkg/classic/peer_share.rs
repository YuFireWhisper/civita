use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Curve, Scalar},
};
use sha2::Digest;

#[derive(Debug)]
pub struct PeerShare<E: Curve, H: Digest + Clone> {
    vss: Option<VerifiableSS<E, H>>,
    scalar: Option<Scalar<E>>,
}

impl<E: Curve, H: Digest + Clone> Default for PeerShare<E, H> {
    fn default() -> Self {
        let vss = None;
        let scalar = None;

        Self { vss, scalar }
    }
}

impl<E: Curve, H: Digest + Clone> PeerShare<E, H> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_vss(&mut self, v_ss: VerifiableSS<E, H>) -> bool {
        self.vss = Some(v_ss);

        self.is_complete()
    }

    pub fn update_scalar(&mut self, scalar: Scalar<E>) -> bool {
        self.scalar = Some(scalar);

        self.is_complete()
    }

    fn is_complete(&self) -> bool {
        self.vss.is_some() && self.scalar.is_some()
    }

    pub fn validate(&self, index: u16) -> bool {
        assert!(
            self.is_complete(),
            "PeerShare is not complete, please update it before validation"
        );

        let v_ss = self
            .vss
            .as_ref()
            .expect("VSS is missing, this should never happen");
        let scalar = self
            .scalar
            .as_ref()
            .expect("Scalar is missing, this should never happen");

        v_ss.validate_share(scalar, index).is_ok()
    }

    pub fn vss_into(self) -> Option<VerifiableSS<E, H>> {
        self.vss
    }

    pub fn scalar(&self) -> Option<&Scalar<E>> {
        self.scalar.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use curv::{
        cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
        elliptic::curves::{Scalar, Secp256k1},
    };
    use sha2::Sha256;

    use crate::crypto::dkg::classic::peer_share::PeerShare;

    const NUM_SHARES: u16 = 3;

    type E = Secp256k1;
    type H = Sha256;

    fn threshold_counter(n: u16) -> u16 {
        2 * n / 3 + 1
    }

    #[test]
    fn returns_default_peer_share() {
        let peer_share = PeerShare::<E, H>::new();

        assert!(peer_share.vss.is_none());
        assert!(peer_share.scalar.is_none());
    }

    #[test]
    fn false_just_update_vss() {
        let mut peer_share = PeerShare::<E, H>::new();

        let threshold = threshold_counter(NUM_SHARES);
        let secret = Scalar::random();
        let (vss, _) = VerifiableSS::<E, H>::share(threshold - 1, NUM_SHARES, &secret);

        let result = peer_share.update_vss(vss);
        // Just update VSS, not complete

        assert!(!result);
    }

    #[test]
    fn false_just_update_scalar() {
        let mut peer_share = PeerShare::<E, H>::new();

        let threshold = threshold_counter(NUM_SHARES);
        let secret = Scalar::random();
        let (_, shares) = VerifiableSS::<E, H>::share(threshold - 1, NUM_SHARES, &secret);

        let result = peer_share.update_scalar(shares.first().unwrap().clone());
        // Just update scalar, not complete

        assert!(!result);
    }

    #[test]
    fn true_update_both() {
        let mut peer_share = PeerShare::<E, H>::new();

        let threshold = threshold_counter(NUM_SHARES);
        let secret = Scalar::random();
        let (vss, shares) = VerifiableSS::<E, H>::share(threshold - 1, NUM_SHARES, &secret);

        let _ = peer_share.update_vss(vss);
        let result = peer_share.update_scalar(shares.first().unwrap().clone());

        assert!(result);
    }

    #[test]
    #[should_panic(expected = "PeerShare is not complete, please update it before validation")]
    fn panics_validate_incomplete() {
        let peer_share = PeerShare::<E, H>::new();

        peer_share.validate(0);
    }

    #[test]
    fn true_valid_pair() {
        let mut peer_share = PeerShare::<E, H>::new();

        let threshold = threshold_counter(NUM_SHARES);
        let secret = Scalar::random();
        let (vss, shares) = VerifiableSS::<E, H>::share(threshold - 1, NUM_SHARES, &secret);

        let _ = peer_share.update_vss(vss);
        let _ = peer_share.update_scalar(shares.first().unwrap().clone());

        let result = peer_share.validate(1); // index is onebased

        assert!(result);
    }

    #[test]
    fn false_invalid_pair() {
        let mut peer_share = PeerShare::<E, H>::new();

        let threshold = threshold_counter(NUM_SHARES);
        let secret1 = Scalar::random();
        let secret2 = Scalar::random();

        let (vss, _) = VerifiableSS::<E, H>::share(threshold - 1, NUM_SHARES, &secret1);
        let (_, shares) = VerifiableSS::<E, H>::share(threshold - 1, NUM_SHARES, &secret2);

        let _ = peer_share.update_vss(vss);
        let _ = peer_share.update_scalar(shares.first().unwrap().clone());

        let result = peer_share.validate(0);

        assert!(!result);
    }
}
