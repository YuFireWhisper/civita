use std::collections::HashMap;

use crate::crypto::{
    keypair::SecretKey,
    primitives::{
        algebra::element::{Public, Secret},
        vss::{Shares, Vss},
    },
};

#[derive(Debug)]
#[derive(Default)]
pub struct Event {
    pairs: HashMap<u16, Shares>,
}

pub struct Context {
    events: HashMap<Vec<u8>, Event>,
}

impl Event {
    pub fn add_peer(&mut self, source_index: u16, shares: Shares) {
        self.pairs.insert(source_index, shares);
    }

    pub fn verify<SK: Secret, PK: Public, V: Vss<SK, PK>>(
        &self,
        source_index: u16,
        verifier_index: u16,
        secret_key: SecretKey,
    ) -> Option<bool> {
        let shares = self.pairs.get(&source_index)?;
        let encrypted_share = shares.shares.get(&verifier_index)?;

        secret_key
            .decrypt(encrypted_share)
            .map_or(Some(false), |decrypted| {
                let commitments = shares
                    .commitments
                    .iter()
                    .map(|c| PK::from_bytes(c))
                    .collect::<Vec<_>>();
                let share = SK::from_bytes(&decrypted);
                Some(V::verify(&verifier_index, &share, &commitments))
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{dkg::joint_feldman::collector::context::Event, primitives::vss::Shares};

    #[test]
    fn length_up() {
        const NUMS: usize = 10;

        let mut event = Event::default();
        for i in 0..NUMS {
            event.add_peer(i as u16, Shares::empty());
            assert_eq!(event.pairs.len(), i + 1);
        }
    }
}
