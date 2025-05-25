use std::{collections::HashMap, sync::Arc};

use libp2p::PeerId;

use crate::{
    consensus::vrf_elector::{self, VrfElector},
    crypto::keypair::{PublicKey, VrfProof},
    network::transport::{
        self,
        store::merkle_dag::{self, KeyArray, Node},
    },
    resident::Record,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    VrfElector(#[from] vrf_elector::Error),

    #[error("{0}")]
    Node(#[from] merkle_dag::node::Error),
}

struct MemberInfo {
    public_key: PublicKey,
    proof: VrfProof,
}

pub struct MemberManager {
    members: HashMap<PeerId, MemberInfo>,
    transport: Arc<Transport>,
    elector: Arc<VrfElector>,
    input: Vec<u8>,
    total_stakes: u32,
    root: Node,
}

impl MemberManager {
    pub fn new(
        transport: Arc<Transport>,
        elector: Arc<VrfElector>,
        input: Vec<u8>,
        total_stakes: u32,
        root: Node,
    ) -> Self {
        Self {
            members: HashMap::new(),
            transport,
            elector,
            input,
            total_stakes,
            root,
        }
    }

    pub async fn add_member(
        &mut self,
        peer_id: PeerId,
        public_key: PublicKey,
        proof: VrfProof,
    ) -> Result<Option<u32>> {
        if !public_key.verify_proof(&self.input, &proof) {
            return Ok(None);
        }

        if self.members.contains_key(&peer_id) {
            return Ok(None);
        }

        let stakes = match self.get_stakes(&peer_id, &self.root).await? {
            Some(stakes) => stakes,
            None => return Ok(None),
        };

        let times = self
            .elector
            .calc_elected_times(stakes, self.total_stakes, &proof.output());

        if times == 0 {
            return Ok(None);
        }

        let info = MemberInfo { public_key, proof };

        self.members.insert(peer_id, info);
        Ok(Some(times))
    }

    async fn get_stakes(&self, peer: &PeerId, root: &Node) -> Result<Option<u32>> {
        let peer_key = Self::peer_to_key_array(peer);
        let hash = root.get(peer_key, &self.transport).await?;

        match hash {
            Some(hash) => {
                let record = self.transport.get::<Record>(&hash).await?;
                Ok(record.map(|r| r.stakes))
            }
            None => Ok(None),
        }
    }

    fn peer_to_key_array(peer: &PeerId) -> KeyArray {
        let bytes = peer.to_bytes();
        let mut result = KeyArray::default();

        for (i, chunk) in result.iter_mut().enumerate() {
            if i * 2 + 1 < bytes.len() {
                let high = bytes[i * 2] as u16;
                let low = bytes[i * 2 + 1] as u16;
                *chunk = (high << 8) | low;
            }
        }

        result
    }

    pub fn get_member_proofs(&self) -> HashMap<PeerId, (PublicKey, VrfProof)> {
        self.members
            .iter()
            .map(|(peer_id, info)| {
                let public_key = info.public_key.clone();
                let proof = info.proof.clone();
                (*peer_id, (public_key, proof))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::vrf_elector::VrfElector,
        crypto::keypair::{self, KeyType, SecretKey},
        network::transport::{store::merkle_dag::Node, MockTransport},
        resident::Record,
    };
    use libp2p::PeerId;
    use std::sync::Arc;

    const TEST_INPUT: &[u8] = b"test input";
    const TEST_DATA: &[u8] = b"test_data_for_record";
    const DEFAULT_TOTAL_STAKES: u32 = 1000;
    const DEFAULT_MEMBER_STAKES: u32 = 100;
    const DEFAULT_MEMBER_COUNT: u32 = 5;

    struct TestContext {
        transport: MockTransport,
        elector: Arc<VrfElector>,
        manager: Option<MemberManager>,
        members: Vec<(PeerId, PublicKey, SecretKey)>,
    }

    impl TestContext {
        pub fn new() -> Self {
            let transport = MockTransport::default();
            let (secret_key, _) = keypair::generate_keypair(KeyType::Secp256k1);
            let elector = Arc::new(VrfElector::new(secret_key, DEFAULT_MEMBER_COUNT));

            Self {
                transport,
                elector,
                manager: None,
                members: Vec::new(),
            }
        }

        pub fn with_expect_get(mut self) -> Self {
            self.transport
                .expect_get::<Record>()
                .returning(move |_| Ok(Some(Self::create_test_record(DEFAULT_MEMBER_STAKES))));
            self
        }

        pub fn with_expect_get_none(mut self) -> Self {
            self.transport
                .expect_get::<Record>()
                .returning(move |_| Ok(None));
            self
        }

        pub fn with_transport_error(mut self) -> Self {
            self.transport
                .expect_get::<Record>()
                .returning(move |_| Err(transport::Error::MockError));
            self
        }

        pub fn with_members(mut self, n: u32) -> Self {
            self.members.extend(Self::create_member(n));
            self
        }

        pub fn with_not_elected_member(mut self) -> Self {
            self.members.push(Self::create_not_elected_member());
            self
        }

        fn create_member(n: u32) -> Vec<(PeerId, PublicKey, SecretKey)> {
            let mut members = Vec::new();

            while members.len() < n as usize {
                let (secret_key, public_key) = keypair::generate_keypair(KeyType::Secp256k1);
                let elector = VrfElector::new(secret_key.clone(), DEFAULT_MEMBER_COUNT);
                let times = elector
                    .generate(TEST_INPUT, DEFAULT_MEMBER_STAKES, DEFAULT_TOTAL_STAKES)
                    .unwrap()
                    .1;

                if times > 0 {
                    let peer_id = public_key.to_peer_id();
                    members.push((peer_id, public_key, secret_key));
                }
            }

            members
        }

        fn create_not_elected_member() -> (PeerId, PublicKey, SecretKey) {
            loop {
                let (secret_key, public_key) = keypair::generate_keypair(KeyType::Secp256k1);
                let elector = VrfElector::new(secret_key.clone(), DEFAULT_MEMBER_COUNT);
                let times = elector
                    .generate(TEST_INPUT, 0, DEFAULT_TOTAL_STAKES)
                    .unwrap()
                    .1;

                if times == 0 {
                    let peer_id = public_key.to_peer_id();
                    break (peer_id, public_key, secret_key);
                }
            }
        }

        pub fn member(&self, index: usize) -> (PeerId, PublicKey, SecretKey) {
            self.members[index].clone()
        }

        pub async fn manager(&mut self) -> &mut MemberManager {
            if self.manager.is_none() {
                let manager = self.create_manager().await;
                self.manager = Some(manager);
            }

            self.manager.as_mut().unwrap()
        }

        async fn create_manager(&mut self) -> MemberManager {
            let transport = std::mem::take(&mut self.transport);
            let transport = Arc::new(transport);

            let node = Node::default();

            for (peer_id, _, _) in &self.members {
                let key = MemberManager::peer_to_key_array(peer_id);
                let record = Self::create_test_record(DEFAULT_MEMBER_STAKES);
                let bytes = record.to_bytes();
                let hash = blake3::hash(&bytes);
                node.insert(key, hash.into(), &transport).await.unwrap();
            }

            MemberManager::new(
                transport,
                self.elector.clone(),
                TEST_INPUT.to_vec(),
                DEFAULT_TOTAL_STAKES,
                node,
            )
        }

        fn create_test_record(stakes: u32) -> Record {
            Record {
                stakes,
                data: TEST_DATA.to_vec(),
            }
        }
    }

    #[tokio::test]
    async fn add_member_with_valid_proof_and_stakes() {
        let mut ctx = TestContext::new().with_expect_get().with_members(1);

        let (peer_id, pk, sk) = ctx.member(0);
        let proof = sk.prove(TEST_INPUT).unwrap();

        let result = ctx
            .manager()
            .await
            .add_member(peer_id, pk, proof)
            .await
            .expect("Failed to add member");

        let member_proofs = ctx.manager().await.get_member_proofs();

        assert!(result.is_some());
        assert!(result.unwrap() > 0);
        assert!(member_proofs.contains_key(&peer_id));
    }

    #[tokio::test]
    async fn add_member_with_invalid_proof() {
        let mut ctx = TestContext::new().with_expect_get().with_members(2);

        let (peer_id1, pk1, _) = ctx.member(0);
        let (_, _, sk2) = ctx.member(1);

        let invalid_proof = sk2.prove(TEST_INPUT).unwrap();

        let result = ctx
            .manager()
            .await
            .add_member(peer_id1, pk1, invalid_proof)
            .await
            .expect("Failed to add member with invalid proof");

        let member_proofs = ctx.manager().await.get_member_proofs();

        assert!(result.is_none());
        assert!(!member_proofs.contains_key(&peer_id1));
    }

    #[tokio::test]
    async fn add_duplicate_member() {
        let mut ctx = TestContext::new().with_expect_get().with_members(1);

        let (peer_id, pk, sk) = ctx.member(0);
        let proof = sk.prove(TEST_INPUT).unwrap();

        let result1 = ctx
            .manager()
            .await
            .add_member(peer_id, pk.clone(), proof.clone())
            .await
            .expect("Failed to add member first time");

        let result2 = ctx
            .manager()
            .await
            .add_member(peer_id, pk, proof)
            .await
            .expect("Failed to add member second time");

        assert!(result1.is_some());
        assert!(result2.is_none());
    }

    #[tokio::test]
    async fn add_member_with_zero_elected_times() {
        let mut ctx = TestContext::new()
            .with_expect_get_none()
            .with_not_elected_member();

        let (peer_id, public_key, secret_key) = ctx.member(0);
        let proof = secret_key.prove(TEST_INPUT).unwrap();

        let result = ctx
            .manager()
            .await
            .add_member(peer_id, public_key, proof)
            .await
            .expect("Failed to add member with no stakes");

        let member_proofs = ctx.manager().await.get_member_proofs();

        assert!(result.is_none());
        assert!(!member_proofs.contains_key(&peer_id));
    }

    #[tokio::test]
    async fn transport_error_during_get_stakes() {
        let mut ctx = TestContext::new().with_transport_error().with_members(1);

        let (peer_id, public_key, secret_key) = ctx.member(0);
        let proof = secret_key.prove(TEST_INPUT).unwrap();

        let result = ctx
            .manager()
            .await
            .add_member(peer_id, public_key, proof)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Transport(_)));
    }

    #[tokio::test]
    async fn get_member_proofs_empty() {
        let mut ctx = TestContext::new();
        let manager = ctx.manager().await;

        let member_proofs = manager.get_member_proofs();

        assert!(member_proofs.is_empty(), "Expected no member proofs");
    }

    #[tokio::test]
    async fn get_member_proofs_with_multiple_members() {
        let mut ctx = TestContext::new().with_expect_get().with_members(3);

        for i in 0..3 {
            let (peer_id, public_key, secret_key) = ctx.member(i);
            let proof = secret_key.prove(TEST_INPUT).unwrap();

            ctx.manager()
                .await
                .add_member(peer_id, public_key, proof)
                .await
                .expect("Failed to add member")
                .expect("Expected some elected times");

            let member_proofs = ctx.manager().await.get_member_proofs();

            assert!(
                member_proofs.contains_key(&peer_id),
                "Member not found in proofs"
            );
            assert_eq!(member_proofs.len(), i + 1,);
        }

        let member_proofs = ctx.manager().await.get_member_proofs();

        assert_eq!(member_proofs.len(), 3, "Expected 3 member proofs");
    }

    #[tokio::test]
    async fn new_member_manager_initialization() {
        let mut ctx = TestContext::new();

        let manager = ctx.manager().await;

        assert!(manager.members.is_empty(), "Expected no members initially");
        assert_eq!(manager.input, TEST_INPUT.to_vec(), "Input should match");
        assert_eq!(
            manager.total_stakes, DEFAULT_TOTAL_STAKES,
            "Total stakes should match"
        );
    }
}
