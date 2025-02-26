use std::collections::{HashMap, HashSet};

use libp2p::PeerId;
use thiserror::Error;

use super::community_id::CommunityId;

#[derive(Debug, Error)]
pub enum CommunityError {
    #[error("Resident already exists in the community")]
    ResidentAlreadyExists,
}

type CommunityResult<T> = Result<T, CommunityError>;

#[derive(Debug)]
pub struct Community {
    id: CommunityId,
    members: HashSet<PeerId>,
    committee_members: HashSet<PeerId>,
    chairpersons: Vec<PeerId>,
    reputation: HashMap<PeerId, u64>,
}

impl Community {
    const RESIDENT_DEFAULT_REPUTATION: u64 = 0;

    pub fn new(id: CommunityId) -> Self {
        Self {
            id,
            members: HashSet::new(),
            committee_members: HashSet::new(),
            chairpersons: Vec::new(),
            reputation: HashMap::new(),
        }
    }

    pub fn add_member(&mut self, peer_id: PeerId) -> CommunityResult<()> {
        if self.members.contains(&peer_id) {
            return Err(CommunityError::ResidentAlreadyExists);
        }

        self.members.insert(peer_id);
        self.reputation
            .insert(peer_id, Self::RESIDENT_DEFAULT_REPUTATION);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use libp2p::PeerId;

    use crate::core::community::Community;
    use crate::core::community_id::CommunityId;

    #[test]
    fn test_new() {
        let id = CommunityId::new([1; 32]);
        let community = Community::new(id.clone());
        assert_eq!(community.id, id, "Community should store the ID");
        assert!(
            community.members.is_empty(),
            "Community should start with no members"
        );
        assert!(
            community.committee_members.is_empty(),
            "Community should start with no committee members"
        );
        assert!(
            community.chairpersons.is_empty(),
            "Community should start with no chairpersons"
        );
        assert!(
            community.reputation.is_empty(),
            "Community should start with no reputation"
        );
    }

    #[test]
    fn test_add_member() {
        let id = CommunityId::new([1; 32]);
        let mut community = Community::new(id);

        let peer_id = PeerId::random();
        community.add_member(peer_id).unwrap();

        assert!(
            community.members.contains(&peer_id),
            "Community should store the member"
        );
        assert_eq!(
            *community.reputation.get(&peer_id).unwrap(),
            Community::RESIDENT_DEFAULT_REPUTATION,
            "Community should store the member's reputation"
        );
    }
}
