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
    pub fn new(id: CommunityId) -> Self {
        Self {
            id,
            members: HashSet::new(),
            committee_members: HashSet::new(),
            chairpersons: Vec::new(),
            reputation: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
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
}
