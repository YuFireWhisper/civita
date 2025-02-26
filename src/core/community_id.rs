pub struct CommunityId(pub [u8; 32]);

impl CommunityId {
    pub fn new(id: [u8; 32]) -> Self {
        Self(id)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_new() {
        let id_bytes = [1; 32];
        let id = super::CommunityId::new(id_bytes);
        assert_eq!(id.0, id_bytes, "CommunityId should store the ID bytes");
    }
}
