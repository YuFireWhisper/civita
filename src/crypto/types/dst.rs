const MAX_DST_LENGTH: usize = 255;

pub trait Name {
    fn name() -> Vec<u8>;
}

pub struct Dst(Vec<u8>);

/// Format: <CrateName>-<Version>-<CipherSuite>
impl Dst {
    pub fn new<N: Name>() -> Self {
        let name = {
            #[cfg(not(test))]
            {
                env!("CARGO_PKG_NAME").as_bytes()
            }

            #[cfg(test)]
            {
                TEST_CRATE_NAME
            }
        };

        let version = {
            #[cfg(not(test))]
            {
                env!("CARGO_PKG_VERSION").as_bytes()
            }

            #[cfg(test)]
            {
                TEST_CRATE_VERSION
            }
        };

        let mut dst = Vec::new();
        dst.extend_from_slice(name);
        dst.push(b'-');
        dst.extend_from_slice(version);
        dst.push(b'-');
        dst.extend_from_slice(&N::name());

        assert!(
            dst.len() <= MAX_DST_LENGTH,
            "DST length exceeds {MAX_DST_LENGTH} bytes"
        );
        assert!(!dst.is_empty(), "DST length is zero");

        Self(dst)
    }

    #[cfg(test)]
    pub fn new_unchecked(dst: Vec<u8>) -> Self {
        Self(dst)
    }
}

impl AsRef<[u8]> for Dst {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[allow(dead_code)]
pub(crate) const TEST_CRATE_NAME: &[u8] = b"CIVIT-TEST";

#[allow(dead_code)]
pub(crate) const TEST_CRATE_VERSION: &[u8] = b"0.1.0-test";

#[cfg(test)]
mod tests {
    use crate::crypto::types::{
        dst::{Name, TEST_CRATE_NAME, TEST_CRATE_VERSION},
        Dst,
    };

    const TEST_NAME: &[u8] = b"test";

    struct TestName;

    impl Name for TestName {
        fn name() -> Vec<u8> {
            TEST_NAME.to_vec()
        }
    }

    #[test]
    fn dst_value_correctness() {
        let expected_dst = [TEST_CRATE_NAME, b"-", TEST_CRATE_VERSION, b"-", TEST_NAME].concat();
        let dst = Dst::new::<TestName>();
        assert_eq!(dst.as_ref(), expected_dst);
    }
}
