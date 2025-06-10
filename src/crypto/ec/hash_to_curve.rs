use ark_ec::short_weierstrass::Affine;

pub mod config;

mod expand_message;
mod hash_to_field;
mod map_to_curve;
mod suites;
mod utils;

pub use config::Config;

#[allow(dead_code)]
pub trait HashToCurve: Config {
    fn hash_to_curve(msg: impl AsRef<[u8]>) -> Affine<Self> {
        let u = hash_to_field::hash_to_field::<Self, 2>(msg);

        let q_0 = Self::map_to_curve(u[0]);
        let q_0 = Affine::new(q_0.0, q_0.1);

        let q_1 = Self::map_to_curve(u[1]);
        let q_1 = Affine::new(q_1.0, q_1.1);

        let r = q_0 + q_1;

        Affine::<Self>::from(r)
    }
}

impl<C: Config> HashToCurve for C {}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::Num;
    use rstest::rstest;

    fn hex_to_string(hex: &str) -> String {
        let hex = hex.trim_start_matches("0x");
        BigUint::from_str_radix(hex, 16).unwrap().to_string()
    }

    #[rstest]
    #[case(
        "",
        "0xc1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
        "0x64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067"
    )]
    #[case(
        "abc",
        "0x3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
        "0x7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"
    )]
    #[case(
        "abcdef0123456789",
        "0xbac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a",
        "0x4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828"
    )]
    #[case(
        "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        "0xe2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9",
        "0xf2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873"
    )]
    #[case(
        "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0xe3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998",
        "0x8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6"
    )]
    fn same_behavior_with_ietf_example_secp256k1(
        #[case] msg: &str,
        #[case] expected_x: &str,
        #[case] expected_y: &str,
    ) {
        use crate::crypto::ec::hash_to_curve::HashToCurve;

        let expected_x = hex_to_string(expected_x);
        let expected_y = hex_to_string(expected_y);

        let p = ark_secp256k1::Config::hash_to_curve(msg);

        let x = p.x.to_string();
        let y = p.y.to_string();

        assert_eq!(x, expected_x);
        assert_eq!(y, expected_y);
    }
}
