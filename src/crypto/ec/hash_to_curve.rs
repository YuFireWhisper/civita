use ark_ec::CurveGroup;
use ark_ec::{
    short_weierstrass::{self, Affine, SWCurveConfig},
    AffineRepr, CurveConfig,
};

use crate::crypto::{
    ec::hash_to_curve::{map_to_curve::MapToCurve, utils::L},
    types::dst::Name,
};

mod expand_message_xmd;
mod hash_to_field;
mod iso_map;
mod map_to_curve;
mod suites;
mod utils;

pub trait HashToCurve: CurveConfig + MapToCurve {
    type Output: AffineRepr<Config = Self>;

    fn hash_to_curve(msg: impl AsRef<[u8]>) -> Self::Output;
}

impl<C> HashToCurve for C
where
    C: SWCurveConfig + MapToCurve + Name + L,
{
    type Output = short_weierstrass::Affine<C>;

    fn hash_to_curve(msg: impl AsRef<[u8]>) -> Self::Output {
        let u = hash_to_field::hash_to_field::<C, 2>(msg);
        let q_0 = C::map_to_curve(u[0]);
        let q_0 = Affine::<C>::new(q_0.0, q_0.1);

        let q_1 = C::map_to_curve(u[1]);
        let q_1 = Affine::<C>::new(q_1.0, q_1.1);

        let r = q_0 + q_1;

        r.into_affine().clear_cofactor()
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::Num;
    use rstest::rstest;

    use crate::crypto::ec::hash_to_curve::HashToCurve;

    fn hex_to_string(hex: &str) -> String {
        let hex = hex.trim_start_matches("0x");
        BigUint::from_str_radix(hex, 16).unwrap().to_string()
    }

    #[rstest]
    #[case(
        "",
        "0x3bd98bee5f6ffeca782c4e162db94470d8f8b11fa60d1430b1c52f5bc8c7c2e4",
        "0xe410639bf2b2f197a6791773a2aca5153cf85a2b48831869ae5f8b6ed324d897"
    )]
    #[case(
        "abc",
        "0xb8784d88ee5aefb33cb0887f88b084f8ef9fc0221efb7726c434f43201b144a0",
        "0x86210241ec863252b42c2c11b3f83f52bb5280b35fdeccd36a451046be33a55e"
    )]
    #[case(
        "abcdef0123456789",
        "0xd390940114d245acd3bc0b12759e517f76695c25f54fd0a62b2adb076ad15ac6",
        "0x373608d27d8c4cbe5f9bb76b89bbe2d1c6a7df320ccf83e2d7855419b798ef96"
    )]
    #[case(
        "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        "0x5ca9d6c89953391068d0f787f800f65856c5bc6e921abc437affe93ca995cfa9",
        "0xe2b985b469ca22a6d487b5cf040f53e4debeffcc4994bfaf6a3989806b406000"
        )]
    #[case(
        "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0x946d7f91cb126ac016f8e214c3f77fb0f1c5b40adc0cc1e546fbb83e405b0d2e",
        "0x515b0a8de2ad374748fac0c968dc2b843f09942ec769f80642c49a7ead79b059"
    )]
    fn same_behavior_with_ietf_example_secp256k1(
        #[case] msg: &str,
        #[case] expected_x: &str,
        #[case] expected_y: &str,
    ) {
        let expected_x = hex_to_string(expected_x);
        let expected_y = hex_to_string(expected_y);

        let p = ark_secp256k1::Config::hash_to_curve(msg);

        let x = p.x.to_string();
        let y = p.y.to_string();

        assert_eq!(x, expected_x);
        assert_eq!(y, expected_y);
    }
}
