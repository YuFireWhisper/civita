use crate::crypto::{ec::hash_to_curve::expand_message::ExpandMessage, traits::hasher::Hasher};

#[derive(Debug)]
#[derive(Default)]
pub struct Xmd;

impl<H: Hasher> ExpandMessage<H> for Xmd {
    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        const ELL_MAX: usize = 225;
        const MAX_LEN_IN_BYTES: usize = 65535;
        const MAX_DST_LEN: usize = 255;

        let ell = len_in_bytes.div_ceil(H::OUTPUT_SIZE_IN_BIT / 8);

        if ell > ELL_MAX || len_in_bytes > MAX_LEN_IN_BYTES || dst.len() > MAX_DST_LEN {
            panic!("Invalid parameters for XMD expansion");
        }

        let dst_len = dst.len();
        let mut dst_prime = Vec::with_capacity(dst_len + 1);
        dst_prime.extend_from_slice(dst);
        dst_prime.push(dst_len as u8);

        let msg_prime_len = H::BLOCK_SIZE_IN_BYTES + msg.len() + 2 + 1 + dst_prime.len();
        let mut msg_prime = Vec::with_capacity(msg_prime_len);

        msg_prime.extend(std::iter::repeat_n(0, H::BLOCK_SIZE_IN_BYTES));

        msg_prime.extend_from_slice(msg.as_ref());

        msg_prime.push((len_in_bytes >> 8) as u8);
        msg_prime.push((len_in_bytes & 0xff) as u8);

        msg_prime.push(0);
        msg_prime.extend_from_slice(&dst_prime);

        let b_0 = H::hash(&msg_prime);

        let mut b_i_input = Vec::with_capacity(b_0.len() + 1 + dst_prime.len());
        b_i_input.extend_from_slice(&b_0);
        b_i_input.push(1);
        b_i_input.extend_from_slice(&dst_prime);

        let b_1 = H::hash(&b_i_input);

        let mut uniform_bytes = Vec::with_capacity(ell * H::BLOCK_SIZE_IN_BYTES);
        uniform_bytes.extend_from_slice(&b_1);

        let mut b_prev = b_1;

        for i in 2..=ell {
            b_i_input.clear();

            for (a, b) in b_0.iter().zip(b_prev.iter()) {
                b_i_input.push(a ^ b);
            }

            b_i_input.push(i as u8);
            b_i_input.extend_from_slice(&dst_prime);

            let b_i = H::hash(&b_i_input);
            uniform_bytes.extend_from_slice(&b_i);
            b_prev = b_i;
        }

        uniform_bytes.truncate(len_in_bytes);

        uniform_bytes
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const MSG: &[u8] = b"abc";
    const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";
    const MAX_VALID_OUTPUT_LEN: usize = 65535;

    fn expand_message<E: ExpandMessage<H>, H: Hasher>(
        msg: &[u8],
        dst: &[u8],
        len_in_bytes: usize,
    ) -> Vec<u8> {
        E::expand_message(msg, dst, len_in_bytes)
    }

    #[rstest]
    #[case(MSG, DST, sha2::Sha256::OUTPUT_SIZE_IN_BIT * 256)]
    #[case(MSG, DST, MAX_VALID_OUTPUT_LEN + 1)]
    #[case(MSG, &[0; 256], 1)]
    #[should_panic(expected = "Invalid parameters for XMD expansion")]
    fn panic_when_invalid_parameters(
        #[case] msg: &[u8],
        #[case] dst: &[u8],
        #[case] len_in_bytes: usize,
    ) {
        expand_message::<Xmd, sha2::Sha256>(msg, dst, len_in_bytes);
    }

    #[rstest]
    #[case(
        b"",
        0x20,
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"
    )]
    #[case(
        b"abc",
        0x20,
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
    )]
    #[case(
        b"abcdef0123456789",
        0x20,
        "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"
    )]
    #[case(
        b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        0x20,
        "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9"
    )]
    #[case(
        b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        0x20,
        "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c"
    )]
    #[case(
        b"",
        0x80,
        "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
    )]
    #[case(
        b"abc",
        0x80,
        "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"
    )]
    #[case(
        b"abcdef0123456789",
        0x80,
        "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df"
    )]
    #[case(
        b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        0x80,
        "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a"
    )]
    #[case(
        b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        0x80,
        "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487"
    )]
    fn same_output_with_rfc_example(
        #[case] msg: &[u8],
        #[case] len_in_bytes: usize,
        #[case] expected_output: &str,
    ) {
        let result = expand_message::<Xmd, sha2::Sha256>(msg, DST, len_in_bytes);
        let hex_result = hex::encode(result);

        assert_eq!(hex_result, expected_output);
    }
}
