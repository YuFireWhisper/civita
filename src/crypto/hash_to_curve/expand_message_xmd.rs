use sha2::{Digest, Sha256};

use crate::crypto::types::Dst;

// RFC Step: b_in_bytes, b / 8 for b the output size of H in bits
// SHA-256 has 256-bit output, so b_in_bytes = 32
const B_IN_BYTES: usize = 32;

// RFC Step: s_in_bytes, the input block size of H, measured in bytes
// SHA-256 has 64-byte input block size
const S_IN_BYTES: usize = 64;

/// Implementation of expand_message_xmd as specified in the RFC
///
/// # Arguments
/// * `msg` - Input message as bytes
/// * `dst` - Domain separation tag, must be ≤ 255 bytes
/// * `len_in_bytes` - Desired output length in bytes, must be ≤ min(255 * B_IN_BYTES, 65535)
///
/// # Returns
/// * `Result<Vec<u8>>` - Uniformly random byte string or error
pub fn expand_message_xmd(msg: impl AsRef<[u8]>, dst: Dst, len_in_bytes: usize) -> Vec<u8> {
    // Calculate maximum valid output length as min(255 * B_IN_BYTES, 65535)
    let max_output_len = std::cmp::min(255 * B_IN_BYTES, 65535);

    // RFC Step 1: ell = ceil(len_in_bytes / b_in_bytes)
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);

    // RFC Step 2: ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
    if ell > 255 || len_in_bytes > max_output_len {
        panic!("Invalid input: ell > 255 or len_in_bytes > 65535");
    }

    // RFC Step 3: DST_prime = DST || I2OSP(len(DST), 1)
    let dst_len = dst.as_ref().len();
    let mut dst_prime = Vec::with_capacity(dst_len + 1);
    dst_prime.extend_from_slice(dst.as_ref());
    dst_prime.push(dst_len as u8);

    // RFC Steps 4-6: Prepare msg_prime
    // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    let msg_prime_len = S_IN_BYTES + msg.as_ref().len() + 2 + 1 + dst_prime.len();
    let mut msg_prime = Vec::with_capacity(msg_prime_len);

    // RFC Step 4: Z_pad = I2OSP(0, s_in_bytes)
    msg_prime.extend(std::iter::repeat_n(0, S_IN_BYTES));

    // Append msg
    msg_prime.extend_from_slice(msg.as_ref());

    // RFC Step 5: l_i_b_str = I2OSP(len_in_bytes, 2)
    // Encode len_in_bytes as 2-byte big-endian
    msg_prime.push((len_in_bytes >> 8) as u8);
    msg_prime.push((len_in_bytes & 0xff) as u8);

    // Append I2OSP(0, 1) and DST_prime
    msg_prime.push(0);
    msg_prime.extend_from_slice(&dst_prime);

    // RFC Step 7: b_0 = H(msg_prime)
    let b_0 = Sha256::digest(&msg_prime);

    // RFC Step 8: b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut b_i_input = Vec::with_capacity(b_0.len() + 1 + dst_prime.len());
    b_i_input.extend_from_slice(&b_0);
    b_i_input.push(1);
    b_i_input.extend_from_slice(&dst_prime);

    let b_1 = Sha256::digest(&b_i_input).to_vec();

    // Start building the result with b_1
    let mut uniform_bytes = Vec::with_capacity(ell * B_IN_BYTES);
    uniform_bytes.extend_from_slice(&b_1);

    let mut b_prev = b_1;

    // RFC Steps 9-10: Generate additional blocks as needed
    for i in 2..=ell {
        b_i_input.clear();

        // RFC Step 10: b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
        for (a, b) in b_0.iter().zip(b_prev.iter()) {
            b_i_input.push(a ^ b);
        }

        b_i_input.push(i as u8);
        b_i_input.extend_from_slice(&dst_prime);

        let b_i = Sha256::digest(&b_i_input).to_vec();
        uniform_bytes.extend_from_slice(&b_i);
        b_prev = b_i;
    }

    // RFC Step 12: return substr(uniform_bytes, 0, len_in_bytes)
    // Truncate to the requested length if necessary
    uniform_bytes.truncate(len_in_bytes);

    uniform_bytes
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const SIMPLE_MSG: &[u8] = b"abc";
    const SIMPLE_DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256";
    const EMPTY_MSG: &[u8] = b"";
    const MAX_VALID_DST_LEN: usize = 255;
    const MAX_VALID_OUTPUT_LEN: usize = 65535;

    #[test]
    fn when_len_in_bytes_smaller_than_b_in_bytes_truncates_correctly() {
        let small_len = 16;
        let result = expand_message_xmd(
            SIMPLE_MSG,
            Dst::new_unchecked(SIMPLE_DST.to_vec()),
            small_len,
        );

        assert_eq!(result.len(), small_len);
    }

    #[test]
    fn when_len_in_bytes_larger_than_b_in_bytes_generates_multiple_blocks() {
        let large_len = B_IN_BYTES * 3 + 5;
        let result = expand_message_xmd(
            SIMPLE_MSG,
            Dst::new_unchecked(SIMPLE_DST.to_vec()),
            large_len,
        );

        assert_eq!(result.len(), large_len);
    }

    #[test]
    #[should_panic(expected = "Invalid input: ell > 255 or len_in_bytes > 65535")]
    fn when_ell_exceeds_255_panics() {
        let invalid_len = B_IN_BYTES * 256;
        expand_message_xmd(
            SIMPLE_MSG,
            Dst::new_unchecked(SIMPLE_DST.to_vec()),
            invalid_len,
        ); // This should panic
    }

    #[test]
    #[should_panic(expected = "Invalid input: ell > 255 or len_in_bytes > 65535")]
    fn when_len_in_bytes_exceeds_limit_panics() {
        let invalid_len = MAX_VALID_OUTPUT_LEN + 1;
        expand_message_xmd(
            SIMPLE_MSG,
            Dst::new_unchecked(SIMPLE_DST.to_vec()),
            invalid_len,
        ); // This should panic
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
        let dst = "QUUX-V01-CS02-with-expander-SHA256-128";

        let result = expand_message_xmd(
            msg,
            Dst::new_unchecked(dst.as_bytes().to_vec()),
            len_in_bytes,
        );
        let hex_result = hex::encode(result);

        assert_eq!(hex_result, expected_output);
    }
}
