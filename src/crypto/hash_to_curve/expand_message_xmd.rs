type Result<T> = std::result::Result<T, Error>;

// RFC Step: b_in_bytes, b / 8 for b the output size of H in bits
// BLAKE3 has 256-bit output, so b_in_bytes = 32
const B_IN_BYTES: usize = 32;

// RFC Step: s_in_bytes, the input block size of H, measured in bytes
// BLAKE3 has 64-byte input block size
const S_IN_BYTES: usize = 64;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Invalid input parameters")]
    InvalidInput,
}

/// Implementation of expand_message_xmd as specified in the RFC
///
/// # Arguments
/// * `msg` - Input message as bytes
/// * `dst` - Domain separation tag, must be ≤ 255 bytes
/// * `len_in_bytes` - Desired output length in bytes, must be ≤ min(255 * B_IN_BYTES, 65535)
///
/// # Returns
/// * `Result<Vec<u8>>` - Uniformly random byte string or error
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>> {
    // Calculate maximum valid output length as min(255 * B_IN_BYTES, 65535)
    let max_output_len = std::cmp::min(255 * B_IN_BYTES, 65535);

    // RFC Step 1: ell = ceil(len_in_bytes / b_in_bytes)
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);

    // RFC Step 2: ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
    if ell > 255 || len_in_bytes > max_output_len || dst.len() > 255 {
        return Err(Error::InvalidInput);
    }

    // RFC Step 3: DST_prime = DST || I2OSP(len(DST), 1)
    let dst_len = dst.len();
    let mut dst_prime = Vec::with_capacity(dst_len + 1);
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst_len as u8);

    // RFC Steps 4-6: Prepare msg_prime
    // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    let msg_prime_len = S_IN_BYTES + msg.len() + 2 + 1 + dst_prime.len();
    let mut msg_prime = Vec::with_capacity(msg_prime_len);

    // RFC Step 4: Z_pad = I2OSP(0, s_in_bytes)
    msg_prime.extend(std::iter::repeat_n(0, S_IN_BYTES));

    // Append msg
    msg_prime.extend_from_slice(msg);

    // RFC Step 5: l_i_b_str = I2OSP(len_in_bytes, 2)
    // Encode len_in_bytes as 2-byte big-endian
    msg_prime.push((len_in_bytes >> 8) as u8);
    msg_prime.push((len_in_bytes & 0xff) as u8);

    // Append I2OSP(0, 1) and DST_prime
    msg_prime.push(0);
    msg_prime.extend_from_slice(&dst_prime);

    // RFC Step 7: b_0 = H(msg_prime)
    let b_0 = blake3::hash(&msg_prime).as_bytes().to_vec();

    // RFC Step 8: b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut b_i_input = Vec::with_capacity(b_0.len() + 1 + dst_prime.len());
    b_i_input.extend_from_slice(&b_0);
    b_i_input.push(1);
    b_i_input.extend_from_slice(&dst_prime);

    let b_1 = blake3::hash(&b_i_input).as_bytes().to_vec();

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

        let b_i = blake3::hash(&b_i_input).as_bytes().to_vec();
        uniform_bytes.extend_from_slice(&b_i);
        b_prev = b_i;
    }

    // RFC Step 12: return substr(uniform_bytes, 0, len_in_bytes)
    // Truncate to the requested length if necessary
    uniform_bytes.truncate(len_in_bytes);

    Ok(uniform_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_MSG: &[u8] = b"abc";
    const SIMPLE_DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256";
    const EMPTY_MSG: &[u8] = b"";
    const MAX_VALID_DST_LEN: usize = 255;
    const MAX_VALID_OUTPUT_LEN: usize = 65535;

    #[test]
    fn when_len_in_bytes_smaller_than_b_in_bytes_truncates_correctly() {
        let small_len = 16;
        let result = expand_message_xmd(SIMPLE_MSG, SIMPLE_DST, small_len).unwrap();

        assert_eq!(result.len(), small_len);
    }

    #[test]
    fn when_len_in_bytes_larger_than_b_in_bytes_generates_multiple_blocks() {
        let large_len = B_IN_BYTES * 3 + 5;
        let result = expand_message_xmd(SIMPLE_MSG, SIMPLE_DST, large_len).unwrap();

        assert_eq!(result.len(), large_len);
    }

    #[test]
    fn when_ell_exceeds_255_returns_error() {
        let invalid_len = B_IN_BYTES * 256;
        let result = expand_message_xmd(SIMPLE_MSG, SIMPLE_DST, invalid_len);

        assert!(result.is_err());
        match result {
            Err(Error::InvalidInput) => {}
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn when_len_in_bytes_exceeds_limit_returns_error() {
        let invalid_len = MAX_VALID_OUTPUT_LEN + 1;
        let result = expand_message_xmd(SIMPLE_MSG, SIMPLE_DST, invalid_len);

        assert!(result.is_err());
        match result {
            Err(Error::InvalidInput) => {}
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn when_dst_too_long_returns_error() {
        let long_dst = vec![0u8; MAX_VALID_DST_LEN + 1];
        let result = expand_message_xmd(SIMPLE_MSG, &long_dst, 32);

        assert!(result.is_err());
        match result {
            Err(Error::InvalidInput) => {}
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn should_handle_empty_message() {
        let result = expand_message_xmd(EMPTY_MSG, SIMPLE_DST, 32).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn should_handle_max_valid_parameters() {
        let max_dst = vec![0u8; MAX_VALID_DST_LEN];
        let max_len = std::cmp::min(255 * B_IN_BYTES, MAX_VALID_OUTPUT_LEN);

        let result = expand_message_xmd(SIMPLE_MSG, &max_dst, max_len);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), max_len);
    }

    #[test]
    fn different_messages_produce_different_outputs() {
        let msg1 = b"message1";
        let msg2 = b"message2";

        let output1 = expand_message_xmd(msg1, SIMPLE_DST, 32).unwrap();
        let output2 = expand_message_xmd(msg2, SIMPLE_DST, 32).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn different_dsts_produce_different_outputs() {
        let dst1 = b"domain1";
        let dst2 = b"domain2";

        let output1 = expand_message_xmd(SIMPLE_MSG, dst1, 32).unwrap();
        let output2 = expand_message_xmd(SIMPLE_MSG, dst2, 32).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn when_zero_length_output_returns_empty_vector() {
        let result = expand_message_xmd(SIMPLE_MSG, SIMPLE_DST, 0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn should_be_deterministic() {
        let output1 = expand_message_xmd(SIMPLE_MSG, SIMPLE_DST, 64).unwrap();
        let output2 = expand_message_xmd(SIMPLE_MSG, SIMPLE_DST, 64).unwrap();

        assert_eq!(output1, output2);
    }

    fn assert_is_invalid_input_error(result: Result<Vec<u8>>) {
        match result {
            Err(Error::InvalidInput) => {}
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[test]
    fn should_validate_parameter_boundaries() {
        let true_max_output_len = std::cmp::min(255 * B_IN_BYTES, MAX_VALID_OUTPUT_LEN);

        assert!(
            expand_message_xmd(SIMPLE_MSG, &vec![0; MAX_VALID_DST_LEN], true_max_output_len)
                .is_ok()
        );

        assert_is_invalid_input_error(expand_message_xmd(
            SIMPLE_MSG,
            &vec![0; MAX_VALID_DST_LEN + 1],
            32,
        ));

        assert_is_invalid_input_error(expand_message_xmd(
            SIMPLE_MSG,
            SIMPLE_DST,
            MAX_VALID_OUTPUT_LEN + 1,
        ));

        let max_valid_ell_bytes = B_IN_BYTES * 255;
        assert!(expand_message_xmd(SIMPLE_MSG, SIMPLE_DST, max_valid_ell_bytes).is_ok());

        assert_is_invalid_input_error(expand_message_xmd(
            SIMPLE_MSG,
            SIMPLE_DST,
            max_valid_ell_bytes + 1,
        ));
    }
}
