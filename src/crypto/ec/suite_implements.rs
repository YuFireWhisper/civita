pub mod secp256k1;

#[allow(dead_code)]
const fn concat_str_slices<const N: usize>(a: &str, b: &str, c: &str) -> [u8; N] {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let c_bytes = c.as_bytes();

    let mut result = [0u8; N];
    let mut i = 0;

    while i < a_bytes.len() {
        result[i] = a_bytes[i];
        i += 1;
    }

    let mut j = 0;
    while j < b_bytes.len() {
        result[i + j] = b_bytes[j];
        j += 1;
    }

    let mut k = 0;
    while k < c_bytes.len() {
        result[i + j + k] = c_bytes[k];
        k += 1;
    }

    result
}
