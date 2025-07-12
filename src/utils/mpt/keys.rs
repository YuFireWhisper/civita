const TERMINATOR: u8 = 16;

pub fn bytes_to_hex(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len() * 2 + 1;
    let mut nibbles = vec![0u8; len];

    for (i, &byte) in bytes.iter().enumerate() {
        nibbles[i * 2] = byte / 16;
        nibbles[i * 2 + 1] = byte % 16;
    }

    nibbles[len - 1] = TERMINATOR;

    nibbles
}

pub fn hex_to_compact(mut hex: &[u8]) -> Vec<u8> {
    let mut terminator = 0;

    if has_term(hex) {
        terminator = 1;
        hex = &hex[..hex.len() - 1];
    }

    let mut buf = vec![0u8; (hex.len()) / 2 + 1];
    buf[0] = terminator << 5;

    if hex.len() % 2 == 1 {
        buf[0] |= 1 << 4;
        buf[0] |= hex[0];
        hex = &hex[1..];
    }

    decode_nibbles(hex, &mut buf[1..]);

    buf
}

fn has_term(hex: &[u8]) -> bool {
    hex.last().is_some_and(|&x| x == TERMINATOR)
}

fn decode_nibbles(nibbles: &[u8], buf: &mut [u8]) {
    nibbles.chunks_exact(2).enumerate().for_each(|(i, chunk)| {
        buf[i] = (chunk[0] << 4) | chunk[1];
    });
}

// pub fn hex_to_compact_in_place(mut hex: Vec<u8>) -> Vec<u8> {
//     let mut hex_len = hex.len();
//     let mut first_byte = 0;
//
//     if hex_len > 0 && hex[hex_len - 1] == TERMINATOR {
//         first_byte |= 1 << 5;
//         hex_len -= 1;
//     }
//
//     let bin_len = (hex_len / 2) + 1;
//     let mut ni = 0;
//     let mut bi = 1;
//
//     if hex_len % 2 == 1 {
//         first_byte |= 1 << 4;
//         first_byte |= hex[0];
//         ni += 1;
//     }
//
//     while ni < hex_len {
//         hex[bi] = hex[ni] << 4 | hex[ni + 1];
//         ni += 2;
//         bi += 1;
//     }
//
//     hex[0] = first_byte;
//
//     hex.truncate(bin_len);
//
//     hex
// }

pub fn compact_to_hex(compact: &[u8]) -> Vec<u8> {
    if compact.is_empty() {
        return vec![];
    }

    let mut base = bytes_to_hex(compact);

    if base[0] < 2 {
        let _ = base.pop();
    }

    let chop = 2 - base[0] % 2;

    base.split_off(chop as usize)
}

// pub fn hex_to_bytes(mut hex: &[u8]) -> Vec<u8> {
//     if has_term(hex) {
//         hex = &hex[..hex.len() - 1];
//     }
//
//     if hex.len() % 2 != 0 {
//         panic!("Hex key must have an even length");
//     }
//
//     let mut bytes = vec![0u8; hex.len() / 2];
//
//     decode_nibbles(hex, &mut bytes);
//
//     bytes
// }

pub fn prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_hex_conversion() {
        let input = vec![0x1, 0x2, 0x3, 0x04];
        let expected = vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, TERMINATOR];

        let result = bytes_to_hex(&input);

        assert_eq!(result, expected);
    }

    // #[test]
    // fn hex_to_compact_conversion() {
    //     let input = vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, TERMINATOR];
    //     let expected = vec![0x20, 0x01, 0x02, 0x03, 0x04];
    //
    //     let result = hex_to_compact(&input);
    //     let result_in_place = hex_to_compact_in_place(input.clone());
    //
    //     assert_eq!(result, expected);
    //     assert_eq!(result_in_place, expected);
    // }

    #[test]
    fn compact_to_hex_conversion() {
        let input = vec![0x20, 0x01, 0x02, 0x03, 0x04];
        let expected = vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, TERMINATOR];

        let result = compact_to_hex(&input);

        assert_eq!(result, expected);
    }

    // #[test]
    // fn hex_to_bytes_conversion() {
    //     let input = vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, TERMINATOR];
    //     let expected = vec![0x1, 0x2, 0x3, 0x4];
    //
    //     let result = hex_to_bytes(&input);
    //
    //     assert_eq!(result, expected);
    // }
}
