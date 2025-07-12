const HEX_TABLE: [u8; 256] = {
    let mut table = [255u8; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = match i as u8 {
            b'0'..=b'9' => i as u8 - b'0',
            b'A'..=b'F' => i as u8 - b'A' + 10,
            b'a'..=b'f' => i as u8 - b'a' + 10,
            0..=15 => i as u8,
            _ => 255,
        };
        i += 1;
    }
    table
};

pub fn slice_to_hex(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(bytes.len() * 2);

    bytes.iter().for_each(|&byte| {
        nibbles.push(byte / 16);
        nibbles.push(byte % 16);
    });

    nibbles
}

pub fn vec_to_hex(mut bytes: Vec<u8>) -> Vec<u8> {
    let len = bytes.len();
    bytes.resize(len * 2, 0);

    for i in (0..len).rev() {
        let byte = bytes[i];
        bytes[i * 2] = byte / 16;
        bytes[i * 2 + 1] = byte % 16;
    }

    bytes
}

pub fn hex_to_vec(hex: &[u8]) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "Hex string must have an even length");

    let mut vec = Vec::with_capacity(hex.len() / 2);

    hex.chunks_exact(2).for_each(|chunk| {
        let high = HEX_TABLE[chunk[0] as usize];
        let low = HEX_TABLE[chunk[1] as usize];

        if high == 255 || low == 255 {
            panic!("Invalid hex character found");
        }

        vec.push(high * 16 + low);
    });

    vec
}

pub fn prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTES: &[u8] = &[0x01, 0x02, 0x03];
    const HEX: &[u8] = &[0x00, 0x01, 0x00, 0x02, 0x00, 0x03];

    #[test]
    fn slice_to_hex_converts() {
        let hex = slice_to_hex(BYTES);
        assert_eq!(hex, HEX);
    }

    #[test]
    fn vec_to_hex_converts() {
        let hex = vec_to_hex(BYTES.to_vec());
        assert_eq!(hex, HEX);
    }

    #[test]
    fn hex_to_vec_converts() {
        let bytes = hex_to_vec(HEX);
        assert_eq!(bytes, BYTES);
    }

    #[test]
    #[should_panic(expected = "Hex string must have an even length")]
    fn panic_if_odd_length() {
        let odd_hex = &[0x0, 0x1, 0x0, 0x2, 0x0];

        let _ = hex_to_vec(odd_hex);
        // This should panic due to odd length
    }
}
