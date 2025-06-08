use ark_ff::{Field, MontFp};
use ark_secp256k1::Fq;

use crate::crypto::{
    hash_to_curve::{
        iso_map::IsoMap,
        map_to_curve::AbZero,
        utils::{self, Z},
    },
    types::dst::Name,
};

const K_1_0: Fq = MontFp!("0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7");
const K_1_1: Fq = MontFp!("0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581");
const K_1_2: Fq = MontFp!("0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262");
const K_1_3: Fq = MontFp!("0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c");

const K_2_0: Fq = MontFp!("0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b");
const K_2_1: Fq = MontFp!("0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14");

const K_3_0: Fq = MontFp!("0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c");
const K_3_1: Fq = MontFp!("0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3");
const K_3_2: Fq = MontFp!("0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931");
const K_3_3: Fq = MontFp!("0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84");

const K_4_0: Fq = MontFp!("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b");
const K_4_1: Fq = MontFp!("0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573");
const K_4_2: Fq = MontFp!("0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f");

const A_PRIME: Fq = MontFp!("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533");
const B_PRIME: Fq = MontFp!("1771");

const L: usize = 48;

const Z: Fq = MontFp!("-11");

const NAME: &[u8] = b"secp256k1";

impl IsoMap for ark_secp256k1::Config {
    fn iso_map(
        mut x: Self::BaseField,
        mut y: Self::BaseField,
    ) -> (Self::BaseField, Self::BaseField) {
        // x_num = k_(1,3) * x'^3 + k_(1,2) * x'^2 + k_(1,1) * x' + k_(1,0)
        let x_num = K_1_3 * x.square() * x + K_1_2 * x.square() + K_1_1 * x + K_1_0;

        // x_den = x'^2 + k_(2,1) * x' + k_(2,0)
        let x_den = x.square() + K_2_1 * x + K_2_0;

        // y_num = k_(3,3) * x'^3 + k_(3,2) * x'^2 + k_(3,1) * x' + k_(3,0)
        let y_num = K_3_3 * x.square() * x + K_3_2 * x.square() + K_3_1 * x + K_3_0;

        // y_den = x'^3 + k_(4,2) * x'^2 + k_(4,1) * x' + k_(4,0)
        let y_den = x.square() * x + K_4_2 * x.square() + K_4_1 * x + K_4_0;

        // x = x_num / x_den
        x = x_num / x_den;

        // y = y' * y_num / y_den
        y = y * y_num / y_den;

        (x, y)
    }
}

impl AbZero for ark_secp256k1::Config {
    const A_PRIME: Fq = A_PRIME;
    const B_PRIME: Fq = B_PRIME;
}

impl Z for ark_secp256k1::Config {
    const Z: Fq = Z;
}

impl utils::L for ark_secp256k1::Config {
    const L: usize = L;
}

impl Name for ark_secp256k1::Config {
    fn name() -> Vec<u8> {
        NAME.to_vec()
    }
}
