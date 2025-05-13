use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    AffineRepr, CurveConfig, CurveGroup,
};
use ark_ff::{MontFp, PrimeField};
use ark_std::{rand::thread_rng, UniformRand};

pub trait AffineType: CurveConfig {
    type Affine: AffineRepr<Config = Self>;
}

pub trait H: CurveConfig + AffineType {
    fn h() -> Self::Affine;
}

pub trait PedersenCommitment<C: CurveConfig + H + AffineType> {
    fn generate(msg: &[u8; 32]) -> (C::Affine, C::ScalarField);
}

impl<C> PedersenCommitment<C> for C
where
    C: SWCurveConfig + H<Affine = Affine<C>>,
{
    fn generate(msg: &[u8; 32]) -> (C::Affine, C::ScalarField) {
        let mut rng = thread_rng();
        let r: C::ScalarField = C::ScalarField::rand(&mut rng);

        let m: C::ScalarField = C::ScalarField::from_be_bytes_mod_order(msg);

        let m_g: Projective<C> = Self::GENERATOR * m;
        let r_h: Projective<C> = Self::h() * r;

        let c: Affine<C> = (m_g + r_h).into_affine();

        (c, r)
    }
}

impl<C> AffineType for C
where
    C: SWCurveConfig,
{
    type Affine = Affine<C>;
}

const SECP256K1_H_X: ark_secp256k1::Fq =
    MontFp!("91331625906872423843953445964701709122281582063745664088622873016979640285856");
const SECP256K1_H_Y: ark_secp256k1::Fq =
    MontFp!("41637138482785242559211843066889621748562997935625727719125597681612312070111");

impl H for ark_secp256k1::Config {
    fn h() -> Self::Affine {
        ark_secp256k1::Affine::new(SECP256K1_H_X, SECP256K1_H_Y)
    }
}
