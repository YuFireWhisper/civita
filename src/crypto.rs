use vrf::Vrf;

pub mod dkg;
pub mod vrf;
pub mod service;

pub struct Crypto {
    pub vrf: Vrf,
}
