use libp2p::PeerId;

pub mod classic;

pub trait Dkg {
    fn init(residents: Vec<PeerId>);
}
