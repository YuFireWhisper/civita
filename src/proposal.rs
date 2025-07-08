#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq, PartialEq)]
pub struct MultiProposal {
    pub code: u8,
    pub data: Vec<u8>,
    pub sig: Vec<u8>,
}
