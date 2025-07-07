use crate::utils::mpt::node::Node;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct ExistenceProof<T> {
    pub key: Vec<u8>,
    pub value: T,
    pub proof_nodes: Vec<Node<T>>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct NonExistenceProof<T> {
    pub key: Vec<u8>,
    pub proof_nodes: Vec<Node<T>>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum Proof<T> {
    Existence(ExistenceProof<T>),
    NonExistence(NonExistenceProof<T>),
}

impl<T> Proof<T> {
    pub fn key(&self) -> &[u8] {
        match self {
            Proof::Existence(p) => &p.key,
            Proof::NonExistence(p) => &p.key,
        }
    }

    pub fn proof_nodes(&self) -> &[Node<T>] {
        match self {
            Proof::Existence(p) => &p.proof_nodes,
            Proof::NonExistence(p) => &p.proof_nodes,
        }
    }
}
