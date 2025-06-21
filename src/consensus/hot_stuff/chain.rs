use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::consensus::hot_stuff::utils::QuorumCertificate;

type Qc<H, T, P, S> = QuorumCertificate<Box<Node<H, T, P, S>>, P, S>;
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),
}

#[derive(Serialize, Deserialize)]
pub enum SerailizedNode<H, T, P, S>
where
    P: Eq + Hash,
{
    Genesis {
        hash: H,
        cmd: T,
        view_number: u64,
    },

    Normal {
        hash: H,
        parent: H,
        cmd: T,
        justify: QuorumCertificate<H, P, S>,
        view_number: u64,
    },

    Dummy {
        hash: H,
        parent: H,
        view_number: u64,
    },
}

#[derive(Clone)]
#[derive(Eq, PartialEq)]
pub enum Node<H, T, P, S>
where
    P: Eq + Hash,
{
    Genesis {
        hash: H,
        cmd: T,
        view_number: u64,
    },

    Normal {
        hash: H,
        parent: Box<Node<H, T, P, S>>,
        cmd: T,
        justify: Qc<H, T, P, S>,
        view_number: u64,
    },

    Dummy {
        hash: H,
        parent: Box<Node<H, T, P, S>>,
        view_number: u64,
    },
}

pub struct Chain<H, T, P, S>
where
    P: Eq + Hash,
{
    locked: Option<Node<H, T, P, S>>,
    executed: Option<Node<H, T, P, S>>,
    leaf: Option<Node<H, T, P, S>>,
    highest_qc: Option<Qc<H, T, P, S>>,
    v_height: u64,
}

impl<H, T, P, S> SerailizedNode<H, T, P, S>
where
    H: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    T: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
    P: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    S: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
{
    pub fn to_vec(&self) -> Vec<u8> {
        self.into()
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Self::try_from(bytes)
    }
}

impl<H, T, P, S> Node<H, T, P, S>
where
    H: Clone + Eq + Hash,
    T: Clone + Eq,
    P: Clone + Eq + Hash,
    S: Clone + Eq,
{
    pub fn view_number(&self) -> u64 {
        match self {
            Node::Genesis { view_number, .. } => *view_number,
            Node::Normal { view_number, .. } => *view_number,
            Node::Dummy { view_number, .. } => *view_number,
        }
    }

    pub fn justify(&self) -> Option<&Qc<H, T, P, S>> {
        match self {
            Node::Normal { justify, .. } => Some(justify),
            _ => None,
        }
    }

    pub fn parent(&self) -> Option<&Node<H, T, P, S>> {
        match self {
            Node::Normal { parent, .. } => Some(parent),
            Node::Dummy { parent, .. } => Some(parent),
            Node::Genesis { .. } => None,
        }
    }

    pub fn hash(&self) -> &H {
        match self {
            Node::Genesis { hash, .. } => hash,
            Node::Normal { hash, .. } => hash,
            Node::Dummy { hash, .. } => hash,
        }
    }

    pub fn hash_take(self) -> H {
        match self {
            Node::Genesis { hash, .. } => hash,
            Node::Normal { hash, .. } => hash,
            Node::Dummy { hash, .. } => hash,
        }
    }

    pub fn is_parent_eq_justify(&self) -> bool {
        match self {
            Node::Normal {
                parent, justify, ..
            } => *parent == justify.node,
            Node::Dummy { .. } => false,
            Node::Genesis { .. } => false,
        }
    }

    pub fn extends_from(&self, other: &Node<H, T, P, S>) -> bool {
        let mut cur = self;

        loop {
            if cur == other {
                return true;
            }

            match cur.parent() {
                Some(parent) => cur = parent,
                None => return false,
            }
        }

        false
    }
}

impl<H, T, P, S> Chain<H, T, P, S>
where
    H: Clone + Eq + Hash,
    T: Clone + Eq,
    P: Clone + Eq + Hash,
    S: Clone + Eq,
{
    pub fn update(&mut self, b3: Node<H, T, P, S>) -> Option<Vec<T>> {
        self.update_highest_qc(b3.justify()?);

        let b2 = &b3.justify()?.node;
        let b1 = &b2.justify()?.node;

        if b1.view_number() > self.locked.as_ref().map_or(0, |n| n.view_number()) {
            self.locked = Some(*b1.clone());
        }

        if b2.is_parent_eq_justify() && b1.is_parent_eq_justify() {
            let mut res = Vec::new();
            self.on_commit(b2, &mut res);
            self.executed = Some(*b1.justify()?.node.clone());
            return Some(res);
        }

        None
    }

    fn update_highest_qc(&mut self, highest_qc_prime: &Qc<H, T, P, S>) {
        if highest_qc_prime.node.view_number()
            > self
                .highest_qc
                .as_ref()
                .map_or(0, |qc| qc.node.view_number())
        {
            self.highest_qc = Some(highest_qc_prime.clone());
            self.leaf = Some(*highest_qc_prime.node.clone());
        }
    }

    fn on_commit(&self, b: &Node<H, T, P, S>, cmds: &mut Vec<T>) {
        if let Some(executed) = &self.executed {
            if executed.view_number() < b.view_number() {
                if let Node::Normal { cmd, .. } = b {
                    cmds.push(cmd.clone());
                }

                if let Some(parent) = b.parent() {
                    self.on_commit(parent, cmds);
                }
            }
        }
    }

    pub fn is_valid_node(&self, node: &Node<H, T, P, S>) -> bool {
        if node.view_number() <= self.v_height {
            return false;
        }

        let locked = match &self.locked {
            Some(locked) => locked,
            None => return true,
        };

        node.extends_from(locked)
            || node
                .justify()
                .is_some_and(|qc| qc.node.view_number() > locked.view_number())
    }
}

impl<H, T, P, S> From<Node<H, T, P, S>> for SerailizedNode<H, T, P, S>
where
    H: Clone + Eq + Hash,
    P: Clone + Eq + Hash,
    T: Clone + Eq,
    S: Clone + Eq,
{
    fn from(node: Node<H, T, P, S>) -> Self {
        match node {
            Node::Genesis {
                hash,
                cmd,
                view_number,
            } => SerailizedNode::Genesis {
                hash,
                cmd,
                view_number,
            },
            Node::Normal {
                hash,
                parent,
                cmd,
                justify,
                view_number,
            } => {
                let justify = QuorumCertificate {
                    node: justify.node.hash_take(),
                    view_number,
                    sig: justify.sig,
                };

                SerailizedNode::Normal {
                    hash,
                    parent: parent.hash_take(),
                    cmd,
                    justify,
                    view_number,
                }
            }
            Node::Dummy {
                hash,
                parent,
                view_number,
            } => SerailizedNode::Dummy {
                hash,
                parent: parent.hash().clone(),
                view_number,
            },
        }
    }
}

impl<H, T, P, S> From<&Node<H, T, P, S>> for SerailizedNode<H, T, P, S>
where
    H: Clone + Eq + Hash,
    P: Clone + Eq + Hash,
    T: Clone + Eq,
    S: Clone + Eq,
{
    fn from(node: &Node<H, T, P, S>) -> Self {
        match node {
            Node::Genesis {
                hash,
                cmd,
                view_number,
            } => SerailizedNode::Genesis {
                hash: hash.clone(),
                cmd: cmd.clone(),
                view_number: *view_number,
            },
            Node::Normal {
                hash,
                parent,
                cmd,
                justify,
                view_number,
            } => {
                let justify = QuorumCertificate {
                    node: justify.node.hash().clone(),
                    view_number: *view_number,
                    sig: justify.sig.clone(),
                };

                SerailizedNode::Normal {
                    hash: hash.clone(),
                    parent: parent.hash().clone(),
                    cmd: cmd.clone(),
                    justify: justify.clone(),
                    view_number: *view_number,
                }
            }
            Node::Dummy {
                hash,
                parent,
                view_number,
            } => SerailizedNode::Dummy {
                hash: hash.clone(),
                parent: parent.hash().clone(),
                view_number: *view_number,
            },
        }
    }
}

impl<H, T, P, S> From<SerailizedNode<H, T, P, S>> for Vec<u8>
where
    H: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    T: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
    P: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    S: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
{
    fn from(node: SerailizedNode<H, T, P, S>) -> Self {
        (&node).into()
    }
}

impl<H, T, P, S> From<&SerailizedNode<H, T, P, S>> for Vec<u8>
where
    H: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    T: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
    P: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    S: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
{
    fn from(node: &SerailizedNode<H, T, P, S>) -> Self {
        bincode::serde::encode_to_vec(node, bincode::config::standard())
            .expect("Failed to serialize node")
    }
}

impl<H, T, P, S> TryFrom<Vec<u8>> for SerailizedNode<H, T, P, S>
where
    H: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    T: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
    P: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    S: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
{
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        bytes.as_slice().try_into()
    }
}

impl<H, T, P, S> TryFrom<&Vec<u8>> for SerailizedNode<H, T, P, S>
where
    H: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    T: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
    P: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    S: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
{
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self> {
        bytes.as_slice().try_into()
    }
}

impl<H, T, P, S> TryFrom<&[u8]> for SerailizedNode<H, T, P, S>
where
    H: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    T: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
    P: Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash,
    S: Serialize + for<'a> Deserialize<'a> + Clone + Eq,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(d, _)| d)
            .map_err(Error::from)
    }
}
