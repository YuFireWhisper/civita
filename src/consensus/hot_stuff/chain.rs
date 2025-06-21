use std::hash::Hash;

use crate::consensus::hot_stuff::utils::QuorumCertificate;

type Qc<H, T, P, S> = QuorumCertificate<Box<Node<H, T, P, S>>, P, S>;

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

    pub fn is_parent_eq_justify(&self) -> bool {
        match self {
            Node::Normal {
                parent, justify, ..
            } => *parent == justify.node,
            Node::Dummy { .. } => false,
            Node::Genesis { .. } => false,
        }
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
}
