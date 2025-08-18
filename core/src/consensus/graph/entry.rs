use std::collections::{HashMap, HashSet};

use crate::{
    crypto::Multihash,
    ty::atom::{Atom, Command, Key, Version, Witness},
    utils::Trie,
};

pub struct BlockEntry<C> {
    pub atom: Atom<C>,
    pub witness: Witness,

    pub trie: Trie,

    pub parent: usize,
    pub children: HashSet<usize>,

    pub outputs: HashMap<Key, HashMap<Version, HashSet<usize>>>,
    pub weight: usize,
}

pub struct PendingEntry<C: Command> {
    pub atom: Atom<C>,
    pub witness: Witness,

    pub remaining_inputs: HashMap<Key, Option<Version>>,
    pub input: HashMap<Key, (C::Value, Version)>,
    pub output: HashMap<Key, (C::Value, Version)>,

    pub block_parent: Option<usize>,
    pub parents: HashSet<usize>,
    pub children: HashSet<usize>,

    pub pending_parent_count: usize,
}

pub struct BasicEntry<C: Command> {
    pub atom: Atom<C>,
    pub witness: Witness,

    pub output: HashMap<Key, (C::Value, Version)>,

    pub block_parent: usize,
    pub children: HashSet<usize>,
}

#[derive(Default)]
pub struct MissingEntry {
    pub children: HashSet<usize>,
}

pub enum Entry<C: Command> {
    Block(Box<BlockEntry<C>>),
    Pending(Box<PendingEntry<C>>),
    Basic(Box<BasicEntry<C>>),
    Missing(Box<MissingEntry>),
}

impl<C: Command> PendingEntry<C> {
    pub fn new(atom: Atom<C>, witness: Witness) -> Self {
        let remaining_inputs = atom.cmd.as_ref().map(|c| c.input()).unwrap_or_default();

        Self {
            atom,
            witness,
            remaining_inputs,
            input: HashMap::new(),
            output: HashMap::new(),
            block_parent: None,
            parents: HashSet::new(),
            children: HashSet::new(),
            pending_parent_count: 0,
        }
    }
}

impl<C: Command> Entry<C> {
    pub fn new_pending(atom: Atom<C>, witness: Witness) -> Self {
        Entry::Pending(Box::new(PendingEntry::new(atom, witness)))
    }

    pub fn into_block(self, trie: Trie) -> Self {
        if let Entry::Pending(entry) = self {
            Entry::Block(Box::new(BlockEntry {
                atom: entry.atom,
                witness: entry.witness,
                trie,
                parent: entry.block_parent.expect("Block parent must be set"),
                children: entry.children,
                outputs: HashMap::new(),
                weight: 0,
            }))
        } else {
            panic!("Cannot convert non-pending entry into a block");
        }
    }

    pub fn into_basic(self) -> Self {
        if let Entry::Pending(entry) = self {
            Entry::Basic(Box::new(BasicEntry {
                atom: entry.atom,
                witness: entry.witness,
                output: entry.output,
                block_parent: entry.block_parent.expect("Block parent must be set"),
                children: entry.children,
            }))
        } else {
            panic!("Cannot convert non-pending entry into a basic entry");
        }
    }

    pub fn add_child(&mut self, child: usize) {
        match self {
            Entry::Block(entry) => {
                entry.children.insert(child);
            }
            Entry::Pending(entry) => {
                entry.children.insert(child);
            }
            Entry::Basic(entry) => {
                entry.children.insert(child);
            }
            Entry::Missing(entry) => {
                entry.children.insert(child);
            }
        }
    }

    pub fn remove_child(&mut self, child: usize) {
        match self {
            Entry::Block(entry) => {
                entry.children.remove(&child);
            }
            Entry::Pending(entry) => {
                entry.children.remove(&child);
            }
            Entry::Basic(entry) => {
                entry.children.remove(&child);
            }
            Entry::Missing(entry) => {
                entry.children.remove(&child);
            }
        }
    }

    pub fn as_pending(&self) -> &PendingEntry<C> {
        if let Entry::Pending(entry) = self {
            entry
        } else {
            panic!("Entry is not a PendingEntry");
        }
    }

    pub fn as_pending_mut(&mut self) -> &mut PendingEntry<C> {
        if let Entry::Pending(entry) = self {
            entry
        } else {
            panic!("Entry is not a PendingEntry");
        }
    }

    pub fn as_pending_mut_opt(&mut self) -> Option<&mut PendingEntry<C>> {
        if let Entry::Pending(entry) = self {
            Some(entry)
        } else {
            None
        }
    }

    pub fn as_block(&self) -> &BlockEntry<C> {
        if let Entry::Block(entry) = self {
            entry
        } else {
            panic!("Entry is not a BlockEntry");
        }
    }

    pub fn as_block_opt(&self) -> Option<&BlockEntry<C>> {
        if let Entry::Block(entry) = self {
            Some(entry)
        } else {
            None
        }
    }

    pub fn as_block_mut(&mut self) -> &mut BlockEntry<C> {
        if let Entry::Block(entry) = self {
            entry
        } else {
            panic!("Entry is not a BlockEntry");
        }
    }

    pub fn as_basic(&self) -> &BasicEntry<C> {
        if let Entry::Basic(entry) = self {
            entry
        } else {
            panic!("Entry is not a BasicEntry");
        }
    }

    pub fn as_basic_mut(&mut self) -> &mut BasicEntry<C> {
        if let Entry::Basic(entry) = self {
            entry
        } else {
            panic!("Entry is not a BasicEntry");
        }
    }

    pub fn hash(&self) -> Option<Multihash> {
        match self {
            Entry::Block(entry) => Some(entry.atom.hash()),
            Entry::Pending(entry) => Some(entry.atom.hash()),
            Entry::Basic(entry) => Some(entry.atom.hash()),
            Entry::Missing(_) => None,
        }
    }

    pub fn children(&self) -> &HashSet<usize> {
        match self {
            Entry::Block(entry) => &entry.children,
            Entry::Pending(entry) => &entry.children,
            Entry::Basic(entry) => &entry.children,
            Entry::Missing(entry) => &entry.children,
        }
    }

    pub fn children_take(&mut self) -> HashSet<usize> {
        match self {
            Entry::Block(entry) => std::mem::take(&mut entry.children),
            Entry::Pending(entry) => std::mem::take(&mut entry.children),
            Entry::Basic(entry) => std::mem::take(&mut entry.children),
            Entry::Missing(entry) => std::mem::take(&mut entry.children),
        }
    }

    pub fn block_parent(&self) -> Option<usize> {
        match self {
            Entry::Block(entry) => Some(entry.parent),
            Entry::Pending(entry) => entry.block_parent,
            Entry::Basic(entry) => Some(entry.block_parent),
            Entry::Missing(_) => None,
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self, Entry::Block(_))
    }

    pub fn is_valid(&self) -> bool {
        matches!(self, Entry::Basic(_) | Entry::Block(_))
    }

    pub fn is_missing(&self) -> bool {
        matches!(self, Entry::Missing(_))
    }
}

impl<C: Command> Default for Entry<C> {
    fn default() -> Self {
        Entry::Missing(Box::default())
    }
}
