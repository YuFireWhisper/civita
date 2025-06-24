use std::hash::Hash;

use crate::{
    consensus::hot_stuff::utils::{QuorumCertificate, ViewNumber},
    traits::{serializable, ConstantSize, Serializable},
};

const NORMAL_ID: u8 = 0;
const DUMMY_ID: u8 = 1;

pub enum View<T, P, S> {
    Normal {
        number: ViewNumber,
        parent_number: ViewNumber,
        cmd: T,
        justify: QuorumCertificate<ViewNumber, P, S>,
    },

    Dummy {
        number: ViewNumber,
        parent_number: ViewNumber,
    },
}

impl<T, P, S> View<T, P, S> {
    pub fn new_normal(
        view_number: ViewNumber,
        parent_number: ViewNumber,
        cmd: T,
        justify: QuorumCertificate<ViewNumber, P, S>,
    ) -> Self {
        View::Normal {
            number: view_number,
            parent_number,
            cmd,
            justify,
        }
    }

    pub fn new_dummy(view_number: ViewNumber, parent_number: ViewNumber) -> Self {
        View::Dummy {
            number: view_number,
            parent_number,
        }
    }

    pub fn is_normal(&self) -> bool {
        matches!(self, View::Normal { .. })
    }

    pub fn number(&self) -> ViewNumber {
        match self {
            View::Normal {
                number: view_number,
                ..
            } => *view_number,
            View::Dummy {
                number: view_number,
                ..
            } => *view_number,
        }
    }

    pub fn parent_number(&self) -> ViewNumber {
        match self {
            View::Normal { parent_number, .. } => *parent_number,
            View::Dummy { parent_number, .. } => *parent_number,
        }
    }

    pub fn cmd(&self) -> Option<&T> {
        match self {
            View::Normal { cmd, .. } => Some(cmd),
            View::Dummy { .. } => None,
        }
    }

    pub fn justify(&self) -> Option<&QuorumCertificate<ViewNumber, P, S>> {
        match self {
            View::Normal { justify, .. } => Some(justify),
            View::Dummy { .. } => None,
        }
    }

    pub fn is_parent_eq_justify(&self) -> bool {
        match self {
            View::Normal {
                parent_number,
                justify,
                ..
            } => *parent_number == justify.view,
            View::Dummy { .. } => false,
        }
    }
}

impl<T, P, S> Serializable for View<T, P, S>
where
    T: Serializable,
    P: Serializable + ConstantSize + Eq + Hash,
    S: Serializable + ConstantSize,
{
    fn serialized_size(&self) -> usize {
        // type_id (1 byte) + view_number (8 bytes) + parent_number (8 bytes, optional)
        let base_size = u8::SIZE + ViewNumber::SIZE + Option::<ViewNumber>::SIZE;

        match self {
            View::Normal { cmd, justify, .. } => {
                base_size + cmd.serialized_size() + justify.serialized_size()
            }

            View::Dummy { .. } => base_size,
        }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let type_id = u8::from_reader(reader)?;
        let number = ViewNumber::from_reader(reader)?;
        let parent_number = ViewNumber::from_reader(reader)?;

        match type_id {
            NORMAL_ID => Ok(View::Normal {
                number,
                parent_number,
                cmd: T::from_reader(reader)?,
                justify: QuorumCertificate::from_reader(reader)?,
            }),

            DUMMY_ID => Ok(View::Dummy {
                number,
                parent_number,
            }),

            _ => Err(serializable::Error(format!("Unknown node type: {type_id}"))),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        match self {
            View::Normal {
                number,
                parent_number,
                cmd,
                justify,
            } => {
                NORMAL_ID.to_writer(writer)?;
                number.to_writer(writer)?;
                parent_number.to_writer(writer)?;
                cmd.to_writer(writer)?;
                justify.to_writer(writer)?;
            }

            View::Dummy {
                number,
                parent_number,
            } => {
                DUMMY_ID.to_writer(writer)?;
                number.to_writer(writer)?;
                parent_number.to_writer(writer)?;
            }
        }

        Ok(())
    }
}
