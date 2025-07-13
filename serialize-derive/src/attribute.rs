use syn::{Field, Meta};

const SKIP: &str = "skip";

enum Attribute {
    Skip,
}

impl Attribute {
    pub fn from_field(field: &Field) -> Option<Self> {
        field.attrs.iter().find_map(|attr| {
            if attr.path().is_ident("serialize") {
                match &attr.meta {
                    Meta::List(list) => Self::from_string(&list.tokens.to_string()),
                    _ => None,
                }
            } else {
                None
            }
        })
    }

    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            SKIP => Some(Self::Skip),
            _ => None,
        }
    }

    pub fn is_skip(&self) -> bool {
        matches!(self, Self::Skip)
    }
}

pub fn is_skip(field: &Field) -> bool {
    Attribute::from_field(field).is_some_and(|attr| attr.is_skip())
}
