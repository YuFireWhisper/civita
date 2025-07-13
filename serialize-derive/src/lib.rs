use proc_macro::TokenStream;
use syn::{parse_macro_input, Data, DeriveInput};

use crate::{enum_impl::generate_enum_impl, struct_impl::generate_struct_impl};

pub(crate) mod attribute;
mod enum_impl;
mod struct_impl;

#[proc_macro_derive(Serialize, attributes(serialize))]
pub fn derive_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = match &input.data {
        Data::Struct(data_struct) => generate_struct_impl(
            name,
            &impl_generics,
            &ty_generics,
            where_clause,
            data_struct,
        ),
        Data::Enum(data_enum) => {
            generate_enum_impl(name, &impl_generics, &ty_generics, where_clause, data_enum)
        }
        Data::Union(_) => {
            panic!("Union types are not supported")
        }
    };

    TokenStream::from(expanded)
}
