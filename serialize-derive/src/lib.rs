use proc_macro::TokenStream;
use syn::{parse_macro_input, Data, DeriveInput};

use crate::{enum_impl::impl_enum, struct_impl::impl_struct};

pub(crate) mod attribute;
mod enum_impl;
pub(crate) mod fields_handler;
mod struct_impl;

#[proc_macro_derive(Serialize, attributes(serialize))]
pub fn derive_serialize(input: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &mut input.generics;
    add_trait_bounds(generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = match &input.data {
        Data::Struct(data_struct) => impl_struct(
            name,
            &impl_generics,
            &ty_generics,
            where_clause,
            data_struct,
        ),
        Data::Enum(data_enum) => {
            impl_enum(name, &impl_generics, &ty_generics, where_clause, data_enum)
        }
        Data::Union(_) => {
            panic!("Union types are not supported")
        }
    };

    TokenStream::from(expanded)
}

fn add_trait_bounds(generics: &mut syn::Generics) {
    generics.params.iter_mut().for_each(|param| {
        if let syn::GenericParam::Type(ty_param) = param {
            ty_param
                .bounds
                .push(syn::parse_quote!(civita_serialize::Serialize));
        }
    });
}
