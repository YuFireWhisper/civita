use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataEnum, Ident, ImplGenerics, TypeGenerics, WhereClause};

use crate::fields_handler::{FieldsHandler, Type};

pub fn impl_enum(
    name: &Ident,
    impl_generics: &ImplGenerics,
    ty_generics: &TypeGenerics,
    where_clause: Option<&WhereClause>,
    data_enum: &DataEnum,
) -> TokenStream {
    let variant_count = data_enum.variants.len();
    if variant_count > 256 {
        panic!("Enum has too many variants (max 256 supported)");
    }

    let (from_reader, to_writer) = impl_variants(data_enum);
    let where_clause = where_clause.map(|wc| quote! { #wc });

    quote! {
        impl #impl_generics civita_serialize::Serialize for #name #ty_generics #where_clause {
            fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, civita_serialize::Error> {
                let discriminant = u8::from_reader(reader)?;
                match discriminant {
                    #(#from_reader,)*
                    _ => Err(civita_serialize::Error(format!("Invalid discriminant: {}", discriminant))),
                }
            }

            fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
                match self {
                    #(#to_writer,)*
                }
            }
        }
    }
}

fn impl_variants(data_enum: &DataEnum) -> (Vec<TokenStream>, Vec<TokenStream>) {
    data_enum
        .variants
        .iter()
        .enumerate()
        .map(|(idx, variant)| {
            let ty = Type::new_enum(&variant.ident, idx as u8);
            FieldsHandler::handle_fields(&variant.fields, ty)
        })
        .unzip()
}
