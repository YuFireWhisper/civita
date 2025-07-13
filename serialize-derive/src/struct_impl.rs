use quote::quote;

use crate::fields_handler::{FieldsHandler, Type};

pub fn impl_struct(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    data_struct: &syn::DataStruct,
) -> proc_macro2::TokenStream {
    let (from_reader, to_writer) = FieldsHandler::handle_fields(&data_struct.fields, Type::Struct);
    let where_clause = where_clause.map(|wc| quote! { #wc });

    quote! {
        impl #impl_generics civita_serialize::Serialize for #name #ty_generics #where_clause {
            fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, civita_serialize::Error> {
                #from_reader
            }

            fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
                #to_writer
            }
        }
    }
}
