use quote::quote;
use syn::{Fields, Index};

use crate::attribute::is_skip;

pub fn generate_struct_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    data_struct: &syn::DataStruct,
) -> proc_macro2::TokenStream {
    match &data_struct.fields {
        Fields::Named(fields) => {
            generate_named_fields_impl(name, impl_generics, ty_generics, where_clause, fields)
        }
        Fields::Unnamed(fields) => {
            generate_unnamed_fields_impl(name, impl_generics, ty_generics, where_clause, fields)
        }
        Fields::Unit => generate_unit_impl(name, impl_generics, ty_generics, where_clause),
    }
}

fn generate_named_fields_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    fields: &syn::FieldsNamed,
) -> proc_macro2::TokenStream {
    let (active_fields, ignored_fields): (Vec<_>, Vec<_>) =
        fields.named.iter().partition(|field| !is_skip(field));

    let field_names: Vec<_> = active_fields.iter().map(|f| &f.ident).collect();
    let ignored_field_names: Vec<_> = ignored_fields.iter().map(|f| &f.ident).collect();

    generate_serialize_impl(
        name,
        impl_generics,
        ty_generics,
        where_clause,
        quote! {
            #(let #field_names = civita_serialize::Serialize::from_reader(reader)?;)*
            Ok(Self {
                #(#field_names,)*
                #(#ignored_field_names: Default::default(),)*
            })
        },
        quote! {
            #(self.#field_names.to_writer(writer);)*
        },
    )
}

fn generate_unnamed_fields_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    fields: &syn::FieldsUnnamed,
) -> proc_macro2::TokenStream {
    let (field_vars, tuple_construction, to_writer_indices) = process_unnamed_fields(fields);

    generate_serialize_impl(
        name,
        impl_generics,
        ty_generics,
        where_clause,
        quote! {
            #(let #field_vars = civita_serialize::Serialize::from_reader(reader)?;)*
            Ok(Self(#(#tuple_construction),*))
        },
        quote! {
            #(self.#to_writer_indices.to_writer(writer);)*
        },
    )
}

fn generate_unit_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
) -> proc_macro2::TokenStream {
    generate_serialize_impl(
        name,
        impl_generics,
        ty_generics,
        where_clause,
        quote! { Ok(Self) },
        quote! { /* Unit struct has no data to write */ },
    )
}

fn generate_serialize_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    from_reader_body: proc_macro2::TokenStream,
    to_writer_body: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        impl #impl_generics civita_serialize::Serialize for #name #ty_generics #where_clause {
            fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, civita_serialize::Error> {
                #from_reader_body
            }

            fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
                #to_writer_body
            }
        }
    }
}

fn process_unnamed_fields(
    fields: &syn::FieldsUnnamed,
) -> (Vec<syn::Ident>, Vec<proc_macro2::TokenStream>, Vec<Index>) {
    let mut field_vars = Vec::new();
    let mut tuple_construction = Vec::new();
    let mut to_writer_indices = Vec::new();
    let mut ser_idx = 0;

    for (orig_idx, field) in fields.unnamed.iter().enumerate() {
        let index = Index::from(orig_idx);

        if is_skip(field) {
            tuple_construction.push(quote! { Default::default() });
        } else {
            let var_name =
                syn::Ident::new(&format!("field_{ser_idx}"), proc_macro2::Span::call_site());
            field_vars.push(var_name.clone());
            tuple_construction.push(quote! { #var_name });
            to_writer_indices.push(index);
            ser_idx += 1;
        }
    }

    (field_vars, tuple_construction, to_writer_indices)
}
