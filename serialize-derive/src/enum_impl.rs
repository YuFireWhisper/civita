use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    DataEnum, Fields, FieldsNamed, FieldsUnnamed, Ident, ImplGenerics, TypeGenerics, WhereClause,
};

use crate::attribute::is_skip;

pub fn generate_enum_impl(
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

    let (from_reader_arms, to_writer_arms) = generate_variant_arms(data_enum);
    let new_where_clause = where_clause.map(|wc| quote! { #wc });

    quote! {
        impl #impl_generics civita_serialize::Serialize for #name #ty_generics #new_where_clause {
            fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, civita_serialize::Error> {
                let discriminant = u8::from_reader(reader)?;
                match discriminant {
                    #(#from_reader_arms,)*
                    _ => Err(civita_serialize::Error(format!("Invalid discriminant: {}", discriminant))),
                }
            }

            fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
                match self {
                    #(#to_writer_arms,)*
                }
            }
        }
    }
}

fn generate_variant_arms(data_enum: &DataEnum) -> (Vec<TokenStream>, Vec<TokenStream>) {
    data_enum
        .variants
        .iter()
        .enumerate()
        .map(|(idx, variant)| {
            let variant_name = &variant.ident;
            let discriminant = idx as u8;

            match &variant.fields {
                Fields::Named(fields) => generate_named_arms(variant_name, discriminant, fields),
                Fields::Unnamed(fields) => {
                    generate_unnamed_arms(variant_name, discriminant, fields)
                }
                Fields::Unit => generate_unit_arms(variant_name, discriminant),
            }
        })
        .unzip()
}

fn generate_named_arms(
    variant_name: &Ident,
    discriminant: u8,
    fields: &FieldsNamed,
) -> (TokenStream, TokenStream) {
    let (serializable, ignored): (Vec<_>, Vec<_>) = fields.named.iter().partition(|f| !is_skip(f));

    let field_names: Vec<_> = serializable.iter().map(|f| &f.ident).collect();
    let ignored_names: Vec<_> = ignored.iter().map(|f| &f.ident).collect();

    let from_arm = quote! {
        #discriminant => {
            #(let #field_names = civita_serialize::Serialize::from_reader(reader)?;)*
            Ok(Self::#variant_name {
                #(#field_names,)*
                #(#ignored_names: Default::default(),)*
            })
        }
    };

    let to_arm = quote! {
        Self::#variant_name { #(#field_names,)* #(#ignored_names: _,)* } => {
            (#discriminant as u8).to_writer(writer);
            #(#field_names.to_writer(writer);)*
        }
    };

    (from_arm, to_arm)
}

fn generate_unnamed_arms(
    variant_name: &Ident,
    discriminant: u8,
    fields: &FieldsUnnamed,
) -> (TokenStream, TokenStream) {
    let serializable_indices: Vec<_> = fields
        .unnamed
        .iter()
        .enumerate()
        .filter(|(_, f)| !is_skip(f))
        .map(|(i, _)| i)
        .collect();

    let field_vars: Vec<_> = serializable_indices
        .iter()
        .map(|i| Ident::new(&format!("field_{i}"), Span::call_site()))
        .collect();

    let (construction, pattern) = build_tuple_patterns(fields, &field_vars);

    let from_arm = quote! {
        #discriminant => {
            #(let #field_vars = civita_serialize::Serialize::from_reader(reader)?;)*
            Ok(Self::#variant_name(#(#construction),*))
        }
    };

    let to_arm = quote! {
        Self::#variant_name(#(#pattern),*) => {
            (#discriminant as u8).to_writer(writer);
            #(#field_vars.to_writer(writer);)*
        }
    };

    (from_arm, to_arm)
}

fn build_tuple_patterns(
    fields: &FieldsUnnamed,
    field_vars: &[Ident],
) -> (Vec<TokenStream>, Vec<TokenStream>) {
    let mut construction = Vec::new();
    let mut pattern = Vec::new();
    let mut var_index = 0;

    for field in fields.unnamed.iter() {
        if is_skip(field) {
            construction.push(quote! { Default::default() });
            pattern.push(quote! { _ });
        } else {
            let var_name = &field_vars[var_index];
            construction.push(quote! { #var_name });
            pattern.push(quote! { #var_name });
            var_index += 1;
        }
    }

    (construction, pattern)
}

fn generate_unit_arms(variant_name: &Ident, discriminant: u8) -> (TokenStream, TokenStream) {
    let from_arm = quote! {
        #discriminant => Ok(Self::#variant_name)
    };

    let to_arm = quote! {
        Self::#variant_name => {
            (#discriminant as u8).to_writer(writer);
        }
    };

    (from_arm, to_arm)
}
