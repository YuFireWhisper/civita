use crate::attribute::Attributes;
use quote::quote;

pub enum Type<'a> {
    Struct,
    Enum(&'a syn::Ident, u8),
}

#[derive(Default)]
pub struct FieldsHandler;

impl<'a> Type<'a> {
    pub fn new_enum(variant_name: &'a syn::Ident, discriminant: u8) -> Self {
        Type::Enum(variant_name, discriminant)
    }

    pub fn is_enum(&self) -> bool {
        matches!(self, Type::Enum(_, _))
    }
}

impl FieldsHandler {
    pub fn handle_fields(
        fields: &syn::Fields,
        ty: Type,
    ) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
        match fields {
            syn::Fields::Named(fields) => Self::handle_named(fields, ty),
            syn::Fields::Unnamed(fields) => Self::handle_unnamed(fields, ty),
            syn::Fields::Unit => Self::handle_unit(ty),
        }
    }

    fn handle_named(
        fields: &syn::FieldsNamed,
        ty: Type,
    ) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
        let (from_reader_stmts, to_writer_stmts, construct_fields, pattern_fields) =
            Self::process_named_fields(&fields.named, &ty);

        Self::generate_tokens(
            ty,
            from_reader_stmts,
            to_writer_stmts,
            construct_fields,
            pattern_fields,
            true,
        )
    }

    fn handle_unnamed(
        fields: &syn::FieldsUnnamed,
        ty: Type,
    ) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
        let (from_reader_stmts, to_writer_stmts, construct_fields, pattern_fields) =
            Self::process_unnamed_fields(&fields.unnamed, &ty);

        Self::generate_tokens(
            ty,
            from_reader_stmts,
            to_writer_stmts,
            construct_fields,
            pattern_fields,
            false,
        )
    }

    fn handle_unit(ty: Type) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
        match ty {
            Type::Struct => (quote! { Ok(Self) }, quote! {}),
            Type::Enum(variant_name, discriminant) => (
                quote! { #discriminant => Ok(Self::#variant_name) },
                quote! { Self::#variant_name => { (#discriminant as u8).to_writer(writer); } },
            ),
        }
    }

    fn process_named_fields(
        fields: &syn::punctuated::Punctuated<syn::Field, syn::Token![,]>,
        ty: &Type,
    ) -> (
        Vec<proc_macro2::TokenStream>,
        Vec<proc_macro2::TokenStream>,
        Vec<proc_macro2::TokenStream>,
        Vec<proc_macro2::TokenStream>,
    ) {
        let mut from_reader_stmts = Vec::new();
        let mut to_writer_stmts = Vec::new();
        let mut construct_fields = Vec::new();
        let mut pattern_fields = Vec::new();

        for field in fields {
            let attrs = Attributes::from_field(field);
            let name = &field.ident;

            if attrs.skip {
                construct_fields.push(quote! { #name: Default::default() });
                if ty.is_enum() {
                    pattern_fields.push(quote! { #name: _ });
                }
                continue;
            }

            let de_expr = Self::deserialize_expr(&attrs);
            let ser_expr = Self::serialize_expr(&attrs, quote! { self.#name });

            from_reader_stmts.push(quote! { let #name = #de_expr; });
            to_writer_stmts.push(ser_expr);
            construct_fields.push(quote! { #name });

            if ty.is_enum() {
                pattern_fields.push(quote! { #name });
            }
        }

        (
            from_reader_stmts,
            to_writer_stmts,
            construct_fields,
            pattern_fields,
        )
    }

    fn process_unnamed_fields(
        fields: &syn::punctuated::Punctuated<syn::Field, syn::Token![,]>,
        ty: &Type,
    ) -> (
        Vec<proc_macro2::TokenStream>,
        Vec<proc_macro2::TokenStream>,
        Vec<proc_macro2::TokenStream>,
        Vec<proc_macro2::TokenStream>,
    ) {
        let mut from_reader_stmts = Vec::new();
        let mut to_writer_stmts = Vec::new();
        let mut construct_fields = Vec::new();
        let mut pattern_fields = Vec::new();

        for (i, field) in fields.iter().enumerate() {
            let attrs = Attributes::from_field(field);

            if attrs.skip {
                construct_fields.push(quote! { Default::default() });
                if ty.is_enum() {
                    pattern_fields.push(quote! { _ });
                }
                continue;
            }

            let var_name = syn::Ident::new(&format!("field_{i}"), proc_macro2::Span::call_site());
            let de_expr = Self::deserialize_expr(&attrs);

            let ser_expr = if ty.is_enum() {
                Self::serialize_expr(&attrs, quote! { #var_name })
            } else {
                let index = syn::Index::from(i);
                Self::serialize_expr(&attrs, quote! { self.#index })
            };

            from_reader_stmts.push(quote! { let #var_name = #de_expr; });
            to_writer_stmts.push(ser_expr);
            construct_fields.push(quote! { #var_name });

            if ty.is_enum() {
                pattern_fields.push(quote! { #var_name });
            }
        }

        (
            from_reader_stmts,
            to_writer_stmts,
            construct_fields,
            pattern_fields,
        )
    }

    fn deserialize_expr(attrs: &Attributes) -> proc_macro2::TokenStream {
        match &attrs.deserialize_with {
            Some(f) => quote! { #f(reader)? },
            None => quote! { civita_serialize::Serialize::from_reader(reader)? },
        }
    }

    fn serialize_expr(
        attrs: &Attributes,
        value: proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        match &attrs.serialize_with {
            Some(f) => quote! { #f(&#value, writer); },
            None => quote! { #value.to_writer(writer); },
        }
    }

    fn generate_tokens(
        ty: Type,
        from_reader_stmts: Vec<proc_macro2::TokenStream>,
        to_writer_stmts: Vec<proc_macro2::TokenStream>,
        construct_fields: Vec<proc_macro2::TokenStream>,
        pattern_fields: Vec<proc_macro2::TokenStream>,
        is_named_fields: bool,
    ) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
        match ty {
            Type::Struct => {
                let construct = if is_named_fields {
                    quote! { Ok(Self { #(#construct_fields),* }) }
                } else {
                    quote! { Ok(Self(#(#construct_fields),*)) }
                };
                (
                    quote! {
                        #(#from_reader_stmts)*
                        #construct
                    },
                    quote! { #(#to_writer_stmts)* },
                )
            }
            Type::Enum(variant_name, discriminant) => {
                let (construct, pattern) = if is_named_fields {
                    (
                        quote! { Ok(Self::#variant_name { #(#construct_fields),* }) },
                        quote! { Self::#variant_name { #(#pattern_fields),* } },
                    )
                } else {
                    (
                        quote! { Ok(Self::#variant_name(#(#construct_fields),*)) },
                        quote! { Self::#variant_name(#(#pattern_fields),*) },
                    )
                };

                (
                    quote! {
                        #discriminant => {
                            #(#from_reader_stmts)*
                            #construct
                        }
                    },
                    quote! {
                        #pattern => {
                            (#discriminant as u8).to_writer(writer);
                            #(#to_writer_stmts)*
                        }
                    },
                )
            }
        }
    }
}
