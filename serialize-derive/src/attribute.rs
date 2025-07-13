use syn::{meta::ParseNestedMeta, Field};

const SKIP: &str = "skip";
const SERIALIZE_WITH: &str = "serialize_with";
const DESERIALIZE_WITH: &str = "deserialize_with";

#[derive(Default)]
pub(crate) struct Attributes {
    pub skip: bool,
    pub serialize_with: Option<syn::Path>,
    pub deserialize_with: Option<syn::Path>,
}

impl Attributes {
    pub fn from_field(field: &Field) -> Self {
        let mut attrs = Attributes::default();

        for attr in &field.attrs {
            if !attr.path().is_ident("serialize") {
                continue;
            }

            let _ = attr.parse_nested_meta(|meta| attrs.parse_nested_meta(&meta));
        }

        attrs
    }

    fn parse_nested_meta(&mut self, meta: &ParseNestedMeta) -> syn::Result<()> {
        if meta.path.is_ident(SKIP) {
            self.skip = true;
            return Ok(());
        }

        if meta.path.is_ident(SERIALIZE_WITH) {
            let str_lit: syn::LitStr = meta.value()?.parse()?;
            let path = syn::parse_str::<syn::Path>(&str_lit.value())
                .map_err(|_| meta.error("Failed to parse serialize_with path"))?;
            self.serialize_with = Some(path);
            return Ok(());
        }

        if meta.path.is_ident(DESERIALIZE_WITH) {
            let str_lit: syn::LitStr = meta.value()?.parse()?;
            let path = syn::parse_str::<syn::Path>(&str_lit.value())
                .map_err(|_| meta.error("Failed to parse deserialize_with path"))?;
            self.deserialize_with = Some(path);
            return Ok(());
        }

        Err(meta.error("Unknown attribute"))
    }
}
