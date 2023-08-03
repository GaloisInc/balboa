extern crate proc_macro;
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    parse_quote, punctuated::Punctuated, Arm, Data, DataEnum, DeriveInput, Expr, Fields, Pat,
    Token, Variant, WhereClause,
};

fn generate_log_size_body(accessors: &[Expr]) -> Expr {
    parse_quote! {
        0 #(+ ::stallone::LoggableMetadata::log_size(&#accessors))*
    }
}

fn generate_serialize_body(accessors: &[Expr]) -> Expr {
    let field_accessors1 = accessors;
    let field_accessors2 = accessors;
    parse_quote! {{
        #(
            let the_log_size =
                ::stallone::LoggableMetadata::log_size(&#field_accessors1);
            ::stallone::LoggableMetadata::log_serialize(
                &#field_accessors2,
                &mut the_input_buffer[0..the_log_size],
            );
            the_input_buffer = &mut the_input_buffer[the_log_size..];
        )*
        let _ = the_input_buffer;
        ()
    }}
}

fn generate_match_expr<F>(e: &DataEnum, f: F) -> Expr
where
    F: Fn(usize, &Variant, &[Expr]) -> Expr,
{
    // TODO: if we don't use the Arm or Pat type, then we can use syn with just the derive feature.
    let mut arms: Vec<Arm> = Vec::new();
    for (disc, v) in e.variants.iter().enumerate() {
        let fields: Vec<Ident> = (0..v.fields.iter().len())
            .map(|i| format_ident!("field_{:x}", i))
            .collect();
        let accessors: Vec<Expr> = fields.iter().map(|ident| parse_quote! {#ident}).collect();
        let body = f(disc, v, &accessors[..]);
        let name = &v.ident;
        let pat: Pat = match &v.fields {
            Fields::Unit => parse_quote! { Self::#name },
            Fields::Unnamed(_) => parse_quote! { Self::#name(#(#fields),*) },
            Fields::Named(named) => {
                let names = named.named.iter().map(|f| f.ident.as_ref().unwrap());
                parse_quote! {
                    Self::#name { #(#names: #fields),* }
                }
            }
        };
        arms.push(parse_quote! {
            #pat => {
                #body
            },
        });
    }
    parse_quote! {
        match self {
            #(#arms)*
        }
    }
}

fn log_record_type_for_fields(all_fields: &Fields) -> Expr {
    match all_fields {
        Fields::Unit => parse_quote! {
            &[]
        },
        Fields::Unnamed(fields) => {
            let mut contents: Punctuated<Expr, Token![,]> = Punctuated::new();
            for (i, field) in fields.unnamed.iter().enumerate() {
                let ty = &field.ty;
                let name = format!("{}", i);
                contents.push(parse_quote! {
                    ::stallone::internal_metadata_structures::RecordTypeField {
                        name: #name,
                        ty: &<#ty as ::stallone::LoggableMetadata>::TYPE_ID,
                    }
                });
            }
            parse_quote! {
                & [#contents]
            }
        }
        Fields::Named(fields) => {
            let mut contents: Punctuated<Expr, Token![,]> = Punctuated::new();
            for field in &fields.named {
                let ty = &field.ty;
                let name = field.ident.as_ref().unwrap();
                let name = syn::LitStr::new(&name.to_string(), name.span());
                contents.push(parse_quote! {
                    ::stallone::internal_metadata_structures::RecordTypeField {
                        name: #name,
                        ty: &<#ty as ::stallone::LoggableMetadata>::TYPE_ID,
                    }
                });
            }
            parse_quote! {
                &[#contents]
            }
        }
    }
}

// TODO: replace this with the standard diagnostics when feature(proc_macro_diagnostic) becomes stable
#[allow(dead_code)] // Due to https://github.com/rust-lang/rust/issues/88900
#[derive(Debug, Clone)]
struct Diagnostic {
    msg: String,
    location: Span,
}

fn inner_derive_loggable_metadata(item: DeriveInput) -> Result<TokenStream, Diagnostic> {
    let ident = item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();
    let mut where_clause: WhereClause = where_clause.map(|x| x.clone()).unwrap_or(WhereClause {
        where_token: Token![where](Span::call_site()),
        predicates: Punctuated::new(),
    });
    Ok(match &item.data {
        Data::Enum(e) => {
            for v in &e.variants {
                for f in &v.fields {
                    let ty = &f.ty;
                    where_clause.predicates.push(parse_quote! {
                        #ty : ::stallone::LoggableMetadata
                    });
                }
            }
            let log_size =
                generate_match_expr(e, |_, _, accessors| generate_log_size_body(accessors));
            let log_serialize = generate_match_expr(e, |disc, _, accessors| {
                assert!(
                    disc < u8::max_value() as usize,
                    "Too many variants of the enum"
                );
                let core = generate_serialize_body(accessors);
                parse_quote! {{
                    the_input_buffer[0] = #disc as u8;
                    the_input_buffer = &mut the_input_buffer[1..];
                    #core
                }}
            });
            let variant_names = e.variants.iter().map(|v| &v.ident);
            let variant_fields_lrt = e
                .variants
                .iter()
                .map(|v| log_record_type_for_fields(&v.fields));
            quote! {
                #[automatically_derived]
                impl #impl_generics ::stallone::LoggableMetadata for #ident #ty_generics #where_clause {
                    const TYPE_ID: ::stallone::internal_metadata_structures::ValueType<'static> =
                        ::stallone::internal_metadata_structures::ValueType::Enum {
                            name: concat!(module_path!(), "::", stringify!(#ident)),
                            variants: &[
                                #(
                                    ::stallone::internal_metadata_structures::RecordType {
                                        name: stringify!(#variant_names),
                                        fields: #variant_fields_lrt,
                                    },
                                )*
                            ],
                        }
                    ;

                    #[inline]
                    fn log_size(&self) -> usize {
                        1 + #log_size
                    }

                    #[inline]
                    fn log_serialize(&self, mut the_input_buffer: &mut [u8]) {
                        #log_serialize
                    }
                }
            }
        }
        Data::Struct(s) => {
            for f in &s.fields {
                let ty = &f.ty;
                where_clause.predicates.push(parse_quote! {
                    #ty : ::stallone::LoggableMetadata
                });
            }
            let field_accessors: Vec<Expr> = match &s.fields {
                Fields::Unit => Vec::new(),
                Fields::Unnamed(fields) => (0..fields.unnamed.len())
                    .map(syn::Index::from)
                    .map(|i| {
                        parse_quote! {
                            self.#i
                        }
                    })
                    .collect(),
                Fields::Named(fields) => fields
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().unwrap())
                    .map(|name| {
                        parse_quote! {
                            self.#name
                        }
                    })
                    .collect(),
            };
            let log_record_type: Expr = log_record_type_for_fields(&s.fields);
            let log_size = generate_log_size_body(&field_accessors[..]);
            let log_serialize = generate_serialize_body(&field_accessors[..]);
            quote! {
                #[automatically_derived]
                impl #impl_generics ::stallone::LoggableMetadata for #ident #ty_generics #where_clause {
                    const TYPE_ID: ::stallone::internal_metadata_structures::ValueType<'static> =
                        ::stallone::internal_metadata_structures::ValueType::Record {
                            contents: ::stallone::internal_metadata_structures::RecordType {
                                name: concat!(module_path!(), "::", stringify!(#ident)),
                                fields: #log_record_type
                            }
                        }
                    ;

                    #[inline(always)]
                    fn log_size(&self) -> usize {
                        #log_size
                    }

                    #[inline(always)]
                    fn log_serialize(&self, mut the_input_buffer: &mut [u8]) {
                        #log_serialize
                    }
                }
            }
        }
        Data::Union(_) => {
            return Err(Diagnostic {
                msg: "Unions aren't loggable".to_string(),
                location: Span::call_site(),
            });
        }
    })
}

#[proc_macro_derive(LoggableMetadata)]
pub fn derive_loggable_metadata(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    match inner_derive_loggable_metadata(syn::parse_macro_input!(item as DeriveInput)) {
        Ok(out) => {
            // Uncomment this to debug.
            //println!("{}", out);
            out.into()
        }
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}
