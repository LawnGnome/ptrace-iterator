use darling::{
    FromDeriveInput, FromField, FromMeta, FromVariant,
    ast::{Data, Fields},
    util::PathList,
};
use syn::{Attribute, Ident, Path, Type, Visibility};

#[derive(FromDeriveInput, Debug)]
#[darling(attributes(syscall), forward_attrs(doc), supports(enum_any))]
pub struct SyscallEnum {
    pub ident: Ident,
    pub vis: Visibility,
    pub data: Data<Variant, ()>,
    pub attrs: Vec<Attribute>,
}

#[derive(FromMeta, Debug)]
#[darling(derive_syn_parse)]
pub struct SyscallArgs {
    pub core: Option<Path>,
}

#[derive(FromVariant, Debug)]
#[darling(attributes(syscall))]
pub struct Variant {
    pub ident: Ident,
    #[darling(flatten)]
    pub syscall: PathList,
    pub fields: Fields<Field>,
}

#[derive(FromField, Debug)]
#[darling(attributes(syscall))]
pub struct Field {
    pub ident: Option<Ident>,
    pub ty: Type,
    #[darling(default)]
    pub private: bool,
    pub ptr: Option<Ptr>,
}

/// The possible states of a process pointer in a syscall argument.
#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum Ptr {
    /// A pointer to an array which has a length known in the field specified by the ident.
    Array(Ident),
    /// A pointer to a NUL-terminated string.
    NulTerminated,
    /// An opaque pointer back to a non-specific C type.
    Opaque,
    /// A pointer to a single data structure of a known type.
    Single,
    /// A pointer to a socket address.
    Socket(Ident),
    /// A pointer to an array which does not have a length known in another struct field.
    UnboundedArray,
}

impl FromMeta for Ptr {
    fn from_list(items: &[darling::ast::NestedMeta]) -> darling::Result<Self> {
        #[derive(FromMeta)]
        struct Inner {
            #[darling(default)]
            array: bool,
            count: Option<Ident>,
            #[darling(default)]
            nul_terminated: bool,
            #[darling(default)]
            opaque: bool,
            socket: Option<Ident>,
        }

        let Inner {
            array,
            count,
            nul_terminated,
            opaque,
            socket,
        } = Inner::from_list(items)?;

        match (array, count, nul_terminated, opaque, socket) {
            (false, Some(count), false, false, None) => Ok(Self::Array(count)),
            (false, None, true, false, None) => Ok(Self::NulTerminated),
            (false, None, false, true, None) => Ok(Self::Opaque),
            (false, None, false, false, None) => Ok(Self::Single),
            (false, None, false, false, Some(len)) => Ok(Self::Socket(len)),
            (true, None, false, false, None) => Ok(Self::UnboundedArray),
            _ => {
                let err = darling::Error::unsupported_shape(
                    "only one of array, count, nul_terminated, opaque, or socket can be specified",
                );
                if let Some(item) = items.first() {
                    Err(err.with_span(item))
                } else {
                    Err(err)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_debug_snapshot;
    use itertools::Itertools;
    use quote::quote;
    use syn::DeriveInput;

    use super::*;

    #[test]
    fn invalid_ptr_attrs() -> anyhow::Result<()> {
        let combos = [
            quote! {array},
            quote! {count = count},
            quote! {nul_terminated},
            quote! {opaque},
        ]
        .into_iter()
        .combinations(2);

        for combo in combos {
            let (a, b) = combo.into_iter().collect_tuple().ok_or_else(|| {
                anyhow::anyhow!("unexpected number of combinations when requesting sets of 2")
            })?;

            let input = quote! {
                #[syscall]
                enum Syscall {
                    #[syscall(read)]
                    Read {
                        fd: Fd,
                        #[syscall(ptr(#a, #b))]
                        buf: PathBuf,
                        #[syscall(private)]
                        count: size_t,
                    }
                }
            };

            let input = syn::parse2::<DeriveInput>(input)?;
            assert_debug_snapshot!(SyscallEnum::from_derive_input(&input));
        }

        Ok(())
    }
}
