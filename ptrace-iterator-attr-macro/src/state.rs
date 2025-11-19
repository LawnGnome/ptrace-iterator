use darling::ast::{Fields, Style};
use itertools::Itertools;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{Attribute, Ident, Path, Type, Visibility};

use crate::derive::{Field, Ptr, Variant};

/// Global state that gets built up as we parse an enum.
#[derive(Debug)]
pub struct State {
    from_args: Vec<TokenStream>,
    structs: Vec<TokenStream>,
    syscalls: Vec<TokenStream>,
    variants: Vec<TokenStream>,

    core: Path,
}

impl State {
    pub fn new(core: Path) -> Self {
        Self {
            from_args: Default::default(),
            structs: Default::default(),
            syscalls: Default::default(),
            variants: Default::default(),
            core,
        }
    }

    pub fn into_token_stream(
        self,
        ident: &Ident,
        vis: &Visibility,
        attrs: &Vec<Attribute>,
    ) -> TokenStream {
        let Self {
            from_args,
            structs,
            syscalls,
            variants,
            core,
        } = self;

        quote! {
            #(#structs)*

            #(#attrs)*
            #[derive(Debug, Clone)]
            #vis enum #ident {
                #(#variants),*,
                Other(#core::Other),
            }

            impl #ident {
                #vis fn nr(&self) -> #core::syscalls::Sysno {
                    match self {
                        #(#syscalls),*,
                        Self::Other(#core::Other { nr, .. }) => *nr,
                    }
                }

                #vis fn try_from_raw(nr: impl Into<#core::syscalls::Sysno>, args: [u64; 6]) -> #core::Result<Self> {
                    let nr = nr.into();
                    let mut args_iter = args.iter().copied();
                    let syscall = match nr {
                        #(#from_args),*,
                        nr => Self::Other(#core::Other { nr, args }),
                    };

                    Ok(syscall)
                }
            }
        }
    }

    pub fn observe_variant(
        &mut self,
        vis: &Visibility,
        Variant {
            ident,
            syscall,
            fields,
        }: Variant,
    ) -> darling::Result<()> {
        let syscall = syscall.iter().exactly_one().map_err(|e| match e.len() {
            0 => darling::Error::custom("no syscall number provided"),
            n => darling::Error::custom(format!("expected exactly one syscall number, got {n}"))
                .with_span(&ident),
        })?;

        self.add_syscall(&ident, syscall);
        self.add_variant(&ident);

        match &fields.style {
            Style::Unit => self.add_unit_fields(ident, syscall, vis),
            Style::Struct => self.add_struct_fields(ident, syscall, vis, fields),
            Style::Tuple => {
                Err(darling::Error::custom("variant cannot be a tuple struct").with_span(&ident))
            }
        }
    }

    fn add_struct_fields(
        &mut self,
        ident: Ident,
        syscall: &Path,
        vis: &Visibility,
        fields: Fields<Field>,
    ) -> darling::Result<()> {
        let core = &self.core;
        let mut state = StructState::new(core);

        for (i, field) in fields.into_iter().enumerate() {
            state.observe_field(i, vis, field)?;
        }

        let StructState {
            from_arg_fields,
            struct_fields,
            impl_methods,
            ..
        } = state;

        self.from_args.push(quote! {
            #core::syscalls::Sysno::#syscall => {
                Self::#ident(#ident {
                    #(#from_arg_fields),*
                })
            }
        });

        self.structs.push(quote! {
            #[allow(clippy::len_without_is_empty)]
            #[derive(Debug, Clone)]
            #vis struct #ident {
                #(#struct_fields),*
            }

            impl #ident {
                #(#impl_methods)*
            }
        });

        Ok(())
    }

    fn add_syscall(&mut self, ident: &Ident, syscall: &Path) {
        let core = &self.core;

        self.syscalls.push(quote! {
            Self::#ident(..) => #core::syscalls::Sysno::#syscall
        });
    }

    fn add_unit_fields(
        &mut self,
        ident: Ident,
        syscall: &Path,
        vis: &Visibility,
    ) -> darling::Result<()> {
        let core = &self.core;

        self.from_args.push(quote! {
            #core::syscalls::Sysno::#syscall => Self::#ident(#ident)
        });

        self.structs.push(quote! {
            #[derive(Debug, Clone)]
            #vis struct #ident;
        });

        Ok(())
    }

    fn add_variant(&mut self, ident: &Ident) {
        self.variants.push(quote! {
            #ident(#ident)
        });
    }
}

/// Per-variant state.
///
/// (At least for struct variants; unit variants aren't that complicated.)
#[derive(Debug)]
struct StructState<'state> {
    from_arg_fields: Vec<TokenStream>,
    struct_fields: Vec<TokenStream>,
    impl_methods: Vec<TokenStream>,
    core: &'state Path,
}

impl<'state> StructState<'state> {
    pub fn new(core: &'state Path) -> Self {
        Self {
            from_arg_fields: Default::default(),
            struct_fields: Default::default(),
            impl_methods: Default::default(),
            core,
        }
    }

    pub fn observe_field(
        &mut self,
        i: usize,
        vis: &Visibility,
        Field {
            ident,
            ty,
            private,
            ptr,
        }: Field,
    ) -> darling::Result<()> {
        let ident = ident
            .ok_or_else(|| darling::Error::custom("unexpectedly missing ident for struct field"))?;

        if let Some(ptr) = ptr {
            self.add_ptr(i, vis, ident, ty, ptr, private);
        } else {
            self.add_register(i, vis, ident, ty, private);
        }

        Ok(())
    }

    fn add_register(&mut self, i: usize, vis: &Visibility, ident: Ident, ty: Type, private: bool) {
        let core = &self.core;

        self.from_arg_fields.push(quote! {
            #ident: <#ty as #core::TryFromArg>::try_from_arg(args[#i])?
        });

        self.struct_fields.push(quote! { #ident: #ty });

        if !private {
            self.impl_methods.push(quote! {
                #[allow(non_snake_case)]
                #vis fn #ident(&self) -> #ty {
                    self.#ident
                }
            });
        }
    }

    fn add_ptr(
        &mut self,
        i: usize,
        vis: &Visibility,
        ident: Ident,
        ty: Type,
        ptr: Ptr,
        private: bool,
    ) {
        let core = &self.core;

        // User pointers are always overridden into usize in the generated struct.
        self.from_arg_fields.push(quote! {
            #ident: #core::Opaque(args[#i] as usize)
        });

        self.struct_fields.push(quote! { #ident: #core::Opaque });

        // Only add impl methods if this isn't private.
        if !private {
            match ptr {
                Ptr::Array(count) => self.add_ptr_array(vis, ident, ty, count),
                Ptr::NulTerminated => self.add_ptr_nul_terminated(vis, ident, ty),
                Ptr::Opaque => self.add_ptr_opaque(vis, ident, ty),
                Ptr::Single => self.add_ptr_single(vis, ident, ty),
                Ptr::Socket(len) => self.add_ptr_socket(vis, ident, ty, len),
                Ptr::UnboundedArray => self.add_ptr_unbounded_array(vis, ident, ty),
            }
        }
    }

    fn add_ptr_array(&mut self, vis: &Visibility, ident: Ident, ty: Type, count: Ident) {
        let core = &self.core;

        if let Type::Path(path) = &ty
            && path.path.get_ident() == Some(&Ident::new("u8", Span::call_site()))
        {
            // Special case Vec<u8> handling.
            self.impl_methods.push(quote! {
                /// # Safety
                /// 
                /// This method can only be called safely while the traced process is stopped, and
                /// before the kernel handles the syscall.
                #[allow(non_snake_case)]
                #vis unsafe fn #ident(&self, pid: #core::nix::unistd::Pid) -> #core::Result<Box<[u8]>> {
                    unsafe { #core::read(pid, self.#ident, self.#count as usize) }
                }
            });
        } else {
            self.impl_methods.push(quote! {
                /// # Safety
                /// 
                /// This method can only be called safely while the traced process is stopped, and
                /// before the kernel handles the syscall.
                #[allow(non_snake_case)]
                #vis unsafe fn #ident(&self, pid: #core::nix::unistd::Pid) -> impl Iterator<Item = #core::Result<#ty>> {
                    let size = ::std::mem::size_of::<#ty>();
                    (0..(self.#count as usize)).map(move |i| {
                        let addr = #core::Opaque(self.#ident.0 + (i * size));
                        unsafe { #core::read_to_type(pid, addr) }
                    })
                }
            });
        }
    }

    fn add_ptr_nul_terminated(&mut self, vis: &Visibility, ident: Ident, ty: Type) {
        let core = &self.core;

        self.impl_methods.push(quote! {
            /// # Safety
            /// 
            /// This method can only be called safely while the traced process is stopped, and
            /// before the kernel handles the syscall.
            /// 
            /// If the buffer being read is not NUL-terminated, this will almost certainly result
            /// in a segfault.
            #[allow(non_snake_case)]
            #vis unsafe fn #ident(&self, pid: #core::nix::unistd::Pid) -> #core::Result<#ty> {
                let raw = unsafe { #core::read_to_nul(pid, self.#ident) }?;
                let os_str = <::std::ffi::OsString as ::std::os::unix::ffi::OsStringExt>::from_vec(raw);
                Ok(os_str.into())
            }
        });
    }

    fn add_ptr_opaque(&mut self, vis: &Visibility, ident: Ident, ty: Type) {
        let core = &self.core;

        let read_ident = format_ident!("read_{}", ident);
        let read_ident_to_type = format_ident!("read_{}_to_type", ident);

        self.impl_methods.push(quote! {
            /// Returns the opaque pointer into the process's address space.
            #[allow(non_snake_case)]
            #vis fn #ident(&self) -> #core::Opaque {
                // It's quite possible that code using this macro won't otherwise refer to the
                // whatever Opaque is aliased as, so we'll just declare a type alias we don't use
                // here to prevent any warnings.
                type PreventWarnings = #ty;

                self.#ident
            }

            /// # Safety
            /// 
            /// This method can only be called safely while the traced process is stopped, and
            /// before the kernel handles the syscall.
            #[allow(non_snake_case)]
            #vis unsafe fn #read_ident(&self, pid: #core::nix::unistd::Pid, count: usize) -> #core::Result<Box<[u8]>> {
                unsafe { #core::read(pid, self.#ident, count) }
            }

            /// # Safety
            /// 
            /// This method can only be called safely while the traced process is stopped, and
            /// before the kernel handles the syscall.
            #[allow(non_snake_case)]
            #vis unsafe fn #read_ident_to_type<T: Sized>(&self, pid: #core::nix::unistd::Pid) -> #core::Result<T> {
                unsafe { #core::read_to_type(pid, self.#ident) }
            }
        });
    }

    fn add_ptr_single(&mut self, vis: &Visibility, ident: Ident, ty: Type) {
        let core = &self.core;

        self.impl_methods.push(quote! {
            /// # Safety
            ///
            /// This method can only be called safely while the traced process is stopped, and
            /// before the kernel handles the syscall.
            #[allow(non_snake_case)]
            #vis unsafe fn #ident(&self, pid: #core::nix::unistd::Pid) -> #core::Result<#ty> {
                unsafe { #core::read_to_type(pid, self.#ident) }
            }
        });
    }

    fn add_ptr_socket(&mut self, vis: &Visibility, ident: Ident, ty: Type, len: Ident) {
        let core = &self.core;

        self.impl_methods.push(quote! {
            /// # Safety
            ///
            /// This method can only be called safely while the traced process is stopped, and
            /// before the kernel handles the syscall.
            #[allow(non_snake_case)]
            #vis unsafe fn #ident(&self, pid: #core::nix::unistd::Pid) -> #core::Result<#core::nix::sys::socket::SockaddrStorage> {
                // It's quite possible that code using this macro won't otherwise refer to the
                // whatever SockaddrStorage is aliased as, so we'll just declare a type alias we
                // don't use here to prevent any warnings.
                type PreventWarnings = #ty;

                let raw = unsafe { #core::read(pid, self.#ident, self.#len as usize) }?;
                <#core::nix::sys::socket::SockaddrStorage as #core::nix::sys::socket::SockaddrLike>::from_raw(
                    raw.as_ptr() as *const #core::nix::sys::socket::sockaddr,
                    Some(self.#len as #core::nix::libc::socklen_t),
                ).ok_or_else(|| #core::Error::SockaddrParse {
                    addr: self.#ident,
                    pid,
                })
            }
        });
    }

    fn add_ptr_unbounded_array(&mut self, vis: &Visibility, ident: Ident, ty: Type) {
        let core = &self.core;

        self.impl_methods.push(quote! {
            /// Returns the `n`-th element in the array.
            /// 
            /// # Safety
            /// 
            /// This method can only be called safely while the traced process is stopped, and
            /// before the kernel handles the syscall.
            /// 
            /// No bounds check is performed on the element number.
            #[allow(non_snake_case)]
            #vis unsafe fn #ident(&self, pid: #core::nix::unistd::Pid, n: usize) -> #core::Result<#ty> {
                unsafe { #core::read_to_type(pid, self.#ident + (n* ::std::mem::size_of::<#ty>())) }
            }
        });
    }
}
