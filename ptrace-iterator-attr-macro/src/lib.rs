use darling::FromDeriveInput;
use proc_macro_error::proc_macro_error;
use syn::{DeriveInput, parse_macro_input};

use crate::{
    derive::{SyscallArgs, SyscallEnum},
    state::State,
};

mod derive;
mod state;

// Note that we're not using inter-crate links in the following docblock due to
// https://github.com/rust-lang/rust/issues/138575. Once that's fixed, they can be reinstated.

/// A macro to build an enum and a set of structs for Linux syscalls.
///
/// This probably isn't useful outside of the project it's being written for.
///
/// # Basic usage
///
/// This macro ingests an `enum`. Each variant should correspond to one — and only one — syscall.
/// Variants need to be annotated with the syscall number like so:
///
/// ```
/// # use ptrace_iterator::syscall;
///
/// #[syscall]
/// enum Syscall {
///     #[syscall(fork)]
///     Fork,
/// }
/// ```
///
/// The syscall number must be a valid variant of the
/// [`syscalls::Sysno`](https://docs.rs/syscalls/0.7.0/syscalls/enum.Sysno.html) enum.
///
/// Under the hood, a `struct` is generated for each variant, along with a tuple variant that
/// delegates to that `struct`, eg:
///
/// ```
/// struct Fork;
///
/// enum Syscall {
///     Fork(Fork),
/// }
/// ```
///
/// # Syscalls with arguments
///
/// Syscalls that take arguments should be declared as `struct` variants like so:
///
/// ```
/// # use std::ffi::c_int;
/// # use ptrace_iterator::syscall;
/// #[syscall]
/// enum Syscall {
///     #[syscall(exit)]
///     Exit { error_code: c_int },
/// }
/// ```
///
/// Field ordering is important: arguments will be parsed in the order that they are declared.
///
/// Field types can be anything that implements `ptrace_iterator::core::TryFromArg`.
/// `ptrace_iterator::core` provides implementations for the basic integer types that are likely to
/// show up in syscall interfaces.
///
/// By default, each field will have an accessor method generated on the struct, so the generated
/// `struct` will actually look something like this:
///
/// ```
/// # use std::ffi::c_int;
/// struct Exit { error_code: c_int }
///
/// impl Exit {
///     pub fn error_code(&self) -> c_int { self.error_code }
/// }
/// ```
///
/// This can be controlled, though, with the attributes listed below.
///
/// # Field attributes
///
/// Two attributes are supported on fields. They can be used together or separately.
///
/// ## Private
///
/// `private` prevents the generation of the accessor method for the given field. In most cases,
/// this means that you will want to implement your own accessor that accesses the field(s) of
/// interest directly. For example, we might want to convert an FFI type into something more Rusty:
///
/// ```
/// # use std::ffi::c_int;
/// # use ptrace_iterator::syscall;
/// #[syscall]
/// enum Syscall {
///     #[syscall(exit)]
///     Exit {
///         #[syscall(private)]
///         error_code: c_int,
///     },
/// }
///
/// impl Exit {
///     pub fn error_code(&self) -> u32 {
///         self.error_code as u32
///     }
/// }
/// ```
///
/// ## Pointers
///
/// Pointers into the traced process's address space require more care.
///
/// Since it is impossible to access the tracee's address space without using `ptrace` or
/// `process_readv`, pointers have to be treated internally as simple integers.
/// `ptrace_iterator::core` provides multiple functions to then access the data given the tracee's
/// PID.
///
/// There are multiple types of pointer that can be specified in different ways:
///
/// ### Simple pointers
///
/// A pointer to a single data structure — presumably a C `struct` or `union` — can be specified
/// like so:
///
/// ```
/// # use ptrace_iterator::nix::libc;
/// # use ptrace_iterator::syscall;
/// #[syscall]
/// enum Syscall {
///     #[syscall(nanosleep)]
///     Nanosleep {
///         #[syscall(ptr())]
///         rqtp: libc::timespec,
///         // ...
///     },
/// }
/// ```
///
/// This will generate the following:
///
/// ```
/// # use ptrace_iterator::nix::{self, libc};
/// struct Nanosleep {
///     rqtp: usize,
/// }
///
/// impl Nanosleep {
///     pub unsafe fn rqtp(&self, pid: nix::unistd::Pid) -> ptrace_iterator::core::Result<libc::timespec> {
///         // ...
/// #       todo!()
///     }
/// }
/// ```
///
/// Note that `rqtp` is transformed into a `usize` internally. Also note that the accessor is
/// `unsafe`, since it is only safe to access the value during the syscall (and probably even then
/// only on entry or exit, depending on the syscall).
///
/// ### Opaque pointers
///
/// Some syscall arguments have types that are unknown at build time. For those,
/// `#[syscall(ptr(opaque))]` can be used.
///
/// Practically, this will generate this impl:
///
/// ```
/// # use ptrace_iterator::nix::unistd::Pid;
/// # struct SyscallType;
/// impl SyscallType {
///     pub fn field(&self) -> ptrace_iterator::core::Opaque { todo!() }
///     pub unsafe fn read_field(&self, pid: Pid) -> ptrace_iterator::core::Result<Vec<u8>> { todo!() }
///     pub unsafe fn read_field_to_type<T: Sized>(&self, pid: Pid) -> ptrace_iterator::core::Result<T> { todo!() }
/// }
/// ```
///
/// The field type is technically ignored when the macro is expanded, but should conventionally be
/// `ptrace_iterator::core::Opaque` to avoid confusion.
///
/// ### NUL terminated
///
/// NUL terminated strings can be annotated with `#[syscall(ptr(nul_terminated))]`. The field type
/// must implement `From<OsString>`.
///
/// ### Arrays
///
/// Arrays with the length in another variant field can be declared thusly:
///
/// ```
/// # use std::ffi::c_int;
/// # use ptrace_iterator::syscall;
/// # use ptrace_iterator::core::Fd;
/// #[syscall]
/// enum Syscall {
///     #[syscall(setsockopt)]
///     Setsockopt {
///         fd: Fd,
///         level: c_int,
///         optname: c_int,
///         #[syscall(ptr(count = optlen))]
///         optval: u8,
///         #[syscall(private)]
///         optlen: c_int,
///     },
/// }
/// ```
///
/// In most cases, you'll want the length field to be private.
///
/// Note that there is a specialisation here: for `u8` arrays, the generated method will return a
/// `Vec<u8>`. Otherwise, the method will return an
/// [`Iterator`](https://doc.rust-lang.org/std/iter/trait.Iterator.html) with the field type as the
/// `Item`.
///
/// ### Unbounded arrays
///
/// Arrays where the length isn't known directly from the syscall arguments can be declared with
/// `#[syscall(ptr(array))]`. These fields get an accessor with an extra parameter, which is the
/// element number. This is not checked in any way.
///
/// # Attribute options
///
/// The top level `syscall` attribute macro accepts one optional argument:
///
/// * `core`: the import path to the `ptrace_iterator::core` (or `ptrace_iterator_core`, if it's
///   being imported directly) crate. Defaults to `::ptrace_iterator::core` if omitted, but can be
///   overridden if the crate is being renamed or imported a different way.
#[proc_macro_error]
#[proc_macro_attribute]
pub fn syscall(
    args: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let args: SyscallArgs = match syn::parse(args) {
        Ok(args) => args,
        Err(e) => return e.to_compile_error().into(),
    };

    let input = parse_macro_input!(input as DeriveInput);
    match syscall_impl(args, input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.write_errors().into(),
    }
}

fn syscall_impl(
    args: SyscallArgs,
    input: DeriveInput,
) -> darling::Result<proc_macro2::TokenStream> {
    let SyscallEnum {
        ident,
        vis,
        data,
        attrs,
    } = SyscallEnum::from_derive_input(&input)?;

    let mut state = State::new(match args.core {
        Some(core) => core,
        None => syn::parse_str("::ptrace_iterator::core").map_err(|e| {
            darling::Error::custom(format!("cannot parse Path from default value: {e}"))
        })?,
    });
    for variant in data
        .take_enum()
        .ok_or_else(|| darling::Error::custom("unexpected non-enum").with_span(&ident))?
        .into_iter()
    {
        state.observe_variant(&vis, variant)?;
    }

    Ok(state.into_token_stream(&ident, &vis, &attrs))
}
