use std::ffi::c_void;

use nix::{
    libc,
    sys::socket::{SockaddrLike, SockaddrStorage},
    unistd::Pid,
};

use crate::{Error, Opaque};

/// A wrapper for the `msghdr` type used in various Linux syscalls.
pub struct Msghdr(libc::msghdr);

impl Msghdr {
    /// Returns the contents of the `msg_control` field within the struct.
    ///
    /// Note that a `NULL` `msg_control` pointer or a zero `msg_controllen` will return a boxed
    /// empty slice, rather than an error.
    ///
    /// # Safety
    ///
    /// Requires a valid `msghdr` with a `msg_control` field that points to a mapped location in
    /// the tracee's memory space, and a `msg_controllen` of the correct size.
    pub unsafe fn control(&self, pid: Pid) -> Result<Box<[u8]>, Error> {
        let addr = Opaque::from(self.0.msg_control);
        if addr.is_null() || self.0.msg_controllen == 0 {
            Ok(Box::new([]))
        } else {
            unsafe { crate::read(pid, addr, self.0.msg_controllen) }
        }
    }

    /// Iterates over the `iovec` elements within the struct.
    ///
    /// # Safety
    ///
    /// Requires a valid `msghdr` with a `msg_iov` that points to a mapped location in the tracee's
    /// memory space, and a `msg_iovlen` of the correct size.
    pub unsafe fn iter_iovecs(
        &self,
        pid: Pid,
    ) -> Box<dyn Iterator<Item = Result<Box<[u8]>, Error>>> {
        if !self.0.msg_iov.is_null() && self.0.msg_iovlen > 0 {
            Box::new(unsafe { iter_iovecs(pid, self.0.msg_iov, self.0.msg_iovlen) })
        } else {
            Box::new(std::iter::empty())
        }
    }

    /// Returns the number of `iovec` elements in the struct.
    pub fn iovec_len(&self) -> usize {
        self.0.msg_iovlen
    }

    /// Returns the `msg_name` field within the struct, which usually corresponds to the target
    /// address.
    ///
    /// # Safety
    ///
    /// Requires a valid `msghdr` with a `msg_name` that points to a mapped location in the
    /// tracee's memory space, and a `msg_namelen` of the correct size.
    pub unsafe fn name(&self, pid: Pid) -> Result<Option<SockaddrStorage>, Error> {
        if !self.0.msg_name.is_null() && self.0.msg_namelen > 0 {
            let msg =
                unsafe { crate::read(pid, self.0.msg_name.into(), self.0.msg_namelen as usize) }?;

            Ok(unsafe {
                SockaddrStorage::from_raw(
                    msg.as_ptr() as *const libc::sockaddr,
                    Some(self.0.msg_namelen as libc::socklen_t),
                )
            })
        } else {
            Ok(None)
        }
    }
}

impl From<libc::msghdr> for Msghdr {
    fn from(value: libc::msghdr) -> Self {
        Self(value)
    }
}

impl From<linux_raw_sys::net::msghdr> for Msghdr {
    fn from(value: linux_raw_sys::net::msghdr) -> Self {
        // The `linux_raw_sys` version of this type represents the same C struct — and therefore
        // memory layout — as the `nix` version. We prefer `nix` here because its definition of
        // `iovec` is more correct than `linux_raw_sys`.
        #[allow(clippy::missing_transmute_annotations)]
        Self(unsafe { std::mem::transmute(value) })
    }
}

/// Iterates over an array of `iovec` elements read from the tracee's memory space.
///
/// # Safety
///
/// `ptr` needs to point to an array of size `len`. Each pointer needs to be a valid address within
/// the tracee's memory space.
pub unsafe fn iter_iovecs(
    pid: Pid,
    ptr: impl Iovec,
    len: usize,
) -> impl Iterator<Item = Result<Box<[u8]>, Error>> {
    (0..len).map(move |i| unsafe {
        let iovec = ptr.add(i);
        crate::read(pid, iovec.base().into(), iovec.len())
    })
}

/// A trait to shim the differences between [`nix`] and [`linux_raw_sys`].
#[allow(clippy::len_without_is_empty)]
pub trait Iovec: Sized {
    fn add(&self, count: usize) -> Self;
    fn base(&self) -> *const c_void;
    fn len(&self) -> usize;
}

macro_rules! impl_iovec_for_ptr {
    ($ty:ty) => {
        impl Iovec for $ty {
            fn add(&self, count: usize) -> Self {
                unsafe { (*self).add(count) }
            }

            fn base(&self) -> *const c_void {
                unsafe { (**self).iov_base }
            }

            fn len(&self) -> usize {
                unsafe { (**self).iov_len as usize }
            }
        }
    };
}

impl_iovec_for_ptr!(*const libc::iovec);
impl_iovec_for_ptr!(*mut libc::iovec);
impl_iovec_for_ptr!(*const linux_raw_sys::general::iovec);
impl_iovec_for_ptr!(*mut linux_raw_sys::general::iovec);
