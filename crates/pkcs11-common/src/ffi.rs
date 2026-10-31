/*
 * Copyright 2026 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Conversions between caller-supplied PKCS#11 pointer/length pairs and Rust
//! slices.
//!
//! These helpers reject null pointers with non-zero lengths and lengths that
//! cannot describe a Rust slice. They cannot prove that a non-null pointer
//! refers to live memory; that remains the caller's obligation under each
//! function's `# Safety` contract.

use pkcs11_sys::*;
use std::marker::PhantomData;

fn slice_len<T>(len: CK_ULONG) -> Result<usize, CK_RV> {
    let len = usize::try_from(len).map_err(|_| CK_RV::from(CKR_ARGUMENTS_BAD))?;
    match len.checked_mul(size_of::<T>()) {
        Some(bytes) if bytes <= isize::MAX as usize => Ok(len),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

/// Borrows `len` elements at `ptr`. An empty slice is returned when `len` is
/// zero; a null `ptr` with a non-zero `len` yields `CKR_ARGUMENTS_BAD`.
///
/// # Safety
///
/// When `len` is non-zero and `ptr` is non-null, `ptr` must be properly
/// aligned and valid for reads of `len` initialized elements of `T`, and the
/// memory must not be written to while the returned slice is in use.
pub unsafe fn in_slice<'a, T>(ptr: *const T, len: CK_ULONG) -> Result<&'a [T], CK_RV> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let len = slice_len::<T>(len)?;
    // SAFETY: non-null, length bounded by `slice_len`; validity, alignment
    // and immutability are the caller's contract.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Like [`in_slice`], but treats a null `ptr` as an empty input regardless of
/// `len`, for optional parameters such as PINs and attribute values.
///
/// # Safety
///
/// Same as [`in_slice`].
pub unsafe fn in_slice_or_empty<'a, T>(ptr: *const T, len: CK_ULONG) -> Result<&'a [T], CK_RV> {
    if ptr.is_null() {
        return Ok(&[]);
    }
    unsafe { in_slice(ptr, len) }
}

/// Mutably borrows `len` caller-initialized elements at `ptr`, such as a
/// `CK_ATTRIBUTE` template the engine fills in. Null handling is as for
/// [`in_slice`].
///
/// # Safety
///
/// When `len` is non-zero and `ptr` is non-null, `ptr` must be properly
/// aligned and valid for reads and writes of `len` initialized elements of
/// `T`, and must not be accessed through any other pointer while the returned
/// slice is in use.
pub unsafe fn inout_slice<'a, T>(ptr: *mut T, len: CK_ULONG) -> Result<&'a mut [T], CK_RV> {
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let len = slice_len::<T>(len)?;
    // SAFETY: as for `in_slice`, plus exclusive access per the contract.
    Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

/// Zero-fills and mutably borrows `len` bytes of caller-owned output memory,
/// so that a backend never observes uninitialized bytes.
///
/// # Safety
///
/// When `len` is non-zero, `ptr` must be valid for writes of `len` bytes and
/// must not be accessed through any other pointer while the returned slice is
/// in use.
pub unsafe fn out_bytes_zeroed<'a>(ptr: *mut u8, len: CK_ULONG) -> Result<&'a mut [u8], CK_RV> {
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let len = slice_len::<u8>(len)?;
    // SAFETY: the caller guarantees `len` writable bytes; zeroing them first
    // makes the slice fully initialized.
    unsafe {
        std::ptr::write_bytes(ptr, 0, len);
        Ok(std::slice::from_raw_parts_mut(ptr, len))
    }
}

/// A caller-supplied output buffer following the PKCS#11 length convention: a
/// null buffer asks for the required length, an undersized buffer yields
/// `CKR_BUFFER_TOO_SMALL`, and the length pointer always receives the
/// required or written element count.
///
/// [`OutBuf::write`] checks the actual data length against the capacity, so a
/// result longer than an earlier estimate can never overflow the buffer.
pub struct OutBuf<'a, T> {
    ptr: *mut T,
    len: *mut CK_ULONG,
    _marker: PhantomData<&'a mut [T]>,
}

impl<T: Copy> OutBuf<'_, T> {
    /// Returns `CKR_ARGUMENTS_BAD` when `len` is null.
    ///
    /// # Safety
    ///
    /// A non-null `len` must be valid for reads and writes of one `CK_ULONG`.
    /// A non-null `ptr` must be properly aligned and valid for writes of
    /// `*len` elements of `T`, and must not overlap `*len` or be accessed
    /// through any other reference while [`OutBuf::write`] runs. Both must
    /// remain valid for the lifetime of the `OutBuf`.
    pub unsafe fn new(ptr: *mut T, len: *mut CK_ULONG) -> Result<Self, CK_RV> {
        if len.is_null() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        Ok(Self {
            ptr,
            len,
            _marker: PhantomData,
        })
    }

    /// Whether the caller only asked for the required length.
    pub fn is_query(&self) -> bool {
        self.ptr.is_null()
    }

    fn set_len(&mut self, n: usize) {
        let n = CK_ULONG::try_from(n).unwrap_or(CK_ULONG::MAX);
        // SAFETY: `len` is non-null and writable per `new`'s contract.
        unsafe { self.len.write(n) }
    }

    /// Reports `needed` and settles the call early when it cannot produce
    /// output: `Some(CKR_OK)` for a length query, `Some(CKR_BUFFER_TOO_SMALL)`
    /// for an undersized buffer, and `None` when `needed` elements fit.
    pub fn check(&mut self, needed: usize) -> Option<CK_RV> {
        if self.is_query() {
            self.set_len(needed);
            return Some(CKR_OK.into());
        }
        // SAFETY: `len` is non-null and readable per `new`'s contract.
        let capacity = unsafe { self.len.read() };
        if usize::try_from(capacity).unwrap_or(usize::MAX) < needed {
            self.set_len(needed);
            return Some(CKR_BUFFER_TOO_SMALL.into());
        }
        None
    }

    /// Copies `data` into the buffer, or reports its length as [`check`]
    /// does when the buffer is absent or too small.
    ///
    /// [`check`]: OutBuf::check
    pub fn write(mut self, data: &[T]) -> CK_RV {
        if let Some(rv) = self.check(data.len()) {
            return rv;
        }
        // SAFETY: `check` established that `ptr` is non-null with capacity
        // for `data.len()` elements; `data` is Rust-owned and cannot overlap
        // caller memory that `new`'s contract reserves for this buffer.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr, data.len()) };
        self.set_len(data.len());
        CKR_OK.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rv(v: u32) -> CK_RV {
        v.into()
    }

    #[test]
    fn in_slice_rejects_null_with_length() {
        let r = unsafe { in_slice::<u8>(std::ptr::null(), 4) };
        assert_eq!(r.unwrap_err(), rv(CKR_ARGUMENTS_BAD));
        assert!(
            unsafe { in_slice::<u8>(std::ptr::null(), 0) }
                .unwrap()
                .is_empty()
        );
        assert!(
            unsafe { in_slice_or_empty::<u8>(std::ptr::null(), 4) }
                .unwrap()
                .is_empty()
        );
    }

    // A 32-bit CK_ULONG cannot express a length exceeding isize::MAX bytes on
    // 64-bit Windows.
    #[cfg(not(windows))]
    #[test]
    fn in_slice_rejects_oversized_length() {
        let data = [0u64; 1];
        let huge = CK_ULONG::MAX;
        let r = unsafe { in_slice(data.as_ptr(), huge) };
        assert_eq!(r.unwrap_err(), rv(CKR_ARGUMENTS_BAD));
    }

    #[test]
    fn out_buf_length_query() {
        let mut len: CK_ULONG = 0;
        let out = unsafe { OutBuf::<u8>::new(std::ptr::null_mut(), &mut len) }.unwrap();
        assert_eq!(out.write(&[1, 2, 3]), rv(CKR_OK));
        assert_eq!(len, 3);
    }

    #[test]
    fn out_buf_requires_length_pointer() {
        let mut buf = [0u8; 4];
        let r = unsafe { OutBuf::new(buf.as_mut_ptr(), std::ptr::null_mut()) };
        assert_eq!(r.err(), Some(rv(CKR_ARGUMENTS_BAD)));
    }

    #[test]
    fn out_buf_writes_and_reports_actual_length() {
        let mut buf = [0u8; 4];
        let mut len = buf.len() as CK_ULONG;
        let mut out = unsafe { OutBuf::new(buf.as_mut_ptr(), &mut len) }.unwrap();
        assert_eq!(out.check(4), None);
        assert_eq!(out.write(&[7, 8]), rv(CKR_OK));
        assert_eq!(len, 2);
        assert_eq!(buf, [7, 8, 0, 0]);
    }

    #[test]
    fn out_buf_write_rechecks_capacity_after_estimate() {
        let mut buf = [0u8; 4];
        let mut len: CK_ULONG = 2;
        let mut out = unsafe { OutBuf::new(buf.as_mut_ptr(), &mut len) }.unwrap();
        // The estimate fits, but the produced result does not.
        assert_eq!(out.check(2), None);
        assert_eq!(out.write(&[1, 2, 3]), rv(CKR_BUFFER_TOO_SMALL));
        assert_eq!(len, 3);
        assert_eq!(buf, [0; 4]);
    }
}
