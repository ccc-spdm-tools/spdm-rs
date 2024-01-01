// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use bytes::{buf::IntoIter, Buf, BufMut, Bytes, BytesMut};
use core::{
    borrow::{Borrow, BorrowMut},
    cmp, hash,
    iter::FromIterator,
    ops::{Deref, DerefMut},
};
use zeroize::Zeroize;

#[derive(Default)]
pub struct BytesMutStrubbed {
    bytes_mut: BytesMut,
}

impl BytesMutStrubbed {
    #[inline]
    pub fn with_capacity(capacity: usize) -> BytesMutStrubbed {
        BytesMutStrubbed {
            bytes_mut: BytesMut::with_capacity(capacity),
        }
    }

    #[inline]
    pub fn new() -> BytesMutStrubbed {
        BytesMutStrubbed {
            bytes_mut: BytesMut::new(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes_mut.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes_mut.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.bytes_mut.capacity()
    }

    pub fn extend_from_slice(&mut self, extend: &[u8]) {
        self.bytes_mut.extend_from_slice(extend)
    }

    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.bytes_mut.reserve(additional)
    }

    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.bytes_mut.resize(new_len, value)
    }

    pub fn clear(&mut self) {
        self.bytes_mut.clear()
    }

    pub fn truncate(&mut self, len: usize) {
        self.bytes_mut.truncate(len)
    }

    pub fn zeroed(len: usize) -> BytesMutStrubbed {
        BytesMutStrubbed {
            bytes_mut: BytesMut::zeroed(len),
        }
    }

    pub fn put_u8(&mut self, n: u8) {
        self.bytes_mut.put_u8(n)
    }
}

impl Drop for BytesMutStrubbed {
    fn drop(&mut self) {
        self.bytes_mut[..].zeroize()
    }
}

impl Buf for BytesMutStrubbed {
    #[inline]
    fn remaining(&self) -> usize {
        self.bytes_mut.remaining()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.bytes_mut.chunk()
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        self.bytes_mut.advance(cnt)
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        self.bytes_mut.copy_to_bytes(len)
    }
}

impl AsRef<[u8]> for BytesMutStrubbed {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes_mut.as_ref()
    }
}

impl Deref for BytesMutStrubbed {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.bytes_mut.deref()
    }
}

impl AsMut<[u8]> for BytesMutStrubbed {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.bytes_mut.as_mut()
    }
}

impl DerefMut for BytesMutStrubbed {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.bytes_mut.deref_mut()
    }
}

impl<'a> From<&'a [u8]> for BytesMutStrubbed {
    fn from(src: &'a [u8]) -> BytesMutStrubbed {
        BytesMutStrubbed {
            bytes_mut: BytesMut::from(src),
        }
    }
}

impl<'a> From<&'a str> for BytesMutStrubbed {
    fn from(src: &'a str) -> BytesMutStrubbed {
        BytesMutStrubbed {
            bytes_mut: BytesMut::from(src),
        }
    }
}

impl PartialEq for BytesMutStrubbed {
    fn eq(&self, other: &BytesMutStrubbed) -> bool {
        self.bytes_mut.eq(&other.bytes_mut)
    }
}

impl PartialOrd for BytesMutStrubbed {
    fn partial_cmp(&self, other: &BytesMutStrubbed) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BytesMutStrubbed {
    fn cmp(&self, other: &BytesMutStrubbed) -> cmp::Ordering {
        self.bytes_mut.cmp(&other.bytes_mut)
    }
}

impl Eq for BytesMutStrubbed {}

impl hash::Hash for BytesMutStrubbed {
    fn hash<H>(&self, state: &mut H)
    where
        H: hash::Hasher,
    {
        self.bytes_mut.hash(state)
    }
}

impl Borrow<[u8]> for BytesMutStrubbed {
    fn borrow(&self) -> &[u8] {
        self.bytes_mut.borrow()
    }
}

impl BorrowMut<[u8]> for BytesMutStrubbed {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.bytes_mut.borrow_mut()
    }
}

impl Clone for BytesMutStrubbed {
    fn clone(&self) -> BytesMutStrubbed {
        BytesMutStrubbed {
            bytes_mut: self.bytes_mut.clone(),
        }
    }
}

impl IntoIterator for BytesMutStrubbed {
    type Item = u8;
    type IntoIter = IntoIter<BytesMutStrubbed>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter::new(self)
    }
}

impl<'a> IntoIterator for &'a BytesMutStrubbed {
    type Item = &'a u8;
    type IntoIter = core::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_ref().iter()
    }
}

impl Extend<u8> for BytesMutStrubbed {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = u8>,
    {
        self.bytes_mut.extend(iter)
    }
}

impl<'a> Extend<&'a u8> for BytesMutStrubbed {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = &'a u8>,
    {
        self.bytes_mut.extend(iter)
    }
}

impl Extend<Bytes> for BytesMutStrubbed {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = Bytes>,
    {
        self.bytes_mut.extend(iter)
    }
}

impl FromIterator<u8> for BytesMutStrubbed {
    fn from_iter<T: IntoIterator<Item = u8>>(into_iter: T) -> Self {
        BytesMutStrubbed {
            bytes_mut: BytesMut::from_iter(into_iter),
        }
    }
}

impl<'a> FromIterator<&'a u8> for BytesMutStrubbed {
    fn from_iter<T: IntoIterator<Item = &'a u8>>(into_iter: T) -> Self {
        BytesMutStrubbed {
            bytes_mut: BytesMut::from_iter(into_iter),
        }
    }
}
