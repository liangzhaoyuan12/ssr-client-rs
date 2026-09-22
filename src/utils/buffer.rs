use bytes::{Buf, BufMut, Bytes, BytesMut};

/// A simple buffer wrapper around BytesMut for SSR protocol operations
#[derive(Debug, Clone)]
pub struct SsrBuffer {
    inner: BytesMut,
}

impl SsrBuffer {
    /// Create a new buffer with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: BytesMut::with_capacity(capacity),
        }
    }

    /// Create a buffer from existing data
    pub fn from_data(data: &[u8]) -> Self {
        Self {
            inner: BytesMut::from(data),
        }
    }

    /// Get the current length
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.inner.len()
    }

    /// Get the data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Advance the read position
    pub fn advance(&mut self, cnt: usize) {
        self.inner.advance(cnt);
    }

    /// Put a byte
    pub fn put_u8(&mut self, val: u8) {
        self.inner.put_u8(val);
    }

    /// Put bytes
    pub fn put_slice(&mut self, data: &[u8]) {
        self.inner.put_slice(data);
    }

    /// Put a u16 big-endian
    pub fn put_u16_be(&mut self, val: u16) {
        self.inner.put_u16(val);
    }

    /// Take all data as BytesMut and leave buffer empty
    pub fn take(&mut self) -> BytesMut {
        self.inner.split_to(self.inner.len())
    }

    /// Get a chunk of data without advancing
    pub fn chunk(&self, len: usize) -> &[u8] {
        let end = len.min(self.inner.len());
        &self.inner[..end]
    }

    /// Read a u8
    pub fn get_u8(&mut self) -> Option<u8> {
        if self.inner.has_remaining() {
            Some(self.inner.get_u8())
        } else {
            None
        }
    }

    /// Read a u16 big-endian
    pub fn get_u16_be(&mut self) -> Option<u16> {
        if self.inner.remaining() >= 2 {
            Some(self.inner.get_u16())
        } else {
            None
        }
    }

    /// Read n bytes
    pub fn get_bytes(&mut self, n: usize) -> Option<BytesMut> {
        if self.inner.remaining() >= n {
            Some(self.inner.split_to(n))
        } else {
            None
        }
    }

    /// Extend with data
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.inner.extend_from_slice(data);
    }

    /// Extend from another buffer
    pub fn extend_from_buf(&mut self, other: &mut BytesMut) {
        self.inner.extend_from_slice(other);
    }

    /// Freeze into Bytes
    pub fn freeze(self) -> Bytes {
        self.inner.freeze()
    }

    /// Get inner BytesMut
    pub fn into_inner(self) -> BytesMut {
        self.inner
    }
}

impl From<BytesMut> for SsrBuffer {
    fn from(inner: BytesMut) -> Self {
        Self { inner }
    }
}

impl From<Vec<u8>> for SsrBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self {
            inner: BytesMut::from(&data[..]),
        }
    }
}

impl From<&[u8]> for SsrBuffer {
    fn from(data: &[u8]) -> Self {
        Self {
            inner: BytesMut::from(data),
        }
    }
}

impl AsRef<[u8]> for SsrBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}
