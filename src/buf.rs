//! Growable byte buffer — heapless by default, heap-backed with `alloc` feature.
//!
//! `Buf<N>` is the canonical buffer type for I/O buffers in milli-http.
//! Without the `alloc` feature, it is backed by `heapless::Vec<u8, N>` (inline storage).
//! With `alloc`, it is backed by `alloc::vec::Vec<u8>` (heap storage, N ignored).

#[cfg(not(feature = "alloc"))]
pub type Buf<const N: usize> = heapless::Vec<u8, N>;

#[cfg(feature = "alloc")]
pub type Buf<const N: usize> = alloc::vec::Vec<u8>;

/// Common operations on byte buffers, abstracting over heapless and alloc backends.
pub trait BufExt {
    fn buf_len(&self) -> usize;
    fn buf_is_empty(&self) -> bool { self.buf_len() == 0 }
    fn buf_clear(&mut self);
    fn buf_truncate(&mut self, len: usize);
    fn buf_extend_from_slice(&mut self, data: &[u8]) -> Result<(), crate::error::Error>;
    fn buf_push(&mut self, byte: u8) -> Result<(), crate::error::Error>;
    fn buf_as_slice(&self) -> &[u8];
    fn buf_as_mut_slice(&mut self) -> &mut [u8];
    /// Drain `n` bytes from the front by shifting remaining data forward.
    fn buf_drain_front(&mut self, n: usize);
}

impl<const N: usize> BufExt for heapless::Vec<u8, N> {
    fn buf_len(&self) -> usize { self.len() }
    fn buf_clear(&mut self) { self.clear(); }
    fn buf_truncate(&mut self, len: usize) { self.truncate(len); }
    fn buf_extend_from_slice(&mut self, data: &[u8]) -> Result<(), crate::error::Error> {
        self.extend_from_slice(data).map_err(|_| crate::error::Error::BufferTooSmall {
            needed: self.len() + data.len(),
        })
    }
    fn buf_push(&mut self, byte: u8) -> Result<(), crate::error::Error> {
        self.push(byte).map_err(|_| crate::error::Error::BufferTooSmall {
            needed: self.len() + 1,
        })
    }
    fn buf_as_slice(&self) -> &[u8] { self }
    fn buf_as_mut_slice(&mut self) -> &mut [u8] { self }
    fn buf_drain_front(&mut self, n: usize) {
        self.copy_within(n.., 0);
        self.truncate(self.len() - n);
    }
}

#[cfg(feature = "alloc")]
impl BufExt for alloc::vec::Vec<u8> {
    fn buf_len(&self) -> usize { self.len() }
    fn buf_clear(&mut self) { self.clear(); }
    fn buf_truncate(&mut self, len: usize) { self.truncate(len); }
    fn buf_extend_from_slice(&mut self, data: &[u8]) -> Result<(), crate::error::Error> {
        self.extend_from_slice(data);
        Ok(())
    }
    fn buf_push(&mut self, byte: u8) -> Result<(), crate::error::Error> {
        self.push(byte);
        Ok(())
    }
    fn buf_as_slice(&self) -> &[u8] { self }
    fn buf_as_mut_slice(&mut self) -> &mut [u8] { self }
    fn buf_drain_front(&mut self, n: usize) {
        self.copy_within(n.., 0);
        self.truncate(self.len() - n);
    }
}
