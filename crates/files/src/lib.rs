//! File transfer primitives will live here.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileChunk {
    pub offset: u64,
    pub length: u32,
}
