//! Cross-platform screen capture primitives for EstroDesk.
//!
//! Platform backends should produce [`VideoFrame`] values. The transport and
//! encoder layers can then consume the same representation on Windows and
//! Linux without knowing anything about the capture API.

mod capture;

pub use capture::{CaptureError, ScreenCapture, TestCapture};

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSize {
    pub width: u32,
    pub height: u32,
}

impl FrameSize {
    pub fn pixel_count(self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Rgba8,
    Bgra8,
}

impl PixelFormat {
    pub const fn bytes_per_pixel(self) -> usize {
        4
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    pub size: FrameSize,
    pub format: PixelFormat,
    pub timestamp: Duration,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    InvalidDimensions,
    InvalidBufferLength { expected: usize, actual: usize },
}

impl VideoFrame {
    pub fn new(
        size: FrameSize,
        format: PixelFormat,
        timestamp: Duration,
        data: Vec<u8>,
    ) -> Result<Self, FrameError> {
        if size.width == 0 || size.height == 0 {
            return Err(FrameError::InvalidDimensions);
        }

        let expected = size
            .pixel_count()
            .checked_mul(format.bytes_per_pixel() as u64)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(FrameError::InvalidDimensions)?;

        if data.len() != expected {
            return Err(FrameError::InvalidBufferLength {
                expected,
                actual: data.len(),
            });
        }

        Ok(Self {
            size,
            format,
            timestamp,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_rgba_frame() {
        let frame = VideoFrame::new(
            FrameSize { width: 2, height: 3 },
            PixelFormat::Rgba8,
            Duration::from_millis(16),
            vec![0; 24],
        )
        .unwrap();

        assert_eq!(frame.size.pixel_count(), 6);
    }

    #[test]
    fn rejects_wrong_buffer_length() {
        let error = VideoFrame::new(
            FrameSize { width: 2, height: 2 },
            PixelFormat::Bgra8,
            Duration::ZERO,
            vec![0; 3],
        )
        .unwrap_err();

        assert_eq!(
            error,
            FrameError::InvalidBufferLength {
                expected: 16,
                actual: 3,
            }
        );
    }

    #[test]
    fn rejects_zero_dimensions() {
        assert_eq!(
            VideoFrame::new(
                FrameSize { width: 0, height: 1080 },
                PixelFormat::Rgba8,
                Duration::ZERO,
                Vec::new(),
            )
            .unwrap_err(),
            FrameError::InvalidDimensions
        );
    }
}
