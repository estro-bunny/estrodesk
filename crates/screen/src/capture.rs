use crate::{FrameError, VideoFrame};
use std::time::Duration;

/// Source-independent contract implemented by platform capture backends.
///
/// A backend should return the newest available frame. Implementations may
/// block while waiting for the next frame, but should avoid accumulating an
/// unbounded queue: remote desktop wants the latest pixels, not stale pixels.
pub trait ScreenCapture {
    fn next_frame(&mut self) -> Result<VideoFrame, CaptureError>;
}

#[derive(Debug)]
pub enum CaptureError {
    Unsupported,
    Frame(FrameError),
    Backend(String),
}

impl From<FrameError> for CaptureError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

/// Small deterministic source useful for protocol and pipeline tests before
/// platform-specific capture APIs are wired in.
pub struct TestCapture {
    width: u32,
    height: u32,
    timestamp: Duration,
}

impl TestCapture {
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            timestamp: Duration::ZERO,
        }
    }
}

impl ScreenCapture for TestCapture {
    fn next_frame(&mut self) -> Result<VideoFrame, CaptureError> {
        let size = crate::FrameSize {
            width: self.width,
            height: self.height,
        };
        let data = vec![0; usize::try_from(size.pixel_count() * 4).unwrap_or(0)];
        let frame = VideoFrame::new(
            size,
            crate::PixelFormat::Bgra8,
            self.timestamp,
            data,
        )?;
        self.timestamp += Duration::from_millis(16);
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_produces_monotonic_frames() {
        let mut capture = TestCapture::new(2, 2);
        let first = capture.next_frame().unwrap();
        let second = capture.next_frame().unwrap();
        assert!(second.timestamp > first.timestamp);
        assert_eq!(second.data.len(), 16);
    }
}
