//! Engine error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("collector '{0}' failed: {1}")]
    Collector(String, String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unsupported platform for this collector")]
    UnsupportedPlatform,
}
