//! SentinelAI security engine — collectors, orchestration, hashing.
//!
//! All functionality is defensive and runs with the privileges of the
//! calling process. Privileged operations (if added later) must be isolated.

pub mod collectors;
pub mod engine;
pub mod error;
pub mod hash;
pub mod inventory;

pub use engine::{ScanEngine, ScanOptions};
pub use error::EngineError;
