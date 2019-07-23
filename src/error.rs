use std::error::Error as StdError;
use std::fmt;

/// Error type for all error produced by this crate.
#[derive(Debug)]
pub enum Error {
    /// Failed to create the engine.
    Initialization,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl StdError for Error {}
