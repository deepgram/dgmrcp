/// Error type for all error produced by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to create the engine.
    #[error("Initialization")]
    Initialization,

    // #[error("Request failed: {0}")]
    // Request(#[from] reqwest::Error),

    #[error("Bad URL: {0}")]
    BadUrl(#[from] url::ParseError),
}
