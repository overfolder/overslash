use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid url: {0}")]
    Url(#[from] url::ParseError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("server returned status {status}: {body}")]
    Status { status: u16, body: String },

    #[error("missing or malformed Mcp-Session-Id header on initialize response")]
    MissingSessionId,

    #[error("not initialized — call connect() first")]
    NotInitialized,

    #[error("unexpected response shape: {0}")]
    UnexpectedResponse(String),

    #[error("sse stream ended before final response event arrived")]
    PrematureStreamEnd,

    #[error("sse parse: {0}")]
    SseParse(String),

    #[error("session has no parked call with token {0}")]
    UnknownCallToken(String),

    #[error("call token already resumed")]
    CallTokenConsumed,
}
