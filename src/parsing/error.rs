use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("acir: {0}")]
    Acir(String),

    #[error("witness: {0}")]
    Witness(String),

    #[error("proving key: {0}")]
    ProvingKey(String),

    #[error("ccs: {0}")]
    Ccs(String),
}
