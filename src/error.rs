use thiserror::Error;

use crate::parsing::ParseError;
use crate::pedersen_commitments::PedersenError;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error(transparent)]
    Pedersen(#[from] PedersenError),
}
