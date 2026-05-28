use thiserror::Error;

use crate::parsing::ParseError;
use crate::pedersen_commitments::PedersenError;
use crate::prover::ProveError;
use crate::solver::SolveError;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error(transparent)]
    Solve(#[from] SolveError),

    #[error(transparent)]
    Pedersen(#[from] PedersenError),

    #[error(transparent)]
    Prove(#[from] ProveError),
}
