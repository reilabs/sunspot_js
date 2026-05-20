use thiserror::Error;

use crate::pedersen_commitments::PedersenError;

#[derive(Debug, Error)]
pub enum ProveError {
    #[error("witness has {actual} entries, expected {expected} (matching pk.nb_wires)")]
    WitnessLengthMismatch { actual: usize, expected: usize },

    #[error("failed to construct coset evaluation domain")]
    CosetDomain,

    #[error("Z(coset) is zero — cannot invert")]
    ZeroCosetZ,

    #[error("MSM {label}: bases/scalars length mismatch ({len})")]
    MsmLengthMismatch { label: &'static str, len: usize },

    #[error("private wire count mismatch: got {actual}, expected {expected}")]
    PrivateWireCountMismatch { actual: usize, expected: usize },

    #[error("wrong commitment system: expected Groth16, got Plonk")]
    UnexpectedPlonkCommitments,

    #[error("commitment_keys mismatch: PK has {pk}, R1CS declares {r1cs}")]
    CommitmentKeysMismatch { pk: usize, r1cs: usize },

    #[error(transparent)]
    Pedersen(#[from] PedersenError),
}

impl ProveError {
    pub(super) fn msm(label: &'static str) -> impl Fn(usize) -> Self {
        move |len| ProveError::MsmLengthMismatch { label, len }
    }
}
