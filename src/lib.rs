#![feature(const_trait_impl)]
pub mod curve;
mod error;
mod parsing;
mod pedersen_commitments;
mod prover;
mod solver;
mod types;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(all(target_arch = "wasm32", feature = "bench"))]
pub mod bench;

pub use error::Error;
pub use pedersen_commitments::{BSB22_FOLD_DST, COMMITMENT_DST, FR_BYTES, bsb22_pok, fold};
pub use prover::{ProveError, prove};
pub use solver::{SolveOutput, Solver, solve, verify_witness};
pub use types::{
    CommitmentInfo, GnarkWitness, PedersenProvingKey, Proof, ProvingKey, R1CS, SystemType,
};
