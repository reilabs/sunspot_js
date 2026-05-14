mod error;
mod parsing;
mod pedersen_commitments;
mod solver;
mod types;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(all(target_arch = "wasm32", feature = "bench"))]
pub mod bench;

pub use error::Error;
pub use pedersen_commitments::{BSB22_FOLD_DST, COMMITMENT_DST, FR_BYTES, bsb22_pok, fold};
pub use solver::{SolveError, Solver, solve, verify_witness};
pub use types::{CommitmentInfo, GnarkWitness, PedersenProvingKey, ProvingKey, R1CS, SystemType};
