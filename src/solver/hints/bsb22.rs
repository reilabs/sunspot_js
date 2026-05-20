//! `frontend/cs/r1cs.Bsb22CommitmentComputePlaceholder` is a placeholder in
//! the R1CS that gets overridden at prove time by
//! `backend/groth16/bn254.Prove.func1`. Mirrors the override:
//!
//! 1. Pedersen-commit the private-committed wire values with the i-th
//!    commitment key.
//! 2. Serialize: 64-byte uncompressed G1 marshal ‖ each
//!    public-and-commitment-committed value as 32-byte big-endian.
//! 3. Hash to a single Fr via `fr.Hash(serialized, "bsb22-commitment", 1)`.
//!
//! Calldata inputs:
//!   [0]        commitment_depth (u64, the index `i`)
//!   [1..1+k]   k = len(commitment_info[i].public_and_commitment_committed)
//!   [1+k..]    the private-committed values

use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::{fr_to_u64, read_input};
use crate::pedersen_commitments::{COMMITMENT_DST, FR_BYTES, hash_to_fr};
use crate::solver::InstrOutput;
use crate::types::CommitmentInfo;

const NAME: &str = "Bsb22CommitmentComputePlaceholder";

/// gnark G1Affine uncompressed marshal length.
const G1_AFFINE_UNCOMPRESSED_BYTES: usize = 64;

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<InstrOutput, SolveError> {
    let nb_inputs = cursor.read_u32()? as usize;
    if nb_inputs < 1 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 1,
            actual: nb_inputs as u32,
        }
        .into());
    }

    let commitment_idx = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;

    let CommitmentInfo::Groth16(commitments) = &solver.r1cs.body.commitment_info else {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 0, // sentinel: wrong commitment system
            actual: 0,
        }
        .into());
    };
    let commitment = commitments.get(commitment_idx).ok_or({
        HintError::HintCommitmentIndexOutOfRange {
            hint_name: NAME,
            index: commitment_idx,
            total: commitments.len(),
        }
    })?;

    let k = commitment.public_and_commitment_committed.len();
    if nb_inputs < 1 + k {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: (1 + k) as u32,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let nb_private = nb_inputs - 1 - k;

    let mut hashed = Vec::with_capacity(k);
    for _ in 0..k {
        hashed.push(read_input(cursor, solver)?);
    }
    let mut committed = Vec::with_capacity(nb_private);
    for _ in 0..nb_private {
        committed.push(read_input(cursor, solver)?);
    }

    let (start, end) = cursor.read_pair()?;
    if end - start != 1 {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: 1,
            actual: end - start,
        }
        .into());
    }

    let pk = solver
        .pk
        .ok_or(HintError::HintMissingProvingKey { hint_name: NAME })?;
    let ck = pk
        .get(commitment_idx)
        .ok_or(HintError::HintCommitmentIndexOutOfRange {
            hint_name: NAME,
            index: commitment_idx,
            total: pk.len(),
        })?;
    let commitment_point =
        ck.commit(&committed)
            .map_err(|source| HintError::HintPedersenCommit {
                hint_name: NAME,
                source,
            })?;

    let mut prehash = Vec::with_capacity(G1_AFFINE_UNCOMPRESSED_BYTES + k * FR_BYTES);
    prehash.extend_from_slice(&g1_marshal(&commitment_point));
    for h in &hashed {
        prehash.extend_from_slice(&fr_to_be_bytes(h));
    }

    let challenge =
        hash_to_fr(&prehash, COMMITMENT_DST).map_err(|source| HintError::HintPedersenCommit {
            hint_name: NAME,
            source,
        })?;

    Ok(InstrOutput::Bsb22 {
        write: (start, challenge),
        commitment_idx,
        point: commitment_point,
        committed_values: committed,
    })
}

/// gnark-crypto BN254 `G1Affine.Marshal()` — uncompressed, 64 bytes:
/// `[X big-endian || Y big-endian]`. Infinity (0,0) marshals to all zeros.
/// The top 2 bits of byte 0 are the metadata mask; for uncompressed they are
/// zero, so X big-endian works as-is (BN254's modulus fits in 254 bits).
fn g1_marshal(p: &ark_bn254::G1Affine) -> [u8; G1_AFFINE_UNCOMPRESSED_BYTES] {
    let mut out = [0u8; G1_AFFINE_UNCOMPRESSED_BYTES];
    if p.is_zero() {
        return out;
    }
    let (x, y) = p.xy().expect("non-infinity point has affine coordinates");
    out[..32].copy_from_slice(&fq_to_be_bytes(&x));
    out[32..].copy_from_slice(&fq_to_be_bytes(&y));
    out
}

fn fq_to_be_bytes(x: &ark_bn254::Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.into_bigint().to_bytes_be();
    // BN254 Fq is 254 bits → fits in 32 bytes; to_bytes_be returns the
    // minimum width 32-byte representation.
    out.copy_from_slice(&bytes);
    out
}

fn fr_to_be_bytes(x: &Fr) -> [u8; FR_BYTES] {
    let mut out = [0u8; FR_BYTES];
    let bytes = x.into_bigint().to_bytes_be();
    out.copy_from_slice(&bytes);
    out
}
