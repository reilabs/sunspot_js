//! Pedersen vector commitments.
//!
//! The commitment is `C = Σ vᵢ · basis[i]`
//! and the proof of knowledge is `PoK = Σ vᵢ · basis_exp_sigma[i]`, where
//! `basis_exp_sigma[i] = basis[i] · σ` for the trusted-setup secret σ.

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, Zero};
use thiserror::Error;

use crate::PedersenProvingKey;

#[derive(Debug, Error)]
pub enum PedersenError {
    #[error("length mismatch: {label} got {actual} values, expected {expected}")]
    LengthMismatch {
        label: &'static str,
        actual: usize,
        expected: usize,
    },
}

/// Chunk size for Pedersen MSMs.
const PEDERSEN_MSM_CHUNK: usize = 100_000;

impl PedersenProvingKey {
    /// `commitment = Σ vᵢ · basis[i]`
    pub fn commit(&self, values: &[Fr]) -> Result<G1Affine, PedersenError> {
        msm("commit", &self.basis, values)
    }

    /// `pok = Σ vᵢ · basis_exp_sigma[i]`
    pub fn prove_knowledge(&self, values: &[Fr]) -> Result<G1Affine, PedersenError> {
        msm("prove_knowledge", &self.basis_exp_sigma, values)
    }
}

/// Fold G1 points into one via a random linear combination:
/// `points[0] + c·points[1] + c²·points[2] + ...`
pub fn fold(points: &[G1Affine], combination_coeff: Fr) -> G1Affine {
    if points.is_empty() {
        return G1Affine::zero();
    }
    if points.len() == 1 {
        return points[0];
    }

    let mut scalars = Vec::with_capacity(points.len());
    let mut power = Fr::one();
    for _ in 0..points.len() {
        scalars.push(power);
        power *= combination_coeff;
    }

    // Lengths match by construction.
    G1Projective::msm(points, &scalars).unwrap().into_affine()
}

fn msm(label: &'static str, basis: &[G1Affine], values: &[Fr]) -> Result<G1Affine, PedersenError> {
    if values.len() != basis.len() {
        return Err(PedersenError::LengthMismatch {
            label,
            actual: values.len(),
            expected: basis.len(),
        });
    }
    if values.is_empty() {
        return Ok(G1Affine::zero());
    }

    let mut acc = G1Projective::zero();
    for (b_chunk, v_chunk) in basis
        .chunks(PEDERSEN_MSM_CHUNK)
        .zip(values.chunks(PEDERSEN_MSM_CHUNK))
    {
        // Lengths match by construction within each chunk pair.
        acc += G1Projective::msm(b_chunk, v_chunk).unwrap();
    }
    Ok(acc.into_affine())
}
