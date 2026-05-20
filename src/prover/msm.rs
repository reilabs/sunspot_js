//! Groth16 MSM stages: `Ar`, `Bs`, `Bs1`, and the final `Krs` element.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::Zero;

use super::error::ProveError;
use crate::types::Groth16Commitment;

/// Compute `A_r`, `B_s`, and `Bs1`
#[allow(clippy::too_many_arguments)]
pub(super) fn prove_ar_bs_bs1(
    g1_a: &[G1Affine],
    g1_b: &[G1Affine],
    g2_b: &[G2Affine],
    infinity_a: &[bool],
    infinity_b: &[bool],
    wire_values: &[Fr],
    g1_alpha: G1Affine,
    g1_beta: G1Affine,
    g2_beta: G2Affine,
    g2_delta: G2Affine,
    r_delta: G1Affine,
    s_delta: G1Affine,
    s_scalar: Fr,
) -> Result<(G1Affine, G2Affine, G1Projective), ProveError> {
    // The PK ships `g1_a`/`g1_b`/`g2_b` with all-zero points filtered out;
    // gather the matching wire scalars by skipping infinity flags.
    let (wire_values_a, wire_values_b) = rayon::join(
        || {
            wire_values
                .iter()
                .enumerate()
                .filter(|(i, _)| !infinity_a[*i])
                .map(|(_, v)| *v)
                .collect::<Vec<Fr>>()
        },
        || {
            wire_values
                .iter()
                .enumerate()
                .filter(|(i, _)| !infinity_b[*i])
                .map(|(_, v)| *v)
                .collect::<Vec<Fr>>()
        },
    );

    let ar = {
        let msm = G1Projective::msm(g1_a, &wire_values_a).map_err(ProveError::msm("g1_a"))?;
        let mut result = msm;
        result += G1Projective::from(g1_alpha);
        result += G1Projective::from(r_delta);
        result.into_affine()
    };
    let bs = {
        let msm = <G2Projective as VariableBaseMSM>::msm(g2_b, &wire_values_b)
            .map_err(ProveError::msm("g2_b"))?;
        let mut result = msm;
        result += G2Projective::from(g2_beta);
        result += G2Projective::from(g2_delta) * s_scalar;
        result.into_affine()
    };
    let bs1 = {
        let msm = G1Projective::msm(g1_b, &wire_values_b).map_err(ProveError::msm("g1_b"))?;
        let mut result = msm;
        result += G1Projective::from(g1_beta);
        result += G1Projective::from(s_delta);
        result
    };
    Ok((ar, bs, bs1))
}

/// Compute `Krs`, the final Groth16 group element.
#[allow(clippy::too_many_arguments)]
pub(super) fn prove_krs(
    g1_k: &[G1Affine],
    g1_z: &[G1Affine],
    h: &[Fr],
    wire_values: &[Fr],
    r1cs_nb_public: usize,
    commitment_info: &[Groth16Commitment],
    challenge_wire_indices: &[usize],
    domain_size: u64,
    ar: G1Affine,
    bs1: G1Projective,
    kr_delta: G1Affine,
    r_scalar: Fr,
    s_scalar: Fr,
) -> Result<G1Affine, ProveError> {
    // `pk.g1_k` is keyed on private, non-committed, non-challenge wires.
    // Strip out the committed and challenge wires from the private witness
    // segment in the same order setup produced the bases.
    let private_wire_values: Vec<Fr> = {
        let mut to_remove: Vec<usize> = Vec::new();
        for ci in commitment_info {
            to_remove.extend(ci.private_committed.iter().map(|&i| i as usize));
        }
        to_remove.extend_from_slice(challenge_wire_indices);
        to_remove.sort_unstable();
        to_remove.dedup();
        filter_by_sorted_indices(&wire_values[r1cs_nb_public..], &to_remove, r1cs_nb_public)
    };

    if private_wire_values.len() != g1_k.len() {
        return Err(ProveError::PrivateWireCountMismatch {
            actual: private_wire_values.len(),
            expected: g1_k.len(),
        });
    }

    let size_h = domain_size as usize - 1;

    let (krs1_result, krs2_result) = rayon::join(
        || G1Projective::msm(g1_k, &private_wire_values).map_err(ProveError::msm("g1_k")),
        || {
            if !h.is_empty() && !g1_z.is_empty() {
                let h_slice = &h[..size_h.min(h.len())];
                let z_slice = &g1_z[..size_h.min(g1_z.len())];
                let min_len = h_slice.len().min(z_slice.len());
                G1Projective::msm(&z_slice[..min_len], &h_slice[..min_len])
                    .map_err(ProveError::msm("g1_z"))
            } else {
                Ok(G1Projective::zero())
            }
        },
    );

    let mut result = krs1_result? + krs2_result?;
    result += G1Projective::from(kr_delta);

    // Cross-terms: s·Ar + r·Bs1.
    let (s_ar, r_bs1) = rayon::join(|| G1Projective::from(ar) * s_scalar, || bs1 * r_scalar);
    result += s_ar;
    result += r_bs1;

    Ok(result.into_affine())
}

/// Drop elements at the sorted absolute indices `sorted_indices` from
/// `slice`, where `slice` starts at absolute index `base_offset`. Merge
/// scan, O(n + k).
fn filter_by_sorted_indices(slice: &[Fr], sorted_indices: &[usize], base_offset: usize) -> Vec<Fr> {
    if sorted_indices.is_empty() {
        return slice.to_vec();
    }
    let mut result = Vec::with_capacity(slice.len());
    let mut remove_idx = 0;
    for (i, val) in slice.iter().enumerate() {
        let abs_idx = i + base_offset;
        while remove_idx < sorted_indices.len() && sorted_indices[remove_idx] < abs_idx {
            remove_idx += 1;
        }
        if remove_idx < sorted_indices.len() && sorted_indices[remove_idx] == abs_idx {
            remove_idx += 1;
            continue;
        }
        result.push(*val);
    }
    result
}
