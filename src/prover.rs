//! Groth16+BSB22 prover.
//!
//! Given a [`SolveOutput`] (full witness, per-constraint row, and the
//!  committed values captured during solving) plus the proving key, emits a [`Proof`].
//!
//! Pipeline:
//! 1. Sample `r`, `s`; precompute `r·δ`, `s·δ`, `−rs·δ` in G1.
//! 2. In parallel: `compute_h` (FFT) and `prove_ar_bs_bs1` + `bsb22_pok`
//!    (MSMs that don't depend on `H`).
//! 3. `prove_krs` combines `H`, `Ar`, `Bs1` into the final element.
mod compute_h;
mod error;
mod msm;

use ark_bn254::{Fr, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

use crate::solver::SolveOutput;
use crate::types::CommitmentInfo;
use crate::{Proof, ProvingKey, R1CS, bsb22_pok};

pub use error::ProveError;

/// Generate a Groth16+BSB22 proof from a [`SolveOutput`] and the parsed
/// proving key.
pub fn prove(r1cs: &R1CS, solved: SolveOutput, pk: &ProvingKey) -> Result<Proof, ProveError> {
    let SolveOutput {
        witness,
        a_evals,
        b_evals,
        c_evals,
        commitments: pedersen_commitments,
        committed_values,
    } = solved;

    let nb_wires = pk.nb_wires as usize;
    if witness.len() != nb_wires {
        return Err(ProveError::WitnessLengthMismatch {
            actual: witness.len(),
            expected: nb_wires,
        });
    }

    let commitments_meta = match &r1cs.body.commitment_info {
        CommitmentInfo::Groth16(v) => v.as_slice(),
        CommitmentInfo::Plonk(_) => return Err(ProveError::UnexpectedPlonkCommitments),
    };
    if commitments_meta.len() != pk.commitment_keys.len() {
        return Err(ProveError::CommitmentKeysMismatch {
            pk: pk.commitment_keys.len(),
            r1cs: commitments_meta.len(),
        });
    }

    // Only the challenge-wire indices still need to be gathered — the
    // commitments and committed values came pre-populated from the solver.
    let challenge_wire_indices: Vec<usize> = commitments_meta
        .iter()
        .map(|ci| ci.commitment_index as usize)
        .collect();

    // --- Trapdoors r, s and their δ multiples (used in both Krs and Ar/Bs).
    let mut rng = ark_std::rand::thread_rng();
    let r_scalar = Fr::rand(&mut rng);
    let s_scalar = Fr::rand(&mut rng);
    let kr_scalar = -(r_scalar * s_scalar);
    let g1_delta_proj = G1Projective::from(pk.g1_delta);
    let r_delta = (g1_delta_proj * r_scalar).into_affine();
    let s_delta = (g1_delta_proj * s_scalar).into_affine();
    let kr_delta = (g1_delta_proj * kr_scalar).into_affine();

    let domain: Radix2EvaluationDomain<Fr> =
        EvaluationDomain::new(r1cs.body.nb_constraints as usize).ok_or(ProveError::CosetDomain)?;
    let domain_size = pk.domain.cardinality;

    // --- Overlap the FFT-bound `compute_h` with the H-independent MSMs.
    let witness_ref = witness.as_slice();
    let (h_result, branch_b_result) = rayon::join(
        move || compute_h::compute_h(a_evals, b_evals, c_evals, &domain),
        || -> Result<_, ProveError> {
            let pok = bsb22_pok(
                &pk.commitment_keys,
                &committed_values,
                &challenge_wire_indices,
                witness_ref,
            )?;
            let (ar, bs, bs1) = msm::prove_ar_bs_bs1(
                &pk.g1_a,
                &pk.g1_b,
                &pk.g2_b,
                &pk.idx_a,
                &pk.idx_b,
                witness_ref,
                pk.g1_alpha,
                pk.g1_beta,
                pk.g2_beta,
                pk.g2_delta,
                r_delta,
                s_delta,
                s_scalar,
            )?;
            Ok((pok, ar, bs, bs1))
        },
    );

    let h = h_result?;
    let (commitment_pok, ar, bs, bs1) = branch_b_result?;

    let krs = msm::prove_krs(
        &pk.g1_k,
        &pk.g1_z,
        &h,
        &witness,
        r1cs.body.public.len(),
        commitments_meta,
        &challenge_wire_indices,
        domain_size,
        ar,
        bs1,
        kr_delta,
        r_scalar,
        s_scalar,
    )?;

    Ok(Proof {
        ar,
        bs,
        krs,
        commitments: pedersen_commitments,
        commitment_pok,
    })
}

/// Per-stage timing breakdown of `prove`, in milliseconds. Stages are run
/// strictly sequentially (no `rayon::join`) so the numbers attribute work to
/// a single stage instead of overlapping pools.
#[cfg(feature = "bench")]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProveStageTimings {
    pub setup_ms: f64,
    pub compute_h_ms: f64,
    pub bsb22_pok_ms: f64,
    pub prove_ar_bs_bs1_ms: f64,
    pub prove_krs_ms: f64,
}

/// Bench-only variant of [`prove`] that records per-stage timings using
/// `performance.now()`. Runs the stages sequentially so each stage's number
/// reflects work done with the full thread pool — useful for spotting the
/// dominant cost, not for predicting end-to-end wall time (which benefits
/// from the `rayon::join` overlap in [`prove`]).
#[cfg(feature = "bench")]
pub fn prove_with_timings(
    r1cs: &R1CS,
    solved: SolveOutput,
    pk: &ProvingKey,
) -> Result<(Proof, ProveStageTimings), ProveError> {
    fn now() -> f64 {
        web_sys::window()
            .expect("no `window`")
            .performance()
            .expect("no `performance`")
            .now()
    }

    let t_setup_start = now();

    let SolveOutput {
        witness,
        a_evals,
        b_evals,
        c_evals,
        commitments: pedersen_commitments,
        committed_values,
    } = solved;

    let nb_wires = pk.nb_wires as usize;
    if witness.len() != nb_wires {
        return Err(ProveError::WitnessLengthMismatch {
            actual: witness.len(),
            expected: nb_wires,
        });
    }

    let commitments_meta = match &r1cs.body.commitment_info {
        CommitmentInfo::Groth16(v) => v.as_slice(),
        CommitmentInfo::Plonk(_) => return Err(ProveError::UnexpectedPlonkCommitments),
    };
    if commitments_meta.len() != pk.commitment_keys.len() {
        return Err(ProveError::CommitmentKeysMismatch {
            pk: pk.commitment_keys.len(),
            r1cs: commitments_meta.len(),
        });
    }

    let challenge_wire_indices: Vec<usize> = commitments_meta
        .iter()
        .map(|ci| ci.commitment_index as usize)
        .collect();

    let mut rng = ark_std::rand::thread_rng();
    let r_scalar = Fr::rand(&mut rng);
    let s_scalar = Fr::rand(&mut rng);
    let kr_scalar = -(r_scalar * s_scalar);
    let g1_delta_proj = G1Projective::from(pk.g1_delta);
    let r_delta = (g1_delta_proj * r_scalar).into_affine();
    let s_delta = (g1_delta_proj * s_scalar).into_affine();
    let kr_delta = (g1_delta_proj * kr_scalar).into_affine();

    let domain: Radix2EvaluationDomain<Fr> =
        EvaluationDomain::new(r1cs.body.nb_constraints as usize).ok_or(ProveError::CosetDomain)?;
    let domain_size = pk.domain.cardinality;

    let witness_ref = witness.as_slice();

    let t_compute_h_start = now();
    let h = compute_h::compute_h(a_evals, b_evals, c_evals, &domain)?;
    let t_compute_h_end = now();

    let commitment_pok = bsb22_pok(
        &pk.commitment_keys,
        &committed_values,
        &challenge_wire_indices,
        witness_ref,
    )?;
    let t_bsb22_pok_end = now();

    let (ar, bs, bs1) = msm::prove_ar_bs_bs1(
        &pk.g1_a,
        &pk.g1_b,
        &pk.g2_b,
        &pk.idx_a,
        &pk.idx_b,
        witness_ref,
        pk.g1_alpha,
        pk.g1_beta,
        pk.g2_beta,
        pk.g2_delta,
        r_delta,
        s_delta,
        s_scalar,
    )?;
    let t_ar_bs_end = now();

    let krs = msm::prove_krs(
        &pk.g1_k,
        &pk.g1_z,
        &h,
        &witness,
        r1cs.body.public.len(),
        commitments_meta,
        &challenge_wire_indices,
        domain_size,
        ar,
        bs1,
        kr_delta,
        r_scalar,
        s_scalar,
    )?;
    let t_krs_end = now();

    let timings = ProveStageTimings {
        setup_ms: t_compute_h_start - t_setup_start,
        compute_h_ms: t_compute_h_end - t_compute_h_start,
        bsb22_pok_ms: t_bsb22_pok_end - t_compute_h_end,
        prove_ar_bs_bs1_ms: t_ar_bs_end - t_bsb22_pok_end,
        prove_krs_ms: t_krs_end - t_ar_bs_end,
    };

    Ok((
        Proof {
            ar,
            bs,
            krs,
            commitments: pedersen_commitments,
            commitment_pok,
        },
        timings,
    ))
}
