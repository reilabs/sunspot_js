//! Quotient polynomial `H = (A·B − C) / Z` via FFT.

use crate::curve::Fr;
use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rayon::prelude::*;

use super::error::ProveError;

/// Given the wire-level evaluations `a_evals = A·w`, `b_evals = B·w`,
/// `c_evals = C·w` for each constraint, compute the coefficients of
/// `H` such that `A·B − C = H·Z` (with `Z` the vanishing polynomial of
/// the FFT domain).
pub(super) fn compute_h(
    mut a_evals: Vec<Fr>,
    mut b_evals: Vec<Fr>,
    mut c_evals: Vec<Fr>,
    domain: &Radix2EvaluationDomain<Fr>,
) -> Result<Vec<Fr>, ProveError> {
    let n = domain.size();

    a_evals.resize(n, Fr::zero());
    b_evals.resize(n, Fr::zero());
    c_evals.resize(n, Fr::zero());

    // IFFT → coset FFT for each buffer. The three pipelines are independent
    // (separate buffers, immutable domain refs), so run them in parallel.
    let coset_domain = domain
        .get_coset(Fr::GENERATOR)
        .ok_or(ProveError::CosetDomain)?;
    rayon::join(
        || {
            domain.ifft_in_place(&mut a_evals);
            coset_domain.fft_in_place(&mut a_evals);
        },
        || {
            rayon::join(
                || {
                    domain.ifft_in_place(&mut b_evals);
                    coset_domain.fft_in_place(&mut b_evals);
                },
                || {
                    domain.ifft_in_place(&mut c_evals);
                    coset_domain.fft_in_place(&mut c_evals);
                },
            )
        },
    );

    // Pointwise on the coset: a[i] ← (a[i]·b[i] − c[i]) · Z(coset)⁻¹.
    // Z(g·ωⁱ) = (g·ωⁱ)^N − 1 = g^N − 1 is constant on the coset.
    let z_inv = {
        let gen_n = Fr::GENERATOR.pow([n as u64]);
        (gen_n - Fr::one())
            .inverse()
            .ok_or(ProveError::ZeroCosetZ)?
    };

    a_evals
        .par_iter_mut()
        .zip(b_evals.par_iter())
        .zip(c_evals.par_iter())
        .for_each(|((a, b), c)| {
            *a = (*a * b - c) * z_inv;
        });

    // Coset IFFT: evaluation on the coset → coefficient form.
    coset_domain.ifft_in_place(&mut a_evals);

    Ok(a_evals)
}
