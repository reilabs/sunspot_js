//! Quotient polynomial `H = (A·B − C) / Z` via FFT.

use crate::curve::{Fft, Fr, SIMDField};
use ark_ff::{FftField, Field, One, Zero};
use ark_std::{cfg_chunks, cfg_chunks_mut, cfg_join};
#[cfg(feature = "parallel")]
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
    fft: &Fft,
) -> Result<Vec<Fr>, ProveError> {
    let n = fft.size();

    a_evals.resize(n, Fr::zero());
    b_evals.resize(n, Fr::zero());
    c_evals.resize(n, Fr::zero());

    // IFFT → coset FFT for each buffer. The three pipelines are independent
    // (separate buffers, immutable Fft ref), so run them in parallel.
    cfg_join!(
        || {
            fft.ifft_in_place(&mut a_evals);
            fft.coset_fft_in_place(&mut a_evals);
        },
        || {
            cfg_join!(
                || {
                    fft.ifft_in_place(&mut b_evals);
                    fft.coset_fft_in_place(&mut b_evals);
                },
                || {
                    fft.ifft_in_place(&mut c_evals);
                    fft.coset_fft_in_place(&mut c_evals);
                }
            )
        }
    );

    // Pointwise on the coset: a[i] ← (a[i]·b[i] − c[i]) · Z(coset)⁻¹.
    // Z(g·ωⁱ) = (g·ωⁱ)^N − 1 = g^N − 1 is constant on the coset.
    let z_inv = {
        let gen_n = Fr::GENERATOR.pow([n as u64]);
        (gen_n - Fr::one())
            .inverse()
            .ok_or(ProveError::ZeroCosetZ)?
    };

    cfg_chunks_mut!(&mut a_evals, 2)
        .zip(cfg_chunks!(&b_evals, 2))
        .zip(cfg_chunks!(&c_evals, 2))
        .for_each(|((a, b), c)| {
            let (ab0, ab1) = Fr::mul_pair(a[0], b[0], a[1], b[1]);
            let (r0, r1) = Fr::mul_pair(ab0 - c[0], z_inv, ab1 - c[1], z_inv);
            a[0] = r0;
            a[1] = r1;
        });

    // Coset IFFT: evaluation on the coset → coefficient form.
    fft.coset_ifft_in_place(&mut a_evals);

    Ok(a_evals)
}
