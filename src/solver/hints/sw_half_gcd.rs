//! `std/algebra/emulated/sw_emulated.halfGCD`: runs the
//! Euclidean half-GCD for `(r, λ)` and returns the first basis vector
//! `V₁ = (V₁[0], V₁[1])` of the GLV-style lattice. Used by the FakeGLV
//! scalar-mul path (non-GLV curves like secp256r1/P-256) to find a short
//! pair `(s₁, s₂)` with `s₁ + s·s₂ ≡ 0 (mod r)` and `|s₁|, |s₂| < √r`.
//!
//! Inputs:
//!   inputs[0..6]   = header [nbNativeIn=0, nbNativeOut=1,
//!                            nbE1In=1, nbE1Out=2, nbE2In=0, nbE2Out=0]
//!   inputs[6..8]   = (nbLimbs, nbBits) for the scalar field
//!   inputs[8..]    = scalar-field modulus limbs, then length-prefixed `_s`
//!
//! Outputs: `1 native + 2 × NB_LIMBS = 9` Fr values laid out as:
//!   nativeOut[0]   = sign(V₁[1])    (0 = nonneg, 1 = negative)
//!   emuOut[0..4]   = V₁[0] limbs    (always nonneg)
//!   emuOut[4..8]   = |V₁[1]| limbs
use crate::curve::Fr;
use ark_ff::{One, Zero};
use crypto_bigint::NonZero;

use crate::{
    Solver,
    solver::{Cursor, SolveError},
};

use super::{
    HINT_HEADER_LEN,
    bigint::{SignedWide, Wide, decompose, recompose},
    emulated_shared::{EMU_HEADER_LEN, NB_BITS, NB_LIMBS},
    error::HintError,
    fr_to_u64, read_input, read_n_inputs,
};

const NAME: &str = "sw_emulated.halfGCD";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()? as usize;
    if nb_inputs < HINT_HEADER_LEN + EMU_HEADER_LEN + 2 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: (HINT_HEADER_LEN + EMU_HEADER_LEN + 2) as u32,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let _header = read_n_inputs(cursor, solver, HINT_HEADER_LEN)?;
    let _nb_limbs = fr_to_u64(NAME, &read_input(cursor, solver)?)?;
    let _nb_bits = fr_to_u64(NAME, &read_input(cursor, solver)?)?;
    let modulus_limbs = read_n_inputs(cursor, solver, NB_LIMBS)?;
    let s_nb = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let s_limbs = read_n_inputs(cursor, solver, s_nb)?;

    let r = recompose(&modulus_limbs, NB_BITS);
    let lambda = recompose(&s_limbs, NB_BITS);

    let (v1_0, v1_1_abs, v1_1_neg) = half_gcd_v1(r, lambda);

    let (start, end) = cursor.read_pair()?;
    let actual = (end - start) as usize;
    let expected = 1 + 2 * NB_LIMBS;
    if actual != expected {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: expected as u32,
            actual: actual as u32,
        }
        .into());
    }

    let mut out = Vec::with_capacity(expected);
    out.push((start, if v1_1_neg { Fr::one() } else { Fr::zero() }));
    for (i, l) in decompose(v1_0, NB_LIMBS).into_iter().enumerate() {
        out.push((start + 1 + i as u32, l));
    }
    for (i, l) in decompose(v1_1_abs, NB_LIMBS).into_iter().enumerate() {
        out.push((start + 1 + NB_LIMBS as u32 + i as u32, l));
    }
    Ok(out)
}

/// Truncated half-GCD: runs the same Euclidean recursion as
/// `gnark-crypto`'s `PrecomputeLattice` but only tracks the data needed for
/// `V₁ = (rst[1][0], −rst[1][2])`. Returns `(V₁[0], |V₁[1]|, V₁[1] < 0)`.
fn half_gcd_v1(r: Wide, lambda: Wide) -> (Wide, Wide, bool) {
    // r[*]: positive remainders. t[*]: signed Bézout-style coefficients for the
    // lambda side. We don't need the matching s-track because V₂ isn't used.
    let mut rr_prev = r;
    let mut rr_curr = lambda;
    let mut tt_prev = SignedWide::ZERO;
    let mut tt_curr = SignedWide::ONE;

    let sqrt_r = r.floor_sqrt();

    // Iterate while rst[1][0] >= sqrt(r). Once below threshold, we have the
    // short basis vector we want.
    while rr_curr >= sqrt_r && rr_curr != Wide::ZERO {
        let rr_nz = NonZero::new(rr_curr).expect("rr_curr nonzero by loop guard");
        let q = rr_prev.div_rem(&rr_nz).0;
        let rr_new = rr_prev.wrapping_sub(&q.wrapping_mul(&rr_curr));
        let tt_new = tt_prev.wrapping_sub(&tt_curr.wrapping_mul(q.as_int()));
        rr_prev = rr_curr;
        rr_curr = rr_new;
        tt_prev = tt_curr;
        tt_curr = tt_new;
    }

    // V₁[0] = rst[1][0] (always ≥ 0). V₁[1] = −rst[1][2] = −tt_curr.
    let v1_1 = tt_curr.wrapping_neg();
    let (v1_1_abs, v1_1_neg) = v1_1.abs_sign();
    (rr_curr, v1_1_abs, bool::from(v1_1_neg))
}
