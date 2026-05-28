//! `std/math/emulated.polyMvHint): emulated multivariate
//! polynomial evaluation. Computes `fullLhs = Σ coeff_i · ∏ vars_j^term_ij`
//! over `Fp` and returns the quotient `k`, the nonnegative remainder `r`,
//! and per-limb carries that align the limb-wise product with `r + k·p`.
//!
//! Calldata layout (per `Field[T].callPolyMvHint` in gnark v0.14.0):
//!   inputs[0]                        = nbBits
//!   inputs[1]                        = nbLimbs
//!   inputs[2]                        = nbTerms
//!   inputs[3]                        = nbVars
//!   inputs[4]                        = nbQuoLimbs
//!   inputs[5]                        = nbCarryLimbs
//!   inputs[6 .. +nbTerms·nbVars]     = exponent matrix (row-major)
//!   inputs[.. +nbTerms]              = signed coefficients (negative ones
//!                                      arrive as `Fr(p − |c|)`)
//!   inputs[.. +nbLimbs]              = modulus limbs
//!   for each var:
//!       inputs[..]                   = nb_limbs of var followed by its limbs
//!
//! Outputs (`nbQuoLimbs + nbLimbs + nbCarryLimbs` Fr values, in order):
//!   `k limbs`, `r limbs`, carry limbs.
//!
//! Note on negative coefficients: gnark stores them as Go ints, but they
//! arrive in the witness as Fr field elements. A coefficient of `-1` becomes
//! `Fr(p − 1)`, which when widened to `Wide` is a ~256-bit positive number.
//! gnark's hint then computes everything in non-modular bigint arithmetic
//! (so `(p − 1)·v ≡ −v (mod p)` automatically), and the constraint check
//! verifies the limb expansion against the same Fr-coefficient interpretation.

use crate::curve::Fr;
use crate::{
    Solver,
    solver::{Cursor, SolveError},
};
use crypto_bigint::NonZero;

use super::{
    HintError,
    bigint::{Wide, decompose, field_to_wide, limb_mul, recompose},
    emulated_shared::{build_rhs_limbs, compute_carries, emit_quo_rem_carries},
    fr_to_u64, read_input, read_n_inputs,
};

const NAME: &str = "emulated.polyMvHint";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()? as usize;
    if nb_inputs < 6 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 6,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let nb_bits = fr_to_u64(NAME, &read_input(cursor, solver)?)? as u32;
    let nb_limbs = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let nb_terms = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let nb_vars = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let nb_quo_limbs = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let nb_carry_limbs = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;

    // Exponent matrix.
    let mut terms: Vec<Vec<usize>> = Vec::with_capacity(nb_terms);
    for _ in 0..nb_terms {
        let mut row = Vec::with_capacity(nb_vars);
        for _ in 0..nb_vars {
            row.push(fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize);
        }
        terms.push(row);
    }

    // Coefficients as Wide values (signed coefficients show up here as their
    // mod-p representative — see header comment).
    let mut coeffs: Vec<Wide> = Vec::with_capacity(nb_terms);
    for _ in 0..nb_terms {
        coeffs.push(field_to_wide(&read_input(cursor, solver)?));
    }

    let p_limbs = read_n_inputs(cursor, solver, nb_limbs)?;
    let p = recompose(&p_limbs, nb_bits);
    let p_wide: Vec<Wide> = p_limbs.iter().map(field_to_wide).collect();

    // Each variable: length-prefixed limb slice.
    let mut vars_limbs: Vec<Vec<Fr>> = Vec::with_capacity(nb_vars);
    for _ in 0..nb_vars {
        let n = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
        vars_limbs.push(read_n_inputs(cursor, solver, n)?);
    }
    let vars_recomposed: Vec<Wide> = vars_limbs.iter().map(|l| recompose(l, nb_bits)).collect();
    let vars_limbs_wide: Vec<Vec<Wide>> = vars_limbs
        .iter()
        .map(|l| l.iter().map(field_to_wide).collect())
        .collect();

    let (start, end) = cursor.read_pair()?;
    let actual_outputs = (end - start) as usize;
    let expected_outputs = nb_quo_limbs + nb_limbs + nb_carry_limbs;
    if actual_outputs != expected_outputs {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: expected_outputs as u32,
            actual: actual_outputs as u32,
        }
        .into());
    }

    // Step 1: full polynomial value as one (large) unsigned bigint. Sized so
    // that for typical EC formulas (≤ 4-var monomials, coefficients of size
    // ≤ |p|, ≤ a handful of terms) the result stays well below 2^2048.
    let mut full_lhs = Wide::ZERO;
    for (i, term) in terms.iter().enumerate() {
        let mut term_res = coeffs[i];
        for (j, pow) in term.iter().enumerate() {
            for _ in 0..*pow {
                term_res = term_res.wrapping_mul(&vars_recomposed[j]);
            }
        }
        full_lhs = full_lhs.wrapping_add(&term_res);
    }

    // Step 2: Euclidean division. fullLhs ≥ 0 here because every coefficient
    // arrived as a nonnegative `Wide` (see header note).
    let (quo, rem) = match NonZero::new(p).into_option() {
        Some(p_nz) => full_lhs.div_rem(&p_nz),
        None => (Wide::ZERO, Wide::ZERO),
    };
    let quo_limbs = decompose(quo, nb_quo_limbs);
    let rem_limbs = decompose(rem, nb_limbs);

    // Step 3: limbwise lhs (all positive — Σ unsigned coeff · ∏ var_limbs).
    let mut lhs: Vec<Wide> = Vec::new();
    for (i, term) in terms.iter().enumerate() {
        let mut term_var_limbs: Vec<&[Wide]> = Vec::new();
        for (j, pow) in term.iter().enumerate() {
            for _ in 0..*pow {
                term_var_limbs.push(&vars_limbs_wide[j]);
            }
        }
        if term_var_limbs.is_empty() {
            continue;
        }
        let mut term_res: Vec<Wide> = vec![coeffs[i]];
        for to_mul in term_var_limbs {
            term_res = limb_mul(&term_res, to_mul);
        }
        while lhs.len() < term_res.len() {
            lhs.push(Wide::ZERO);
        }
        for (j, t) in term_res.into_iter().enumerate() {
            lhs[j] = lhs[j].wrapping_add(&t);
        }
    }

    // Step 4: rhs = rem + k·p, then walk carries and emit.
    let rhs = build_rhs_limbs(&quo_limbs, &p_wide, &rem_limbs);
    let carries = compute_carries(&lhs, &rhs, nb_carry_limbs, nb_bits);
    Ok(emit_quo_rem_carries(
        start, &quo_limbs, &rem_limbs, &carries,
    ))
}
