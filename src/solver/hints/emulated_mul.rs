//! `std/math/emulated.mulHint`: computes the quotient, remainder, and per-limb
//! carries for `a * b == k * p + r` over the emulated field.
//!
//! Calldata layout (per `Field[T].callMulHint`):
//!   inputs[0]              = nbBits
//!   inputs[1]              = nbLimbs
//!   inputs[2]              = nbALen
//!   inputs[3]              = nbQuoLen
//!   inputs[4 .. +nbLimbs]  = modulus limbs (little-endian)
//!   inputs[.. +nbALen]     = a limbs
//!   inputs[..]             = b limbs
//!
//! Outputs (in order):
//!   nbQuoLen quotient limbs, nbLimbs remainder limbs, nbCarryLen carry limbs
//!   where `nbCarryLen = max(nbMulRes(nbALen,nbBLen), nbMulRes(nbQuoLen,nbLimbs)) - 1`.

use crate::curve::Fr;
use ark_ff::PrimeField;

use crate::{
    Solver,
    solver::{Cursor, SolveError},
};

use super::{
    HintError,
    bigint::{Wide, decompose, field_to_wide, limb_mul, nb_mul_res_limbs, recompose},
    emulated_shared::{
        build_rhs_limbs, compute_carries, dispatch_by_modulus, emit_quo_rem_carries,
    },
    fr_to_u64, read_input, read_n_inputs,
};

const NAME: &str = "emulated.mulHint";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()? as usize;
    if nb_inputs < 4 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 4,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let nb_bits = fr_to_u64(NAME, &read_input(cursor, solver)?)? as u32;
    let nb_limbs = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let nb_a_len = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let nb_quo_len = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;

    // Remaining inputs split as [modulus_limbs(nbLimbs), a_limbs(nbALen), b_limbs(nbBLen)].
    let remaining = nb_inputs - 4;
    if remaining < nb_limbs + nb_a_len {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: (4 + nb_limbs + nb_a_len) as u32,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let nb_b_len = remaining - nb_limbs - nb_a_len;

    let p_limbs = read_n_inputs(cursor, solver, nb_limbs)?;
    let a_limbs = read_n_inputs(cursor, solver, nb_a_len)?;
    let b_limbs = read_n_inputs(cursor, solver, nb_b_len)?;

    let nb_carry_len = nb_mul_res_limbs(nb_a_len, nb_b_len)
        .max(nb_mul_res_limbs(nb_quo_len, nb_limbs))
        .saturating_sub(1);
    let expected_outputs = nb_quo_len + nb_limbs + nb_carry_len;

    let (start, end) = cursor.read_pair()?;
    let actual_outputs = (end - start) as usize;
    if actual_outputs != expected_outputs {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: expected_outputs as u32,
            actual: actual_outputs as u32,
        }
        .into());
    }

    // Recompose the operands into bigints. The remainder is computed via the
    // matching arkworks field (dispatch on modulus); the quotient is the exact
    // integer division `(a·b − rem) / p`.
    let p = recompose(&p_limbs, nb_bits);
    let a = recompose(&a_limbs, nb_bits);
    let b = recompose(&b_limbs, nb_bits);
    let ab = a.wrapping_mul(&b);
    let rem = dispatch_mul(p, a, b, NAME)?;
    let quo = ab
        .wrapping_sub(&rem)
        .div_rem(&crypto_bigint::NonZero::new(p).expect("modulus is nonzero"))
        .0;

    // Lay out the quotient and remainder limbs.
    let quo_limbs = decompose(quo, nb_quo_len);
    let rem_limbs = decompose(rem, nb_limbs);

    // Build the limb-product lhs/rhs and let the shared helper walk the carries.
    let a_wide: Vec<Wide> = a_limbs.iter().map(field_to_wide).collect();
    let b_wide: Vec<Wide> = b_limbs.iter().map(field_to_wide).collect();
    let p_wide: Vec<Wide> = p_limbs.iter().map(field_to_wide).collect();
    let lhs = limb_mul(&a_wide, &b_wide);
    let rhs = build_rhs_limbs(&quo_limbs, &p_wide, &rem_limbs);
    let carries = compute_carries(&lhs, &rhs, nb_carry_len, nb_bits);

    Ok(emit_quo_rem_carries(
        start, &quo_limbs, &rem_limbs, &carries,
    ))
}

/// Dispatch `a · b mod p` to the matching arkworks field.
fn dispatch_mul(p: Wide, a: Wide, b: Wide, hint_name: &'static str) -> Result<Wide, SolveError> {
    dispatch_by_modulus!(p, hint_name, |F| {
        let af = F::from_le_bytes_mod_order(&a.to_le_bytes());
        let bf = F::from_le_bytes_mod_order(&b.to_le_bytes());
        field_to_wide(&(af * bf))
    })
}
