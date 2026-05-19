//! Emulated-field modular inverse and division.
//!
//! `DivHint` calldata:
//!   inputs[0]                                 = nbBits
//!   inputs[1]                                 = nbLimbs
//!   inputs[2]                                 = nbDenomLimbs
//!   inputs[3]                                 = nbNomLimbs
//!   inputs[4 .. +nbLimbs]                     = modulus limbs
//!   inputs[.. +nbNomLimbs]                    = nominator limbs
//!   inputs[..]                                = denominator limbs
//! Outputs: nbLimbs limbs of `(nominator · denominator⁻¹) mod p`.
//!
//! `InverseHint` calldata is the same as DivHint without the nominator section:
//!   inputs[0]                  = nbBits
//!   inputs[1]                  = nbLimbs
//!   inputs[2 .. +nbLimbs]      = modulus limbs
//!   inputs[..]                 = x limbs
//! Outputs: nbLimbs limbs of `x⁻¹ mod p`.

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};

use super::{
    HintError,
    bigint::{Wide, decompose, field_to_wide, recompose},
    emulated_shared::dispatch_by_modulus,
    {fr_to_u64, read_input, read_n_inputs},
};
use crate::solver::{Cursor, SolveError, Solver};

const NAME_DIV: &str = "emulated.DivHint";
const NAME_INV: &str = "emulated.InverseHint";

pub(super) fn solve_div(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()? as usize;
    if nb_inputs < 4 {
        return Err(HintError::HintInputShape {
            hint_name: NAME_DIV,
            expected: 4,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let nb_bits = fr_to_u64(NAME_DIV, &read_input(cursor, solver)?)? as u32;
    let nb_limbs = fr_to_u64(NAME_DIV, &read_input(cursor, solver)?)? as usize;
    let nb_denom = fr_to_u64(NAME_DIV, &read_input(cursor, solver)?)? as usize;
    let nb_nom = fr_to_u64(NAME_DIV, &read_input(cursor, solver)?)? as usize;
    let remaining = nb_inputs - 4;
    let expected_remaining = nb_limbs + nb_nom + nb_denom;
    if remaining != expected_remaining {
        return Err(HintError::HintInputShape {
            hint_name: NAME_DIV,
            expected: (4 + expected_remaining) as u32,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let p = recompose(&read_n_inputs(cursor, solver, nb_limbs)?, nb_bits);
    let nom = recompose(&read_n_inputs(cursor, solver, nb_nom)?, nb_bits);
    let denom = recompose(&read_n_inputs(cursor, solver, nb_denom)?, nb_bits);

    let (start, end) = cursor.read_pair()?;
    if (end - start) as usize != nb_limbs {
        return Err(HintError::HintOutputShape {
            hint_name: NAME_DIV,
            expected: nb_limbs as u32,
            actual: end - start,
        }
        .into());
    }

    let res = dispatch_div(p, nom, denom, NAME_DIV)?.ok_or(HintError::HintNoModInverse {
        hint_name: NAME_DIV,
    })?;
    let limbs = decompose(res, nb_limbs);
    Ok(limbs
        .into_iter()
        .enumerate()
        .map(|(i, l)| (start + i as u32, l))
        .collect())
}

pub(super) fn solve_inverse(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()? as usize;
    if nb_inputs < 2 {
        return Err(HintError::HintInputShape {
            hint_name: NAME_INV,
            expected: 2,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let nb_bits = fr_to_u64(NAME_INV, &read_input(cursor, solver)?)? as u32;
    let nb_limbs = fr_to_u64(NAME_INV, &read_input(cursor, solver)?)? as usize;
    let remaining = nb_inputs - 2;
    if remaining < 2 * nb_limbs {
        return Err(HintError::HintInputShape {
            hint_name: NAME_INV,
            expected: (2 + 2 * nb_limbs) as u32,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let p = recompose(&read_n_inputs(cursor, solver, nb_limbs)?, nb_bits);
    let x_len = remaining - nb_limbs;
    let x = recompose(&read_n_inputs(cursor, solver, x_len)?, nb_bits);

    let (start, end) = cursor.read_pair()?;
    if (end - start) as usize != nb_limbs {
        return Err(HintError::HintOutputShape {
            hint_name: NAME_INV,
            expected: nb_limbs as u32,
            actual: end - start,
        }
        .into());
    }

    let inv = dispatch_inv(p, x, NAME_INV)?.ok_or(HintError::HintNoModInverse {
        hint_name: NAME_INV,
    })?;
    let limbs = decompose(inv, nb_limbs);
    Ok(limbs
        .into_iter()
        .enumerate()
        .map(|(i, l)| (start + i as u32, l))
        .collect())
}

/// Dispatch `nom · denom⁻¹ mod p` to the matching arkworks field. Returns
/// `Ok(None)` when `denom` has no inverse (i.e. `denom ≡ 0 mod p`).
fn dispatch_div(
    p: Wide,
    nom: Wide,
    denom: Wide,
    hint_name: &'static str,
) -> Result<Option<Wide>, SolveError> {
    dispatch_by_modulus!(p, hint_name, |F| {
        let n = F::from_le_bytes_mod_order(&nom.to_le_bytes());
        let d = F::from_le_bytes_mod_order(&denom.to_le_bytes());
        d.inverse().map(|inv| field_to_wide(&(n * inv)))
    })
}

fn dispatch_inv(p: Wide, x: Wide, hint_name: &'static str) -> Result<Option<Wide>, SolveError> {
    dispatch_by_modulus!(p, hint_name, |F| {
        let xf = F::from_le_bytes_mod_order(&x.to_le_bytes());
        xf.inverse().map(|v| field_to_wide(&v))
    })
}
