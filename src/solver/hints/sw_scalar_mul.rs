//! Computes `Q = [s]·P` over a short-Weierstrass curve, with point coordinates
//! and the scalar all in emulated form.
//!
//! Calldata layout:
//!
//!   inputs[0..6]   = header [nbNativeIn=0, nbNativeOut=0,
//!                            nbE1In=2, nbE1Out=2, nbE2In=1, nbE2Out=0]
//!   inputs[6..]    = T1 (base-field) modulus header (nbLimbs, nbBits, limbs)
//!                    followed by length-prefixed Px and Py
//!   inputs[..]     = T2 (scalar-field) modulus header followed by
//!                    length-prefixed s
//!
//! Outputs: `2 · t1_nb_limbs` Fr witness values — base-field limbs of Qx
//! followed by limbs of Qy.
use crate::curve::{Fr, G1Config};
use ark_ec::{
    AffineRepr, CurveGroup,
    short_weierstrass::{Affine, SWCurveConfig},
};
use ark_ff::PrimeField;

use super::{
    bigint::{Wide, decompose, field_to_wide, recompose},
    emulated_shared::{BN254_FP, SECP256K1_FP, SECP256R1_FP},
    error::HintError,
    {fr_to_u64, read_input, read_n_inputs},
};
use crate::solver::{Cursor, error::SolveError, hints::HINT_HEADER_LEN, state::Solver};

const NAME: &str = "sw_emulated.scalarMulHint";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let _nb_inputs = cursor.read_u32()?;

    let _header = read_n_inputs(cursor, solver, HINT_HEADER_LEN)?;

    let t1_nb_limbs = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let t1_nb_bits = fr_to_u64(NAME, &read_input(cursor, solver)?)? as u32;
    let t1_modulus_limbs = read_n_inputs(cursor, solver, t1_nb_limbs)?;
    let base_modulus = recompose(&t1_modulus_limbs, t1_nb_bits);
    let px_nb = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let px_limbs = read_n_inputs(cursor, solver, px_nb)?;
    let py_nb = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let py_limbs = read_n_inputs(cursor, solver, py_nb)?;

    // T2 (scalar) field block
    let t2_nb_limbs = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let t2_nb_bits = fr_to_u64(NAME, &read_input(cursor, solver)?)? as u32;
    // We match on base field modulus for the three curves we support
    let _t2_modulus_limbs = read_n_inputs(cursor, solver, t2_nb_limbs)?;
    let s_nb = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let s_limbs = read_n_inputs(cursor, solver, s_nb)?;

    let px = recompose(&px_limbs, t1_nb_bits);
    let py = recompose(&py_limbs, t1_nb_bits);
    let s = recompose(&s_limbs, t2_nb_bits);

    let (qx, qy) = if base_modulus == SECP256R1_FP {
        scalar_mul::<ark_secp256r1::Config>(px, py, s)
    } else if base_modulus == SECP256K1_FP {
        scalar_mul::<ark_secp256k1::Config>(px, py, s)
    } else if base_modulus == BN254_FP {
        scalar_mul::<G1Config>(px, py, s)
    } else {
        return Err(HintError::UnsupportedCurve {
            hint_name: NAME,
            lambda_hex: format!("base_modulus={base_modulus:x}"),
        }
        .into());
    };

    let (start, _end) = cursor.read_pair()?;

    let nb_out = 2 * t1_nb_limbs;
    let mut out = Vec::with_capacity(nb_out);
    for (i, l) in decompose(qx, t1_nb_limbs).into_iter().enumerate() {
        out.push((start + i as u32, l));
    }
    for (i, l) in decompose(qy, t1_nb_limbs).into_iter().enumerate() {
        out.push((start + (t1_nb_limbs + i) as u32, l));
    }
    Ok(out)
}

/// Reconstruct an affine point and multiply by a scalar. `(0, 0)` is treated
/// as the point at infinity.
fn scalar_mul<C: SWCurveConfig>(px: Wide, py: Wide, s: Wide) -> (Wide, Wide)
where
    C::BaseField: PrimeField,
{
    if px == Wide::ZERO && py == Wide::ZERO {
        return (Wide::ZERO, Wide::ZERO);
    }
    let xf = C::BaseField::from_le_bytes_mod_order(&px.to_le_bytes());
    let yf = C::BaseField::from_le_bytes_mod_order(&py.to_le_bytes());
    let p = Affine::<C>::new_unchecked(xf, yf);
    let sf = C::ScalarField::from_le_bytes_mod_order(&s.to_le_bytes());
    let q = (p * sf).into_affine();
    point_to_wide(&q)
}

fn point_to_wide<A, F>(p: &A) -> (Wide, Wide)
where
    A: AffineRepr<BaseField = F>,
    F: PrimeField,
{
    if p.is_zero() {
        return (Wide::ZERO, Wide::ZERO);
    }
    let (x, y) = p.xy().expect("non-zero point has coords");
    (field_to_wide(&x), field_to_wide(&y))
}
