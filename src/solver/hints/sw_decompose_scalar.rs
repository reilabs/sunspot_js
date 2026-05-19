//! `std/algebra/emulated/sw_emulated.decomposeScalarG1`: GLV decomposition of
//! an *emulated* scalar `s` into two sub-scalars `s1, s2` such that
//! `s = s1 + λ·s2 (mod r)`, where `λ` is the eigenvalue of the curve's
//! endomorphism. Outputs `|s1|`, `|s2|` as emulated values plus per-component
//! sign bits as native values, so that in-circuit the points (not the
//! sub-scalars) get conditionally negated.
//!
//! Native input layout (from `Field[S].NewHintGeneric` →
//! `wrapGenericHintInputs`):
//!   inputs[0..6]   = header [nbNativeIn=0, nbNativeOut=2,
//!                            nbE1In=2, nbE1Out=2, nbE2In=0, nbE2Out=0]
//!   inputs[6..8]   = (nbLimbs, nbBits) for the emulated modulus (4, 64)
//!   inputs[8..12]  = scalar-field modulus limbs
//!   inputs[12]     = nb_limbs for s
//!   inputs[..]     = s limbs
//!   inputs[..]     = nb_limbs for λ followed by λ's limbs
//!
//! Outputs (10 Fr witness values, in order):
//!   2 native sign bits (s1_sign, s2_sign) followed by 8 emulated limbs
//!   ([|s1|_limbs(4), |s2|_limbs(4)]).
//!
//! Curve dispatch: the precomputed GLV lattice depends on `r` and `λ`. We
//! recognise secp256k1 by the input λ value and reject everything else.

use ark_bn254::Fr;
use ark_ff::{One, Zero};

use crate::{
    Solver,
    solver::{Cursor, SolveError, hints::glv_lattice::GLVLatticeCurve},
};

use super::{
    HINT_HEADER_LEN, HintError,
    bigint::{decompose, recompose},
    emulated_shared::{EMU_HEADER_LEN, NB_BITS, NB_LIMBS},
    fr_to_u64, read_input, read_n_inputs,
};

const NAME: &str = "sw_emulated.decomposeScalarG1";

type Curve = ark_secp256k1::Config;

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
    let _emu_header = read_n_inputs(cursor, solver, EMU_HEADER_LEN)?;

    // The emulated inputs are length-prefixed in the gnark wrapper, so we
    // read each (nb_limbs, limbs…) pair off the cursor explicitly.
    let s_nb = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let s_limbs = read_n_inputs(cursor, solver, s_nb)?;
    let lambda_nb = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let lambda_limbs = read_n_inputs(cursor, solver, lambda_nb)?;

    let total_consumed = HINT_HEADER_LEN + EMU_HEADER_LEN + 1 + s_nb + 1 + lambda_nb;
    if total_consumed != nb_inputs {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: total_consumed as u32,
            actual: nb_inputs as u32,
        }
        .into());
    }

    let s = recompose(&s_limbs, NB_BITS);
    let lambda = recompose(&lambda_limbs, NB_BITS);

    if lambda != Curve::LAMBDA {
        return Err(HintError::UnsupportedCurve {
            hint_name: NAME,
            lambda_hex: format!("{lambda:x}"),
        }
        .into());
    }

    let (sp0, sp1) = Curve::split_scalar(s);
    let (out0_abs, out0_sign) = sp0.abs_sign();
    let (out1_abs, out1_sign) = sp1.abs_sign();
    let out0_sign = bool::from(out0_sign);
    let out1_sign = bool::from(out1_sign);

    let (start, end) = cursor.read_pair()?;
    let actual = (end - start) as usize;
    let expected = 2 + 2 * NB_LIMBS;
    if actual != expected {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: expected as u32,
            actual: actual as u32,
        }
        .into());
    }

    let mut out = Vec::with_capacity(expected);
    out.push((start, if out0_sign { Fr::one() } else { Fr::zero() }));
    out.push((start + 1, if out1_sign { Fr::one() } else { Fr::zero() }));
    for (i, l) in decompose(out0_abs, NB_LIMBS).into_iter().enumerate() {
        out.push((start + 2 + i as u32, l));
    }
    for (i, l) in decompose(out1_abs, NB_LIMBS).into_iter().enumerate() {
        out.push((start + 2 + NB_LIMBS as u32 + i as u32, l));
    }
    Ok(out)
}
