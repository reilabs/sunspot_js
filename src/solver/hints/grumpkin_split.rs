//! `sunspot/go/sw-grumpkin.decomposeScalar`: GLV decomposition of a native
//! BN254-Fr scalar `s` into two BN254-Fp emulated outputs `(s1, s2)` such
//! that `s1 + λ · s2 ≡ s (mod r_grumpkin)`, where `r_grumpkin = p_bn254`.
//!
//! Native input layout (per `emulated.NewHintWithNativeInput` /
//! `wrapGenericHintInputs`):
//!   inputs[0..6]   = header [nbNativeIn=1, nbNativeOut=0, nbE1In=0,
//!                            nbE1Out=2, nbE2In=0, nbE2Out=0]
//!   inputs[6]      = native scalar `s`
//!   inputs[7..13]  = emulated-modulus header (nbLimbs=4, nbBits=64) followed
//!                    by 4 modulus limbs — read but unused; we know we're
//!                    decomposing for BN254-Fp.
//!
//! Outputs: 8 Fr witness values laid out as `[s1_limbs(4), s2_limbs(4)]`.
use ark_bn254::Fr;

use super::{
    HINT_HEADER_LEN, HintError,
    bigint::{decompose, field_to_wide},
    emulated_shared::NB_LIMBS,
    glv_lattice::GLVLatticeCurve,
    read_input, read_n_inputs,
};

use crate::{
    Solver,
    solver::{Cursor, SolveError},
};

const NAME: &str = "sw-grumpkin.decomposeScalar";

const NB_NATIVE_IN: usize = 1;
const EMULATED_HEADER_LEN: usize = 2 + NB_LIMBS; // nbLimbs, nbBits, modulus limbs
const TOTAL_INPUTS: usize = HINT_HEADER_LEN + NB_NATIVE_IN + EMULATED_HEADER_LEN;
const NB_OUTPUTS: usize = NB_LIMBS * 2;

type Curve = ark_grumpkin::GrumpkinConfig;

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()? as usize;
    if nb_inputs != TOTAL_INPUTS {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: TOTAL_INPUTS as u32,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let _header = read_n_inputs(cursor, solver, HINT_HEADER_LEN)?;
    let s = read_input(cursor, solver)?;
    // Skip the emulated-field header (nbLimbs, nbBits, modulus limbs); we
    // already know we're operating in BN254 Fp.
    let _emu = read_n_inputs(cursor, solver, EMULATED_HEADER_LEN)?;

    let (start, end) = cursor.read_pair()?;
    let actual_outputs = (end - start) as usize;
    if actual_outputs != NB_OUTPUTS {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: NB_OUTPUTS as u32,
            actual: actual_outputs as u32,
        }
        .into());
    }

    let (sp0, sp1) = Curve::split_scalar(field_to_wide(&s));
    let (out0, _) = sp0.abs_sign();
    let (out1, _) = sp1.abs_sign();

    let mut out = Vec::with_capacity(NB_OUTPUTS);
    for (i, l) in decompose(out0, NB_LIMBS).into_iter().enumerate() {
        out.push((start + i as u32, l));
    }
    for (i, l) in decompose(out1, NB_LIMBS).into_iter().enumerate() {
        out.push((start + (NB_LIMBS + i) as u32, l));
    }
    Ok(out)
}
