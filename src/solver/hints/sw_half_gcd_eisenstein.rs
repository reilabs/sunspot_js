//! `std/algebra/emulated/sw_emulated.halfGCDEisenstein`
//! given a scalar `s` and the curve's GLV eigenvalue λ over the scalar field
//! `Fr`, returns a 4-component decomposition `(res[0], res[1])` ∈ ℤ[ω]² such
//! that the FakeGLV-with-endomorphism scalar mul can verify
//! `Q − [s]P = 0` via ω-multiplication tricks.
//!
//! Algorithm (mirrors `gnark-crypto/field/eisenstein.HalfGCD`):
//!   r := (V₁[0], V₁[1])                ← first row of the GLV lattice
//!   sp := SplitScalar(s, lattice)      ← (s₁, s₂) with s ≡ s₁ + λ·s₂ (mod r)
//!   s_eis := −(sp[0], sp[1])           ← packed as Eisenstein integer
//!   res  := HalfGCD(r, s_eis)          ← Euclidean half-GCD over ℤ[ω]
//!   output |res[0].A0|, |res[0].A1|, |res[1].A0|, |res[1].A1| (emulated)
//!          + 4 sign bits (native)
//!
//! Curve dispatch is by input eigenvalue. Today only BN254 is wired (its
//! GLV lattice is hardcoded below); other GLV curves can be added by dumping
//! their lattices via `gnark-crypto/ecc.PrecomputeLattice` and adding a match
//! arm.
//!
//! ## Native input layout (`Field[S].NewHintGeneric(halfGCDEisenstein, 4, 4,
//! nil, [_s, eigenvalue])`):
//!
//!   inputs[0..6]   = header [nbNativeIn=0, nbNativeOut=4, nbE1In=2,
//!                            nbE1Out=4, nbE2In=0, nbE2Out=0]
//!   inputs[6..8]   = (nbLimbs=4, nbBits=64)
//!   inputs[8..12]  = scalar-field modulus limbs
//!   inputs[12..]   = length-prefixed `s` and `λ`, in that order
//!
//! Outputs (20 Fr witness values):
//!   nativeOut[0..4]    = sign bits for res[0].A0, res[0].A1, res[1].A0, res[1].A1
//!   emuOut[0..4]       = |res[0].A0| limbs
//!   emuOut[4..8]       = |res[0].A1| limbs
//!   emuOut[8..12]      = |res[1].A0| limbs
//!   emuOut[12..16]     = |res[1].A1| limbs

use ark_bn254::Fr;
use ark_ff::{One, Zero};

use crate::{
    Solver,
    solver::{Cursor, SolveError, hints::glv_lattice::GLVLatticeCurve},
};

use super::{
    HINT_HEADER_LEN, HintError,
    bigint::{decompose, recompose},
    emulated_shared::{NB_BITS, NB_LIMBS},
    fr_to_u64, read_input, read_n_inputs,
};

// We only support this hint for this specific curve
type Curve = ark_bn254::g1::Config;

const NAME: &str = "sw_emulated.halfGCDEisenstein";

const EMU_HEADER_LEN: usize = 2 + NB_LIMBS;
const NB_NATIVE_OUT: usize = 4;
const NB_EMU_OUT: usize = 4;
const NB_OUTPUTS: usize = NB_NATIVE_OUT + NB_EMU_OUT * NB_LIMBS;

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

    let s_nb = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let s_limbs = read_n_inputs(cursor, solver, s_nb)?;
    let lambda_nb = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let lambda_limbs = read_n_inputs(cursor, solver, lambda_nb)?;

    let s = recompose(&s_limbs, NB_BITS);
    let lambda = recompose(&lambda_limbs, NB_BITS);

    if lambda != Curve::LAMBDA {
        return Err(HintError::UnsupportedCurve {
            hint_name: NAME,
            lambda_hex: format!("{lambda:x}"),
        }
        .into());
    }

    let outputs = Curve::half_gcd(s);

    let (start, end) = cursor.read_pair()?;
    let actual = (end - start) as usize;
    if actual != NB_OUTPUTS {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: NB_OUTPUTS as u32,
            actual: actual as u32,
        }
        .into());
    }

    let mut out = Vec::with_capacity(NB_OUTPUTS);
    for (i, e) in outputs.iter().enumerate() {
        let is_neg = bool::from(e.is_negative());
        out.push((
            start + i as u32,
            if is_neg { Fr::one() } else { Fr::zero() },
        ));
    }
    for (block_idx, e) in outputs.iter().enumerate() {
        let (abs, _) = e.abs_sign();
        let limbs = decompose(abs, NB_LIMBS);
        for (i, l) in limbs.into_iter().enumerate() {
            out.push((start + (NB_NATIVE_OUT + block_idx * NB_LIMBS + i) as u32, l));
        }
    }
    Ok(out)
}
