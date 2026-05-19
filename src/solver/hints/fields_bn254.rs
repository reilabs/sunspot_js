//! `std/algebra/emulated/fields_bn254.{divE2Hint, inverseE12Hint}`
//!
//! ## divE2Hint
//!
//! `UnwrapHint` shape: 4 emulated inputs (a.A0, a.A1, b.A0, b.A1), 2 emulated
//! outputs (c.A0, c.A1) where `c = a / b` in Fp²[u]/(u² + 1).
//!
//! ## inverseE12Hint
//!
//! Same wrapping, but with 12 inputs / 12 outputs. The catch is that gnark
//! stores each Fp² coefficient of Fp¹² in a *re-based* form aligned with
//! Fp⁶'s nonresidue `ξ = u + 9`: where ark-bn254 stores `(α, β)` for
//! `α + β·u`, gnark stores `(α − 9β, β)`. We convert in→bn254 by `α′ + 9β`,
//! invert via [`ark_bn254::Fq12::inverse`], and convert back via `α − 9β`.
//!
//! ## Native layout (per `Field[T].NewHint` / `UnwrapHint`)
//!
//!   inputs[0..6]   = header [nbNativeIn=0, nbNativeOut=0,
//!                            nbE1In=N_in, nbE1Out=N_out,
//!                            nbE2In=0, nbE2Out=0]
//!   inputs[6..8]   = (nbLimbs=4, nbBits=64)
//!   inputs[8..12]  = BN254 Fp modulus limbs
//!   inputs[12..]   = N_in length-prefixed emulated inputs
//!
//! Outputs: N_out × 4 Fp limbs, laid out as concatenated 4-limb blocks.

use ark_bn254::{Fq, Fq2, Fq6, Fq12};
use ark_ff::{Field, PrimeField};

use super::{
    HINT_HEADER_LEN, HintError,
    bigint::{Wide, decompose, field_to_wide},
    emulated_shared::{EMU_HEADER_LEN, NB_BITS, NB_LIMBS},
    fr_to_u64, read_input, read_n_inputs,
};
use crate::solver::{Cursor, SolveError, Solver};

/// Generic Fp¹² re-basing factor from gnark's Fp²-tower convention.
const NINE: u64 = 9;

// ── divE2Hint ───────────────────────────────────────────────────────────

const NAME_DIV_E2: &str = "fields_bn254.divE2Hint";

pub(super) fn solve_div_e2(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, ark_bn254::Fr)>, SolveError> {
    let inputs = read_unwrap_hint_inputs(solver, cursor, NAME_DIV_E2, 4)?;
    let a = fq2_from_inputs(&inputs, 0);
    let b = fq2_from_inputs(&inputs, 2);
    let c = a * b.inverse().expect("Fp² inverse exists");
    write_fq2_outputs(cursor, c, 1)
}

// ── inverseE12Hint ──────────────────────────────────────────────────────

const NAME_INV_E12: &str = "fields_bn254.inverseE12Hint";

pub(super) fn solve_inverse_e12(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, ark_bn254::Fr)>, SolveError> {
    let inputs = read_unwrap_hint_inputs(solver, cursor, NAME_INV_E12, 12)?;

    // gnark interleaves C0/C1 sub-fields in pairs and stores each Fp² as
    // `(α − 9β, β)`. Build an ark `Fq12` from the rebased values.
    let a = gnark_inputs_to_fq12(&inputs);
    let inv = a.inverse().expect("Fp¹² inverse exists");
    let limbs = fq12_to_gnark_outputs(inv);

    write_fp_limb_outputs(cursor, &limbs)
}

// ── shared helpers ──────────────────────────────────────────────────────

/// Read the standard `UnwrapHint` framing and return the N emulated-input Fp
/// values as `Wide`s. The header validates input count and length-prefix
/// shape; the emulated modulus is read but unused (we only ever target BN254
/// Fp here).
fn read_unwrap_hint_inputs(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
    hint_name: &'static str,
    nb_emu_in: usize,
) -> Result<Vec<Wide>, SolveError> {
    let nb_inputs = cursor.read_u32()? as usize;
    let min_inputs = HINT_HEADER_LEN + EMU_HEADER_LEN + nb_emu_in;
    if nb_inputs < min_inputs {
        return Err(HintError::HintInputShape {
            hint_name,
            expected: min_inputs as u32,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let _header = read_n_inputs(cursor, solver, HINT_HEADER_LEN)?;
    let _emu_header = read_n_inputs(cursor, solver, EMU_HEADER_LEN)?;
    let mut out = Vec::with_capacity(nb_emu_in);
    for _ in 0..nb_emu_in {
        let n = fr_to_u64(hint_name, &read_input(cursor, solver)?)? as usize;
        let limbs = read_n_inputs(cursor, solver, n)?;
        let mut acc = Wide::ZERO;
        for limb in limbs.iter().rev() {
            acc <<= NB_BITS;
            acc = acc.wrapping_add(&field_to_wide(limb));
        }
        out.push(acc);
    }
    Ok(out)
}

fn fq2_from_inputs(inputs: &[Wide], base: usize) -> Fq2 {
    Fq2::new(wide_to_fq(inputs[base]), wide_to_fq(inputs[base + 1]))
}

fn wide_to_fq(x: Wide) -> Fq {
    Fq::from_le_bytes_mod_order(&x.to_le_bytes())
}

fn write_fq2_outputs(
    cursor: &mut Cursor<'_>,
    c: Fq2,
    nb_emu_out: usize,
) -> Result<Vec<(u32, ark_bn254::Fr)>, SolveError> {
    let expected = nb_emu_out * 2 * NB_LIMBS;
    let limbs = [field_to_wide(&c.c0), field_to_wide(&c.c1)];
    let (start, end) = cursor.read_pair()?;
    let actual = (end - start) as usize;
    if actual != expected {
        return Err(HintError::HintOutputShape {
            hint_name: NAME_DIV_E2,
            expected: expected as u32,
            actual: actual as u32,
        }
        .into());
    }
    let mut out = Vec::with_capacity(expected);
    for (block_idx, w) in limbs.iter().enumerate() {
        for (i, l) in decompose(*w, NB_LIMBS).into_iter().enumerate() {
            out.push((start + (block_idx * NB_LIMBS + i) as u32, l));
        }
    }
    Ok(out)
}

fn write_fp_limb_outputs(
    cursor: &mut Cursor<'_>,
    limbs: &[Wide],
) -> Result<Vec<(u32, ark_bn254::Fr)>, SolveError> {
    let expected = limbs.len() * NB_LIMBS;
    let (start, end) = cursor.read_pair()?;
    let actual = (end - start) as usize;
    if actual != expected {
        return Err(HintError::HintOutputShape {
            hint_name: NAME_INV_E12,
            expected: expected as u32,
            actual: actual as u32,
        }
        .into());
    }
    let mut out = Vec::with_capacity(expected);
    for (block_idx, w) in limbs.iter().enumerate() {
        for (i, l) in decompose(*w, NB_LIMBS).into_iter().enumerate() {
            out.push((start + (block_idx * NB_LIMBS + i) as u32, l));
        }
    }
    Ok(out)
}

/// Rebuild `Fq12` from gnark's 12-input layout. Inputs are interleaved
/// `[C0.B0, C1.B0, C0.B1, C1.B1, C0.B2, C1.B2]` for the "real" parts
/// (indices 0..6) and the matching imaginary parts in 6..12. Each Fp² is
/// rebased as `α = α′ + 9β` (ark form) from `α′ = inputs[i], β = inputs[6+i]`
/// (gnark form).
fn gnark_inputs_to_fq12(inputs: &[Wide]) -> Fq12 {
    // For position k (0..6), pair up real input[k] with imag input[6+k]:
    let pair = |k: usize| {
        let beta = wide_to_fq(inputs[6 + k]);
        let alpha = wide_to_fq(inputs[k]) + beta * Fq::from(NINE);
        Fq2::new(alpha, beta)
    };
    let c0_b0 = pair(0);
    let c1_b0 = pair(1);
    let c0_b1 = pair(2);
    let c1_b1 = pair(3);
    let c0_b2 = pair(4);
    let c1_b2 = pair(5);

    let c0 = Fq6::new(c0_b0, c0_b1, c0_b2);
    let c1 = Fq6::new(c1_b0, c1_b1, c1_b2);
    Fq12::new(c0, c1)
}

/// Inverse of [`gnark_inputs_to_fq12`]: return 12 limb-wide values laid out
/// in gnark's order. For each Fp²-coordinate `(α, β)` we emit `α′ = α − 9β`
/// in the "real" slot and `β` in the "imag" slot.
fn fq12_to_gnark_outputs(c: Fq12) -> [Wide; 12] {
    let entries = [
        c.c0.c0, c.c1.c0, c.c0.c1, c.c1.c1, c.c0.c2, c.c1.c2, // 6 Fp² coords
    ];
    let mut out = [Wide::ZERO; 12];
    for (k, fq2) in entries.iter().enumerate() {
        // α′ = α − 9β
        let alpha_prime = fq2.c0 - fq2.c1 * Fq::from(NINE);
        out[k] = field_to_wide(&alpha_prime);
        out[6 + k] = field_to_wide(&fq2.c1);
    }
    out
}
