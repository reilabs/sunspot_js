//! `std/rangecheck.DecomposeHint`: 3 inputs (varSize, limbSize, val), N
//! outputs where N = ceil(varSize / limbSize). Each output is one
//! `limbSize`-bit limb of `val` (least-significant limb first).

use crate::curve::Fr;
use ark_ff::{BigInteger, PrimeField};

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::{fr_to_u64, read_input};

const NAME: &str = "DecomposeHint";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()?;
    if nb_inputs != 3 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 3,
            actual: nb_inputs,
        }
        .into());
    }
    let var_size = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let limb_size = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let val = read_input(cursor, solver)?;

    let (start, end) = cursor.read_pair()?;
    let nb_limbs = var_size.div_ceil(limb_size);
    let actual = (end - start) as usize;
    if actual != nb_limbs {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: nb_limbs as u32,
            actual: actual as u32,
        }
        .into());
    }

    // BN254 Fr fits in 254 bits = 4 u64 limbs. limb_size is a small power of
    // two width chosen by the rangechecker (e.g. 8/16), so a per-bit shift is
    // simplest and within budget.
    let bigint = val.into_bigint();
    let bits = bigint.to_bits_le();

    let mut out = Vec::with_capacity(nb_limbs);
    for i in 0..nb_limbs {
        let bit_lo = i * limb_size;
        let bit_hi = (bit_lo + limb_size).min(bits.len());
        let mut limb: u128 = 0;
        for (j, &b) in bits[bit_lo..bit_hi].iter().enumerate() {
            if b {
                limb |= 1u128 << j;
            }
        }
        // limb_size is bounded by the rangechecker heuristic (≤ 17 in
        // practice), so `limb` always fits in a u128 → Fr.
        out.push((start + i as u32, Fr::from(limb)));
    }
    Ok(out)
}
