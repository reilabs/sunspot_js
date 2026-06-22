//! `github.com/reilabs/sunspot/go/sw-grumpkin.decompose`: 1 input (`s`), 4 outputs — the four
//! 64-bit little-endian limbs of `s`. Mirrors gnark's per-circuit helper that
//! cracks a native scalar into limbs so it can be re-bound as an
//! `Element[BN254Fp]` for the GLV equality check.

use crate::curve::Fr;
use ark_ff::PrimeField;

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::read_input;

const NAME: &str = "sw-grumpkin.decompose";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()?;
    if nb_inputs != 1 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 1,
            actual: nb_inputs,
        }
        .into());
    }
    let s = read_input(cursor, solver)?;
    let (start, end) = cursor.read_pair()?;
    if end - start != 4 {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: 4,
            actual: end - start,
        }
        .into());
    }
    let limbs = s.into_bigint().0; // [u64; 4], little-endian
    Ok((0..4)
        .map(|i| (start + i as u32, Fr::from(limbs[i])))
        .collect())
}
