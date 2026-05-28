//! `std/math/uints.toBytes`: 2 inputs (nbLimbs, val), nbLimbs outputs. Each
//! output is the i-th byte of `val` (little-endian: output 0 is the LSB).

use crate::curve::Fr;
use ark_ff::{BigInteger, PrimeField};

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::{fr_to_u64, read_input};

const NAME: &str = "toBytes";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()?;
    if nb_inputs != 2 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 2,
            actual: nb_inputs,
        }
        .into());
    }
    let nb_limbs = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let val = read_input(cursor, solver)?;

    let (start, end) = cursor.read_pair()?;
    let actual = (end - start) as usize;
    if actual != nb_limbs {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: nb_limbs as u32,
            actual: actual as u32,
        }
        .into());
    }

    let bytes = val.into_bigint().to_bytes_le();
    let out = (0..nb_limbs)
        .map(|i| {
            let byte = bytes.get(i).copied().unwrap_or(0);
            (start + i as u32, Fr::from(byte))
        })
        .collect();
    Ok(out)
}
