//! Sunspot-local `splitInto64BitLimbsHint`: 1 input, 2 outputs. Outputs
//! `[v mod 2^64, v >> 64]`.

use ark_bn254::Fr;
use ark_ff::PrimeField;

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::read_input;

const NAME: &str = "splitInto64BitLimbsHint";

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
    let v = read_input(cursor, solver)?;

    let (start, end) = cursor.read_pair()?;
    if end - start != 2 {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: 2,
            actual: end - start,
        }
        .into());
    }

    // Inputs to this hint must fit in 128 bits, so limbs 2 and 3 must be zero.
    let bigint = v.into_bigint().0;
    if bigint[2] != 0 || bigint[3] != 0 {
        return Err(HintError::HintInputNotUint128 { hint_name: NAME }.into());
    }
    Ok(vec![
        (start, Fr::from(bigint[0])),
        (start + 1, Fr::from(bigint[1])),
    ])
}
