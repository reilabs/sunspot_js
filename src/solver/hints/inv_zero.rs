//! `constraint/solver.InvZeroHint`: 1 input, 1 output. Returns `1/x` for
//! non-zero `x`, else `0`. Mirrors gnark's built-in InvZeroHint.

use ark_bn254::Fr;
use ark_ff::{Field, Zero};

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::read_input;

const NAME: &str = "InvZeroHint";

pub(super) fn solve(solver: &Solver<'_>, cursor: &mut Cursor<'_>) -> Result<(u32, Fr), SolveError> {
    let nb_inputs = cursor.read_u32()?;
    if nb_inputs != 1 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 1,
            actual: nb_inputs,
        }
        .into());
    }
    let x = read_input(cursor, solver)?;
    let (start, end) = cursor.read_pair()?;
    if end - start != 1 {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: 1,
            actual: end - start,
        }
        .into());
    }
    let inv = if x.is_zero() {
        Fr::zero()
    } else {
        x.inverse().expect("non-zero inverse must exist")
    };
    Ok((start, inv))
}
