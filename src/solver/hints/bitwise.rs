//! `std/math/uints.{and,or,xor}Hint`: 2 inputs, 1 output. Shared bitwise solver;
//! the op is selected by the per-hint wrapper.

use crate::curve::Fr;

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::{fr_to_u64, read_input};

const OR_HINT_NAME: &str = "orHint";
const XOR_HINT_NAME: &str = "xorHint";
const AND_HINT_NAME: &str = "andHint";

pub(super) fn solve_or(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<(u32, Fr), SolveError> {
    let or_fn = |a: u64, b: u64| a | b;
    solve_bitwise(solver, cursor, OR_HINT_NAME, or_fn)
}

pub(super) fn solve_xor(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<(u32, Fr), SolveError> {
    let xor_fn = |a: u64, b: u64| a ^ b;
    solve_bitwise(solver, cursor, XOR_HINT_NAME, xor_fn)
}

pub(super) fn solve_and(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<(u32, Fr), SolveError> {
    let and_fn = |a: u64, b: u64| a & b;
    solve_bitwise(solver, cursor, AND_HINT_NAME, and_fn)
}

fn solve_bitwise(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
    name: &'static str,
    bitwise_fn: fn(u64, u64) -> u64,
) -> Result<(u32, Fr), SolveError> {
    let nb_inputs = cursor.read_u32()?;
    if nb_inputs != 2 {
        return Err(HintError::HintInputShape {
            hint_name: name,
            expected: 2,
            actual: nb_inputs,
        }
        .into());
    }
    let a = fr_to_u64(name, &read_input(cursor, solver)?)?;
    let b = fr_to_u64(name, &read_input(cursor, solver)?)?;
    let (start, end) = cursor.read_pair()?;
    if end - start != 1 {
        return Err(HintError::HintOutputShape {
            hint_name: name,
            expected: 1,
            actual: end - start,
        }
        .into());
    }
    Ok((start, Fr::from(bitwise_fn(a, b))))
}
