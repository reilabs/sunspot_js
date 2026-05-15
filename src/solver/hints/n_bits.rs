//! `std/math/bits.nBits`: 1 input (`val`), N outputs — each output is bit `i`
//! of `val` (LSB first).
use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::read_input;

const NAME: &str = "nBits";

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
    let val = read_input(cursor, solver)?;
    let (start, end) = cursor.read_pair()?;
    let n = (end - start) as usize;

    let bits = val.into_bigint().to_bits_le();
    let zero = Fr::zero();
    let one = Fr::one();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let bit = bits.get(i).copied().unwrap_or(false);
        out.push((start + i as u32, if bit { one } else { zero }));
    }
    Ok(out)
}
