//! `internal/hints.Randomize`: 0 inputs, N outputs. Returns N uniformly random
//! field elements drawn from the OS CSPRNG, matching gnark's behavior.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::read_n_inputs;

const NAME: &str = "Randomize";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()?;
    if nb_inputs != 0 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 0,
            actual: nb_inputs,
        }
        .into());
    }
    let _ = read_n_inputs(cursor, solver, 0)?;
    let (start, end) = cursor.read_pair()?;

    let mut rng = OsRng;
    let out = (start..end).map(|wid| (wid, Fr::rand(&mut rng))).collect();
    Ok(out)
}
