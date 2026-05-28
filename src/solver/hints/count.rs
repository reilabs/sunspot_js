//! `std/internal/logderivarg.countHint`: builds a histogram of how often each
//! table row is queried.
//!
//! Inputs (in order):
//!   - nbTable: u64
//!   - nbRow:   u64 (row width — number of field elements per entry)
//!   - nbTable rows of nbRow Fr's: the table entries
//!   - nbQueries rows of nbRow Fr's: the queries (nbQueries derived from
//!     remaining input count)
//!
//! Outputs: nbTable Fr's — for each table row, how many queries hit it.

use std::collections::HashMap;

use crate::curve::Fr;
use ark_ff::{BigInteger, PrimeField};

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::{fr_to_u64, read_input};

const NAME: &str = "countHint";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()? as usize;
    if nb_inputs < 3 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 3,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let nb_table = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let nb_row = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let remaining = nb_inputs - 2;
    if nb_row == 0
        || remaining < nb_table * nb_row
        || !(remaining - nb_table * nb_row).is_multiple_of(nb_row)
    {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: (2 + nb_table * nb_row) as u32,
            actual: nb_inputs as u32,
        }
        .into());
    }
    let nb_queries = (remaining - nb_table * nb_row) / nb_row;

    let mut table = Vec::with_capacity(nb_table);
    for _ in 0..nb_table {
        let mut row = Vec::with_capacity(nb_row);
        for _ in 0..nb_row {
            row.push(read_input(cursor, solver)?);
        }
        table.push(row);
    }
    let mut queries = Vec::with_capacity(nb_queries);
    for _ in 0..nb_queries {
        let mut row = Vec::with_capacity(nb_row);
        for _ in 0..nb_row {
            row.push(read_input(cursor, solver)?);
        }
        queries.push(row);
    }

    let (start, end) = cursor.read_pair()?;
    let actual = (end - start) as usize;
    if actual != nb_table {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: nb_table as u32,
            actual: actual as u32,
        }
        .into());
    }

    let mut histo: HashMap<Vec<u8>, (usize, u64)> = HashMap::with_capacity(nb_table);
    for (idx, row) in table.iter().enumerate() {
        let key = key_for_row(row);
        if histo.insert(key, (idx, 0)).is_some() {
            return Err(HintError::HintInputShape {
                hint_name: NAME,
                expected: 0, // sentinel "duplicate table row"
                actual: idx as u32,
            }
            .into());
        }
    }
    for row in &queries {
        let key = key_for_row(row);
        let Some(entry) = histo.get_mut(&key) else {
            return Err(HintError::HintInputShape {
                hint_name: NAME,
                expected: 0, // sentinel "query not in table"
                actual: u32::MAX,
            }
            .into());
        };
        entry.1 += 1;
    }

    let mut counts = vec![0u64; nb_table];
    for (_, (idx, count)) in histo {
        counts[idx] = count;
    }

    let mut out = Vec::with_capacity(nb_table);
    for (i, c) in counts.into_iter().enumerate() {
        out.push((start + i as u32, Fr::from(c)));
    }
    Ok(out)
}

fn key_for_row(row: &[Fr]) -> Vec<u8> {
    let mut key = Vec::with_capacity(row.len() * 32);
    for f in row {
        key.extend_from_slice(&f.into_bigint().to_bytes_be());
    }
    key
}
