//! `Blueprint::LookupHint` solver — mirrors gnark's `BlueprintLookupHint[E].Solve`.
//!
//! Per-instruction frame: `[total, nb_entries, nb_inputs, queries…]`, each query a
//! length-prefixed LE evaluating to a table index. The table itself lives on the
//! blueprint as `entries_calldata` (a stream of length-prefixed LEs), shared across
//! instructions with `nb_entries` choosing the live prefix. Outputs go to consecutive
//! wires starting at `wire_offset`.

use super::{error::HintError, fr_to_u64, read_input};
use crate::solver::{Cursor, InstrOutput, SolveError, Solver};

const NAME: &str = "LookupHint";

pub(in crate::solver) fn solve_lookup(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
    entries_calldata: &[u32],
    wire_offset: u32,
) -> Result<InstrOutput, SolveError> {
    let _total = cursor.read_u32()?;
    let nb_entries = cursor.read_u32()? as usize;
    let nb_inputs = cursor.read_u32()? as usize;

    // Evaluate each query's linear expression to a field element (the
    // table index).
    let mut queries = Vec::with_capacity(nb_inputs);
    for _ in 0..nb_inputs {
        queries.push(read_input(cursor, solver)?);
    }

    // One linear scan of the entries stream to build offsets for the live
    // prefix. Each LE is `n, (cid, wid)*n`, so its length is `1 + 2n` words.
    let mut entry_offsets = Vec::with_capacity(nb_entries);
    let mut pos = 0usize;
    for _ in 0..nb_entries {
        let n = *entries_calldata
            .get(pos)
            .ok_or(SolveError::CalldataTruncated {
                offset: pos,
                needed: 1,
            })? as usize;
        entry_offsets.push(pos);
        pos += 1 + 2 * n;
        if pos > entries_calldata.len() {
            return Err(SolveError::CalldataTruncated {
                offset: pos,
                needed: pos - entries_calldata.len(),
            });
        }
    }

    let mut out = Vec::with_capacity(nb_inputs);
    for (i, q) in queries.into_iter().enumerate() {
        let idx = fr_to_u64(NAME, &q)? as usize;
        if idx >= nb_entries {
            return Err(HintError::LookupIndexOutOfRange {
                idx,
                total: nb_entries,
            }
            .into());
        }
        let mut entry_cursor = Cursor::new(entries_calldata, entry_offsets[idx])?;
        let value = read_input(&mut entry_cursor, solver)?;
        out.push((wire_offset + i as u32, value));
    }

    Ok(InstrOutput::Hint(out))
}
