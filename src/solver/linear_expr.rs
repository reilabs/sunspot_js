use crate::curve::Fr;
use ark_ff::Zero;

use super::cursor::Cursor;
use super::error::SolveError;

/// Linear-expression evaluation result.
///
/// The R1C solver rejects any constraint with more than one unknown across
/// A/B/C, so we only ever need to remember the first one we see — but we still
/// count the rest so the caller can report `TooManyUnknowns` accurately.
pub(super) struct PartialEval {
    /// Σ coefficients[t.cid] · witness[t.wid] over terms with a solved wire.
    pub known_sum: Fr,
    /// `(coefficient, wire_id)` of the first unsolved term, if any.
    pub unknown: Option<(Fr, u32)>,
    /// Total number of unsolved terms encountered.
    pub n_unknowns: usize,
}

/// Streams `n` packed `(coeff_id u32, wire_id u32)` term pairs from the
/// cursor, evaluating solved wires into `known_sum` and capturing the first
/// unsolved term in `unknown`.
pub(super) fn eval_terms(
    cursor: &mut Cursor<'_>,
    n: usize,
    witness: &[Fr],
    solved: &[bool],
    coeffs: &[Fr],
) -> Result<PartialEval, SolveError> {
    let mut known_sum = Fr::zero();
    let mut unknown: Option<(Fr, u32)> = None;
    let mut n_unknowns = 0;
    for _ in 0..n {
        let (coeff_id, wire_id) = cursor.read_pair()?;
        let coeff = *coeffs
            .get(coeff_id as usize)
            .ok_or(SolveError::CoeffOutOfRange {
                cid: coeff_id,
                total: coeffs.len(),
            })?;
        let value = *witness
            .get(wire_id as usize)
            .ok_or(SolveError::WireOutOfRange {
                wid: wire_id,
                total: witness.len(),
            })?;
        if solved[wire_id as usize] {
            known_sum += coeff * value;
        } else {
            if unknown.is_none() {
                unknown = Some((coeff, wire_id));
            }
            n_unknowns += 1;
        }
    }
    Ok(PartialEval {
        known_sum,
        unknown,
        n_unknowns,
    })
}
