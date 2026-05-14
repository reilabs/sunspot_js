use ark_bn254::Fr;
use ark_ff::Zero;

use super::cursor::Cursor;
use super::error::SolveError;

/// One `(coefficient_id, wire_id)` entry in a packed linear expression.
#[derive(Debug, Clone, Copy)]
pub(super) struct Term {
    pub coeff_id: u32,
    pub wire_id: u32,
}

/// Reads `n` packed `(coeff_id u32, wire_id u32)` term pairs. The term count
/// is *not* part of the linear-expression body in gnark's `CompressR1C`
/// encoding — it lives in the instruction header alongside the L/R/O lengths.
pub(super) fn read_terms(cursor: &mut Cursor<'_>, n: usize) -> Result<Vec<Term>, SolveError> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let (coeff_id, wire_id) = cursor.read_pair()?;
        out.push(Term { coeff_id, wire_id });
    }
    Ok(out)
}

/// Linear-expression evaluation result with unsolved terms held aside so the
/// caller can solve for them.
pub(super) struct PartialEval {
    /// Σ coefficients[t.cid] · witness[t.wid] over terms with a solved wire.
    pub known_sum: Fr,
    /// `(coefficient, wire_id)` for each unsolved term, in encounter order.
    pub unknowns: Vec<(Fr, u32)>,
}

/// Walks `terms`, evaluating solved wires into `known_sum` and holding the
/// rest aside in `unknowns`. Returns errors for out-of-range wire/coeff ids.
pub(super) fn partial_eval(
    terms: &[Term],
    witness: &[Fr],
    solved: &[bool],
    coeffs: &[Fr],
) -> Result<PartialEval, SolveError> {
    let mut known_sum = Fr::zero();
    let mut unknowns = Vec::new();
    for term in terms {
        let wid = term.wire_id as usize;
        let cid = term.coeff_id as usize;
        let coeff = *coeffs.get(cid).ok_or(SolveError::CoeffOutOfRange {
            cid: term.coeff_id,
            total: coeffs.len(),
        })?;
        let value = *witness.get(wid).ok_or(SolveError::WireOutOfRange {
            wid: term.wire_id,
            total: witness.len(),
        })?;
        if solved[wid] {
            known_sum += coeff * value;
        } else {
            unknowns.push((coeff, term.wire_id));
        }
    }
    Ok(PartialEval {
        known_sum,
        unknowns,
    })
}
