use crate::curve::Fr;
use ark_ff::{Field, Zero};

use crate::solver::InstrOutput;

use super::{
    Cursor, SolveError, Solver,
    linear_expr::{self, PartialEval},
};

/// Solves one `BlueprintGenericR1C` instruction.
///
/// Returns an optional `(wire_id, value)` pair (if not already solved)
/// and the row's full `(A·w, B·w, C·w)` evaluations.
pub(super) fn solve_generic_r1c(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
    instr_idx: u32,
    row_idx: u32,
) -> Result<InstrOutput, SolveError> {
    let _nb_inputs = cursor.read_u32()?;
    let len_a = cursor.read_u32()? as usize;
    let len_b = cursor.read_u32()? as usize;
    let len_c = cursor.read_u32()? as usize;

    let coeffs = &solver.r1cs.coefficients;
    let witness = &solver.witness;
    let solved = &solver.solved;
    let eval_a = linear_expr::eval_terms(cursor, len_a, witness, solved, coeffs)?;
    let eval_b = linear_expr::eval_terms(cursor, len_b, witness, solved, coeffs)?;
    let eval_c = linear_expr::eval_terms(cursor, len_c, witness, solved, coeffs)?;

    let n_unknowns = eval_a.n_unknowns + eval_b.n_unknowns + eval_c.n_unknowns;
    if n_unknowns > 1 {
        return Err(SolveError::TooManyUnknowns {
            instr_idx,
            count: n_unknowns,
        });
    }

    if n_unknowns == 0 {
        // Verification-only: assert A·B = C.
        if eval_a.known_sum * eval_b.known_sum != eval_c.known_sum {
            return Err(SolveError::ConstraintUnsatisfied { instr_idx });
        }
        return Ok(InstrOutput::R1c {
            write: None,
            row_idx,
            row: (eval_a.known_sum, eval_b.known_sum, eval_c.known_sum),
        });
    }

    let (write, row) = if let Some((coeff, wid)) = eval_a.unknown {
        //  value = (C/B − a) / coeff
        let value = solve_via_quotient(
            eval_c.known_sum,
            eval_b.known_sum,
            &eval_a,
            coeff,
            instr_idx,
        )?;
        let a_full = eval_a.known_sum + coeff * value;
        ((wid, value), (a_full, eval_b.known_sum, eval_c.known_sum))
    } else if let Some((coeff, wid)) = eval_b.unknown {
        //  value = (C/A − b) / coeff
        let value = solve_via_quotient(
            eval_c.known_sum,
            eval_a.known_sum,
            &eval_b,
            coeff,
            instr_idx,
        )?;
        let b_full = eval_b.known_sum + coeff * value;
        ((wid, value), (eval_a.known_sum, b_full, eval_c.known_sum))
    } else {
        let (coeff, wid) = eval_c.unknown.unwrap();
        // value = (A·B − c) / coeff
        let coeff_inv = coeff
            .inverse()
            .ok_or(SolveError::NoSolution { instr_idx })?;
        let value = (eval_a.known_sum * eval_b.known_sum - eval_c.known_sum) * coeff_inv;
        let c_full = eval_c.known_sum + coeff * value;
        ((wid, value), (eval_a.known_sum, eval_b.known_sum, c_full))
    };

    Ok(InstrOutput::R1c {
        write: Some(write),
        row_idx,
        row,
    })
}

/// Helper for the A- and B-side cases: solves `partial + coeff·x = num/denom`
/// for `x`. Handles `denom == 0` the way gnark does — any `x` satisfies the
/// constraint when `num == 0` too, so default the unknown to zero.
fn solve_via_quotient(
    num: Fr,
    denom: Fr,
    partial: &PartialEval,
    coeff: Fr,
    instr_idx: u32,
) -> Result<Fr, SolveError> {
    let coeff_inv = coeff
        .inverse()
        .ok_or(SolveError::NoSolution { instr_idx })?;
    if denom.is_zero() {
        if !num.is_zero() {
            return Err(SolveError::NoSolution { instr_idx });
        }
        return Ok(Fr::zero());
    }
    let denom_inv = denom
        .inverse()
        .ok_or(SolveError::NoSolution { instr_idx })?;
    Ok((num * denom_inv - partial.known_sum) * coeff_inv)
}
