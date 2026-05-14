use ark_bn254::Fr;
use ark_ff::{Field, Zero};

use super::cursor::Cursor;
use super::error::SolveError;
use super::linear_expr::{self, PartialEval};
use super::state::Solver;

/// Solves one `BlueprintGenericR1C` instruction.
///
/// Pure compute: reads from `solver` but performs no writes. Returns the
/// `(wire_id, value)` pair to commit if the constraint had one unknown, or
/// `None` if the constraint was fully solved (verification-only branch).
/// The caller commits writes after the parallel level finishes — see
/// [`super::run_solver`].
pub(super) fn solve_generic_r1c(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
    instr_idx: u32,
) -> Result<Option<(u32, Fr)>, SolveError> {
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
        return Ok(None);
    }

    let (w_id, value) = if let Some((coeff, wid)) = eval_a.unknown {
        //  value = (C/B − a) / coeff
        let value = solve_via_quotient(
            eval_c.known_sum,
            eval_b.known_sum,
            &eval_a,
            coeff,
            instr_idx,
        )?;
        (wid, value)
    } else if let Some((coeff, wid)) = eval_b.unknown {
        //  value = (C/A − b) / coeff
        let value = solve_via_quotient(
            eval_c.known_sum,
            eval_a.known_sum,
            &eval_b,
            coeff,
            instr_idx,
        )?;
        (wid, value)
    } else {
        let (coeff, wid) = eval_c.unknown.unwrap();
        // value = (A·B − c) / coeff
        let coeff_inv = coeff
            .inverse()
            .ok_or(SolveError::NoSolution { instr_idx })?;
        let value = (eval_a.known_sum * eval_b.known_sum - eval_c.known_sum) * coeff_inv;
        (wid, value)
    };

    Ok(Some((w_id, value)))
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
