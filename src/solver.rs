//! R1CS witness solver.
//!
//! Ported from gnark's `constraint.Solver`: extends the partial witness
//! (public + secret inputs) into a full witness by executing levels of
//! instructions in topological order and invoking each instruction's
//! blueprint solver.

mod cursor;
mod error;
mod linear_expr;
mod r1c;
mod state;

use ark_bn254::Fr;

use crate::types::Blueprint;
use crate::{GnarkWitness, R1CS};

pub use error::SolveError;

use self::cursor::Cursor;
pub use self::state::Solver;

/// Solves the constraint system, returning the full witness vector laid out
/// as `[1, public..., secret..., internal...]`.
pub fn solve(r1cs: &R1CS, witness: &GnarkWitness) -> Result<Vec<Fr>, SolveError> {
    let solver = Solver::new(r1cs, witness)?;

    run_solver(r1cs, solver)
}

fn run_solver(r1cs: &R1CS, mut solver: Solver<'_>) -> Result<Vec<Fr>, SolveError> {
    for level in r1cs.levels.iter() {
        for &instr_idx in level {
            run_instruction(&mut solver, instr_idx)?;
        }
    }

    Ok(solver.into_witness())
}

fn run_instruction(solver: &mut Solver<'_>, instr_idx: u32) -> Result<(), SolveError> {
    let instr = solver
        .r1cs
        .instructions
        .get(instr_idx as usize)
        .copied()
        .ok_or(SolveError::InstructionOutOfRange {
            instr_idx,
            total: solver.r1cs.instructions.len(),
        })?;

    let bp = solver
        .r1cs
        .body
        .blueprints
        .get(instr.blueprint_id as usize)
        .ok_or(SolveError::BlueprintOutOfRange {
            instr_idx,
            bp_id: instr.blueprint_id,
            total: solver.r1cs.body.blueprints.len(),
        })?;

    let mut cursor = Cursor::new(&solver.r1cs.calldata, instr.start_call_data as usize)?;

    match bp {
        Blueprint::GenericR1c => r1c::solve_generic_r1c(solver, &mut cursor, instr_idx),
        Blueprint::GenericHint => Err(SolveError::BlueprintNotImplemented("generic hint")),
        Blueprint::LookupHint { .. } => Err(SolveError::BlueprintNotImplemented("lookup hint")),
        Blueprint::BatchInverse(_) => Err(SolveError::BlueprintNotImplemented("batch inverse")),
        _ => Err(SolveError::BlueprintNotImplemented(
            "Plonkish Constraints not supported",
        )),
    }
}

/// Asserts that a presolved witness satisfies every R1C constraint. With all
/// wires already solved, each blueprint solver hits its `n_unknowns == 0`
/// branch and checks `A·B = C` in place of assigning a wire — so re-running
/// the solver is exactly a constraint check.
pub fn verify_witness(r1cs: &R1CS, witness: Vec<Fr>) -> Result<(), SolveError> {
    let solver = Solver::from_full_witness(r1cs, witness)?;
    for (wid, &is_solved) in solver.solved.iter().enumerate() {
        // This should not happen because `Solver::from_full_witness`
        // initialises all solved as true
        assert!(is_solved, "verify_solving: wire {wid} is not solved");
    }
    run_solver(r1cs, solver)?;
    Ok(())
}
