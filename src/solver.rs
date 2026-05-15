//! R1CS witness solver.
//!
//! Ported from gnark's `constraint.Solver`: extends the partial witness
//! (public + secret inputs) into a full witness by executing levels of
//! instructions in topological order and invoking each instruction's
//! blueprint solver.

mod cursor;
mod error;
mod hints;
mod linear_expr;
mod lookup;
mod r1c;
mod state;

use ark_bn254::Fr;
use rayon::prelude::*;

use crate::types::Blueprint;
use crate::{GnarkWitness, PedersenProvingKey, R1CS};

pub use error::SolveError;

use self::cursor::Cursor;
pub use self::state::Solver;

/// Solves the constraint system, returning the full witness vector laid out
/// as `[1, public..., secret..., internal...]`.
pub fn solve(
    r1cs: &R1CS,
    witness: &GnarkWitness,
    pk: Option<&[PedersenProvingKey]>,
) -> Result<Vec<Fr>, SolveError> {
    let solver = Solver::new(r1cs, witness, pk)?;
    run_solver(r1cs, solver)
}

fn run_solver(r1cs: &R1CS, mut solver: Solver<'_>) -> Result<Vec<Fr>, SolveError> {
    for level in r1cs.levels.iter() {
        let writes: Vec<Vec<(u32, Fr)>> = level
            .par_iter()
            .map(|&instr_idx| run_instruction(&solver, instr_idx))
            .collect::<Result<Vec<_>, _>>()?;

        for (w_id, value) in writes.into_iter().flatten() {
            solver.set_wire(w_id, value)?;
        }
    }

    Ok(solver.into_witness())
}

fn run_instruction(solver: &Solver<'_>, instr_idx: u32) -> Result<Vec<(u32, Fr)>, SolveError> {
    let (bp, mut cursor, _instr) = lookup_instruction(solver, instr_idx)?;

    match bp {
        Blueprint::GenericR1c => r1c::solve_generic_r1c(solver, &mut cursor, instr_idx)
            .map(|w| w.map(|p| vec![p]).unwrap_or_default()),
        Blueprint::GenericHint => Err(SolveError::BlueprintNotImplemented("generic hint")),
        Blueprint::LookupHint { .. } => Err(SolveError::BlueprintNotImplemented("lookup hint")),
        Blueprint::BatchInverse(_) => Err(SolveError::BlueprintNotImplemented("batch inverse")),
        _ => Err(SolveError::BlueprintNotImplemented(
            "Plonkish Constraints not supported",
        )),
    }
}

/// Asserts that a presolved witness satisfies every R1C constraint.
pub fn verify_witness(r1cs: &R1CS, witness: Vec<Fr>) -> Result<(), SolveError> {
    let solver = Solver::from_full_witness(r1cs, witness)?;
    for level in r1cs.levels.iter() {
        level
            .par_iter()
            .try_for_each(|&instr_idx| verify_instruction(&solver, instr_idx))?;
    }
    Ok(())
}

/// Only runs algebraic instructions
/// Meant to be used only to verify correctness of presolved witnesses.
fn verify_instruction(solver: &Solver<'_>, instr_idx: u32) -> Result<(), SolveError> {
    let (bp, mut cursor, _) = lookup_instruction(solver, instr_idx)?;
    match bp {
        Blueprint::GenericR1c => r1c::solve_generic_r1c(solver, &mut cursor, instr_idx).map(|_| ()),
        _ => Ok(()),
    }
}

/// Resolves an instruction index to its blueprint, a cursor positioned at
/// the start of its calldata, and the packed instruction itself.
fn lookup_instruction<'a>(
    solver: &'a Solver<'_>,
    instr_idx: u32,
) -> Result<(&'a Blueprint, Cursor<'a>, crate::types::PackedInstruction), SolveError> {
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

    let cursor = Cursor::new(&solver.r1cs.calldata, instr.start_call_data as usize)?;
    Ok((bp, cursor, instr))
}
