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
mod r1c;
mod state;

use ark_bn254::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use rayon::prelude::*;

use crate::types::CommitmentInfo;
use crate::{GnarkWitness, PedersenProvingKey, R1CS, types::Blueprint};
use hints::{solve_generic_hint, solve_lookup};

use self::cursor::Cursor;
pub use self::state::Solver;
pub use error::SolveError;

/// Full solver output: the witness vector, constraint row evaluations
///  and the BSB22 artifacts.
pub struct SolveOutput {
    /// Full witness laid out as `[1, public..., secret..., internal...]`.
    pub witness: Vec<Fr>,
    pub a_evals: Vec<Fr>,
    pub b_evals: Vec<Fr>,
    pub c_evals: Vec<Fr>,
    /// Pedersen commitments, zero for circuits without commitments.
    pub commitments: Vec<G1Affine>,
    /// Private-committed witness values that fed each commitment
    pub committed_values: Vec<Vec<Fr>>,
}

/// One instruction's per-level output.
pub(super) enum InstrOutput {
    R1c {
        write: Option<(u32, Fr)>,
        row_idx: u32,
        row: (Fr, Fr, Fr),
    },
    Hint(Vec<(u32, Fr)>),
    Bsb22 {
        write: (u32, Fr),
        commitment_idx: usize,
        point: G1Affine,
        committed_values: Vec<Fr>,
    },
}

/// Returns full witness vector and per-row R1CS evaluations.
pub fn solve(
    r1cs: &R1CS,
    witness: &GnarkWitness,
    pk: Option<&[PedersenProvingKey]>,
) -> Result<SolveOutput, SolveError> {
    let solver = Solver::new(r1cs, witness, pk)?;
    run_solver(r1cs, solver)
}

fn run_solver(r1cs: &R1CS, mut solver: Solver<'_>) -> Result<SolveOutput, SolveError> {
    let n = r1cs.body.nb_constraints as usize;
    let mut a_evals = vec![Fr::zero(); n];
    let mut b_evals = vec![Fr::zero(); n];
    let mut c_evals = vec![Fr::zero(); n];

    let nb_commitments = match &r1cs.body.commitment_info {
        CommitmentInfo::Groth16(v) => v.len(),
        CommitmentInfo::Plonk(_) => 0,
    };
    let mut commitments = vec![G1Affine::zero(); nb_commitments];
    let mut committed_values = vec![Vec::<Fr>::new(); nb_commitments];

    for level in r1cs.levels.iter() {
        let results: Vec<InstrOutput> = level
            .par_iter()
            .map(|&instr_idx| run_instruction(&solver, instr_idx))
            .collect::<Result<Vec<_>, _>>()?;

        for output in results {
            handle_instruction_output(
                &mut solver,
                &mut a_evals,
                &mut b_evals,
                &mut c_evals,
                &mut commitments,
                &mut committed_values,
                output,
                r1cs.body.nb_constraints as usize,
            )?;
        }
    }

    Ok(SolveOutput {
        witness: solver.into_witness(),
        a_evals,
        b_evals,
        c_evals,
        commitments,
        committed_values,
    })
}

fn run_instruction(solver: &Solver<'_>, instr_idx: u32) -> Result<InstrOutput, SolveError> {
    let (bp, mut cursor, instr) = lookup_instruction(solver, instr_idx)?;

    match bp {
        Blueprint::GenericR1c => {
            r1c::solve_generic_r1c(solver, &mut cursor, instr_idx, instr.constraint_offset)
        }
        Blueprint::GenericHint => solve_generic_hint(solver, &mut cursor),
        Blueprint::LookupHint {
            entries_calldata, ..
        } => solve_lookup(solver, &mut cursor, entries_calldata, instr.wire_offset),
        Blueprint::BatchInverse(_) => Err(SolveError::BlueprintNotImplemented(
            "Inverse blueprint called, but is not supported via sunspot",
        )),
        _ => Err(SolveError::BlueprintNotImplemented(
            "Plonkish Constraints not supported",
        )),
    }
}

/// Return the solved wire(s) and constraint rows for each instruction output.
/// BSB22 outputs also return their Pedersen artifacts.
#[allow(clippy::too_many_arguments)]
fn handle_instruction_output(
    solver: &mut Solver<'_>,
    a_evals: &mut [Fr],
    b_evals: &mut [Fr],
    c_evals: &mut [Fr],
    commitments: &mut [G1Affine],
    committed_values: &mut [Vec<Fr>],
    output: InstrOutput,
    nb_constraints: usize,
) -> Result<(), SolveError> {
    match output {
        InstrOutput::R1c {
            write,
            row_idx,
            row: (a, b, c),
        } => {
            if let Some((w_id, value)) = write {
                solver.set_wire(w_id, value)?;
            }
            let r = row_idx as usize;
            if r >= nb_constraints {
                return Err(SolveError::ConstraintRowOutOfRange {
                    row: r,
                    total: nb_constraints,
                });
            }
            a_evals[r] = a;
            b_evals[r] = b;
            c_evals[r] = c;
        }
        InstrOutput::Hint(writes) => {
            for (w_id, value) in writes {
                solver.set_wire(w_id, value)?;
            }
        }
        InstrOutput::Bsb22 {
            write: (w_id, value),
            commitment_idx,
            point,
            committed_values: vals,
        } => {
            if commitment_idx >= commitments.len() {
                return Err(SolveError::CommitmentIndexOutOfRange {
                    idx: commitment_idx,
                    total: commitments.len(),
                });
            }
            commitments[commitment_idx] = point;
            committed_values[commitment_idx] = vals;
            solver.set_wire(w_id, value)?;
        }
    }
    Ok(())
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
    let (bp, mut cursor, instr) = lookup_instruction(solver, instr_idx)?;
    match bp {
        Blueprint::GenericR1c => {
            r1c::solve_generic_r1c(solver, &mut cursor, instr_idx, instr.constraint_offset)
                .map(|_| ())
        }
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
