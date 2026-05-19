use thiserror::Error;

use super::hints::error::HintError;

#[derive(Debug, Error)]
pub enum SolveError {
    #[error(transparent)]
    Hint(#[from] HintError),

    #[error("{label} witness length mismatch: got {actual}, expected {expected}")]
    WitnessLengthMismatch {
        label: &'static str,
        actual: usize,
        expected: usize,
    },

    #[error("wire id {wid} out of range (witness has {total} wires)")]
    WireOutOfRange { wid: u32, total: usize },

    #[error("coefficient id {cid} out of range (table has {total} coefficients)")]
    CoeffOutOfRange { cid: u32, total: usize },

    #[error("instruction {instr_idx} out of range (only {total} instructions)")]
    InstructionOutOfRange { instr_idx: u32, total: usize },

    #[error(
        "instruction {instr_idx} references blueprint {bp_id} (only {total} blueprints declared)"
    )]
    BlueprintOutOfRange {
        instr_idx: u32,
        bp_id: u32,
        total: usize,
    },

    #[error("calldata truncated: needed {needed} more word(s) at offset {offset}")]
    CalldataTruncated { offset: usize, needed: usize },

    #[error("instruction {instr_idx}: {count} unsolved wires (expected 0 or 1)")]
    TooManyUnknowns { instr_idx: u32, count: usize },

    #[error("instruction {instr_idx}: constraint A·B = C not satisfied")]
    ConstraintUnsatisfied { instr_idx: u32 },

    #[error("instruction {instr_idx}: no solution for unknown wire")]
    NoSolution { instr_idx: u32 },

    #[error("wire {wid} re-assigned (was already solved)")]
    WireReassigned { wid: u32 },

    #[error("blueprint not yet implemented: {0}")]
    BlueprintNotImplemented(&'static str),
}
