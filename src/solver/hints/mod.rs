//! Hint dispatcher for `BlueprintGenericHint` instructions.
//!
//! Calldata layout (per `constraint.BlueprintGenericHint.CompressHint`):
//!   [0]     total length (we stream, so unused)
//!   [1]     hint id (FNV-1a-32 of the fully qualified gnark hint name)
//!   [2]     nb_inputs
//!   [3..]   nb_inputs linear expressions: (n, cid_0, vid_0, ..., cid_{n-1}, vid_{n-1})
//!   [..]    output_start, output_end — output wire range

use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};

use super::cursor::Cursor;
use super::error::SolveError;
use super::state::Solver;
use error::HintError;

mod bigint;
mod bitwise;
mod bsb22;
mod count;
mod decompose;
mod eisenstein_integers;
mod emulated_div;
mod emulated_mul;
mod emulated_shared;
pub(super) mod error;
mod fields_bn254;
mod glv_lattice;
mod grumpkin_decompose;
mod grumpkin_split;
mod inv_zero;
mod n_bits;
mod partition;
mod poly_mv;
mod randomize;
mod split_to_64;
mod sw_decompose_scalar;
mod sw_half_gcd;
mod sw_half_gcd_eisenstein;
mod sw_scalar_mul;
mod to_bytes;

pub(super) const HINT_HEADER_LEN: usize = 6;
/// Entry point for a `Blueprint::GenericHint` instruction.
pub(super) fn solve_hint(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let _total = cursor.read_u32()?;
    let hint_id = cursor.read_u32()?;
    match hint_id {
        HID_INV_ZERO => inv_zero::solve(solver, cursor).map(|p| vec![p]),
        HID_DECOMPOSE => decompose::solve(solver, cursor),
        HID_RANDOMIZE => randomize::solve(solver, cursor),
        HID_COUNT => count::solve(solver, cursor),
        HID_BSB22 => bsb22::solve(solver, cursor).map(|p| vec![p]),
        HID_XOR => bitwise::solve_xor(solver, cursor).map(|p| vec![p]),
        HID_AND => bitwise::solve_and(solver, cursor).map(|p| vec![p]),
        HID_OR => bitwise::solve_or(solver, cursor).map(|p| vec![p]),
        HID_TO_BYTES => to_bytes::solve(solver, cursor),
        HID_SPLIT_TO_64 => split_to_64::solve(solver, cursor),
        HID_PARTITION => partition::solve(solver, cursor),
        HID_EMU_MUL => emulated_mul::solve(solver, cursor),
        HID_EMU_DIV => emulated_div::solve_div(solver, cursor),
        HID_EMU_INVERSE => emulated_div::solve_inverse(solver, cursor),
        HID_DIV_E2 => fields_bn254::solve_div_e2(solver, cursor),
        HID_INVERSE_E12 => fields_bn254::solve_inverse_e12(solver, cursor),
        HID_GRUMPKIN_DECOMPOSE_SCALAR => grumpkin_split::solve(solver, cursor),
        HID_GRUMPKIN_DECOMPOSE => grumpkin_decompose::solve(solver, cursor),
        HID_SW_DECOMPOSE_SCALAR_G1 => sw_decompose_scalar::solve(solver, cursor),
        HID_SW_SCALAR_MUL => sw_scalar_mul::solve(solver, cursor),
        HID_SW_HALF_GCD => sw_half_gcd::solve(solver, cursor),
        HID_SW_HALF_GCD_EISENSTEIN => sw_half_gcd_eisenstein::solve(solver, cursor),
        HID_N_BITS => n_bits::solve(solver, cursor),
        HID_POLY_MV => poly_mv::solve(solver, cursor),
        _ => Err(HintError::UnknownHint { hint_id }.into()),
    }
}

/// Read a length-prefixed linear expression and evaluate it against the
/// witness. Every wire must already be solved.
pub(super) fn read_input(cursor: &mut Cursor<'_>, solver: &Solver<'_>) -> Result<Fr, SolveError> {
    let n = cursor.read_u32()? as usize;
    let coeffs = &solver.r1cs.coefficients;
    let witness = &solver.witness;
    let mut sum = Fr::zero();
    for _ in 0..n {
        let (cid, wid) = cursor.read_pair()?;
        let coeff = *coeffs
            .get(cid as usize)
            .ok_or(SolveError::CoeffOutOfRange {
                cid,
                total: coeffs.len(),
            })?;
        // Per gnark constraint.Term.IsConstant: VID == math.MaxUint32 flags a
        // pure-constant term, where the value is just the coefficient.
        if wid == u32::MAX {
            sum += coeff;
            continue;
        }
        let value = *witness
            .get(wid as usize)
            .ok_or(SolveError::WireOutOfRange {
                wid,
                total: witness.len(),
            })?;
        debug_assert!(
            solver.solved[wid as usize],
            "hint input wire {wid} not solved — level scheduler bug",
        );
        sum += coeff * value;
    }
    Ok(sum)
}

/// Read N hint inputs in sequence, evaluating each linear expression.
pub(super) fn read_n_inputs(
    cursor: &mut Cursor<'_>,
    solver: &Solver<'_>,
    n: usize,
) -> Result<Vec<Fr>, SolveError> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(read_input(cursor, solver)?);
    }
    Ok(out)
}

/// Extract a small unsigned integer from a field element.
/// Takes the hint name for error handling
pub(super) fn fr_to_u64(hint_name: &'static str, x: &Fr) -> Result<u64, SolveError> {
    let bigint = x.into_bigint().0;
    // BN254 Fr is 4 u64 limbs (little-endian). Anything above limb 0 means
    // the value exceeds u64.
    if bigint[1] != 0 || bigint[2] != 0 || bigint[3] != 0 {
        return Err(HintError::HintInputNotUint64 { hint_name }.into());
    }
    Ok(bigint[0])
}

// Hint IDs — derived at compile time from the gnark FQNs. Add a new const
// here per hint and a matching arm in `solve_hint`.
const HID_INV_ZERO: u32 = fnv1a32(b"github.com/consensys/gnark/constraint/solver.InvZeroHint");
const HID_DECOMPOSE: u32 = fnv1a32(b"github.com/consensys/gnark/std/rangecheck.DecomposeHint");
const HID_RANDOMIZE: u32 = fnv1a32(b"github.com/consensys/gnark/internal/hints.Randomize");
const HID_COUNT: u32 = fnv1a32(b"github.com/consensys/gnark/std/internal/logderivarg.countHint");
const HID_BSB22: u32 =
    fnv1a32(b"github.com/consensys/gnark/frontend/cs.Bsb22CommitmentComputePlaceholder");
const HID_XOR: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/uints.xorHint");
const HID_AND: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/uints.andHint");
const HID_OR: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/uints.orHint");
const HID_TO_BYTES: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/uints.toBytes");
const HID_SPLIT_TO_64: u32 = fnv1a32(b"sunspot/go/acir/black_box_func.splitInto64BitLimbsHint");
const HID_PARTITION: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/bitslice.partitionHint");
const HID_EMU_MUL: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/emulated.mulHint");
const HID_EMU_DIV: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/emulated.DivHint");
const HID_EMU_INVERSE: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/emulated.InverseHint");
const HID_DIV_E2: u32 =
    fnv1a32(b"github.com/consensys/gnark/std/algebra/emulated/fields_bn254.divE2Hint");
const HID_INVERSE_E12: u32 =
    fnv1a32(b"github.com/consensys/gnark/std/algebra/emulated/fields_bn254.inverseE12Hint");
const HID_GRUMPKIN_DECOMPOSE_SCALAR: u32 = fnv1a32(b"sunspot/go/sw-grumpkin.decomposeScalar");
const HID_GRUMPKIN_DECOMPOSE: u32 = fnv1a32(b"sunspot/go/sw-grumpkin.decompose");
const HID_SW_DECOMPOSE_SCALAR_G1: u32 =
    fnv1a32(b"github.com/consensys/gnark/std/algebra/emulated/sw_emulated.decomposeScalarG1");
const HID_SW_SCALAR_MUL: u32 =
    fnv1a32(b"github.com/consensys/gnark/std/algebra/emulated/sw_emulated.scalarMulHint");
const HID_SW_HALF_GCD: u32 =
    fnv1a32(b"github.com/consensys/gnark/std/algebra/emulated/sw_emulated.halfGCD");
const HID_SW_HALF_GCD_EISENSTEIN: u32 =
    fnv1a32(b"github.com/consensys/gnark/std/algebra/emulated/sw_emulated.halfGCDEisenstein");
const HID_N_BITS: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/bits.nBits");
const HID_POLY_MV: u32 = fnv1a32(b"github.com/consensys/gnark/std/math/emulated.polyMvHint");

/// FNV-1a 32-bit hash, matching Go's `hash/fnv.New32a`. Used by gnark in
/// `csolver.GetHintID` to derive HintIDs from fully qualified function names.
const fn fnv1a32(s: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < s.len() {
        h ^= s[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}
