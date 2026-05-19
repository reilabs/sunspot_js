//! `std/math/bitslice.partitionHint`: 2 inputs (`split` bit position, `val`),
//! 2 outputs `[val >> split, val mod 2^split]`. Mirrors gnark's
//! `big.Int.QuoRem(val, 1 << split, &lo)` — outputs[0] is the high part,
//! outputs[1] is the low part.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use super::super::cursor::Cursor;
use super::super::error::SolveError;
use super::super::state::Solver;
use super::error::HintError;
use super::{fr_to_u64, read_input};

const NAME: &str = "partitionHint";

pub(super) fn solve(
    solver: &Solver<'_>,
    cursor: &mut Cursor<'_>,
) -> Result<Vec<(u32, Fr)>, SolveError> {
    let nb_inputs = cursor.read_u32()?;
    if nb_inputs != 2 {
        return Err(HintError::HintInputShape {
            hint_name: NAME,
            expected: 2,
            actual: nb_inputs,
        }
        .into());
    }
    let split = fr_to_u64(NAME, &read_input(cursor, solver)?)? as usize;
    let val = read_input(cursor, solver)?;

    let (start, end) = cursor.read_pair()?;
    if end - start != 2 {
        return Err(HintError::HintOutputShape {
            hint_name: NAME,
            expected: 2,
            actual: end - start,
        }
        .into());
    }

    let bits = val.into_bigint().to_bits_le();
    let lo = fr_from_bits_le(&bits[..split.min(bits.len())]);
    let hi = if split < bits.len() {
        fr_from_bits_le(&bits[split..])
    } else {
        Fr::from(0u64)
    };

    Ok(vec![(start, hi), (start + 1, lo)])
}

fn fr_from_bits_le(bits: &[bool]) -> Fr {
    // Pack bits LE into bytes, then read as a little-endian field element.
    // BN254 Fr fits in 32 bytes; the input vector is ≤ 254 bits so this
    // never overflows.
    let mut bytes = [0u8; 32];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            bytes[i / 8] |= 1u8 << (i % 8);
        }
    }
    Fr::from_le_bytes_mod_order(&bytes)
}
